"""Persistent, coal-domain-only conversation orchestration.

The chat surface is deliberately narrower than the general Harness API:
domain checks happen before a run is created, every run is pinned to the
``chat_read_only`` tool profile, and assistant messages are materialized only
from locally governed knowledge or an integrity-checked Harness result.
"""

from __future__ import annotations

import json
import re
import sqlite3
import threading
import unicodedata
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .errors import ConflictError, NotFoundError
from .harness.sanitize import has_secret_material, redact_text
from .skills import SkillRegistry
from .util import (
    canonical_json,
    parse_aware_datetime,
    sha256_json,
    utc_text,
)

_SESSION_ID = re.compile(r"^[0-9a-f-]{36}$")
_DRAFT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_CLIENT_MESSAGE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_MAX_MESSAGE_CHARS = 2_000
_MAX_CONTEXT_CHARS = 3_200
_MAX_CONTEXT_MESSAGES = 8
_MAX_MESSAGES_PER_SESSION = 500
_MAX_PUBLIC_MESSAGES = 200
_MAX_GENERAL_ANSWER_CHARS = 6_000
_MAX_GENERAL_CONTEXT_QUESTION_CHARS = 1_000
_MAX_GENERAL_CONTEXT_ANSWER_CHARS = 3_000
_MAX_CHAT_PROVIDER_GLOBAL = 8
_MAX_CHAT_PROVIDER_PER_ACTOR = 2
_FINAL_DISCLAIMER = (
    "以上内容仅用于煤炭业务辅助分析，不是监管认定、法律意见或提交指令；"
    "请结合原始凭证和现场情况人工复核。对话未执行确认、签名或提交。"
)
_GENERAL_KNOWLEDGE_DISCLAIMER = (
    "这是煤炭通识说明，不是针对某个矿井的参数认定；涉及现场安全阈值时，"
    "请以煤样检测、适用规程和专业人员意见为准。"
)
_NEWS_DISCLAIMER = (
    "以上为公开网络检索线索，新闻会持续更新，请打开原文核验；"
    "不构成监管认定或企业数据结论。"
)
_NEWS_PROVIDER_LABELS = {
    "baidu-news-search": "百度新闻",
    "deepseek-web-search": "DeepSeek 联网搜索",
    "bing-news-rss": "Bing News",
}
_NEWS_FAILURE_LABELS = {
    "network_timeout": "连接超时",
    "network_unavailable": "网络或 DNS 不可用",
    "challenge_required": "触发安全验证",
    "authentication_failed": "鉴权失败",
    "rate_limited": "请求频率受限",
    "upstream_blocked": "上游拒绝访问",
    "upstream_unavailable": "上游服务异常",
    "invalid_search_page": "未识别到有效新闻结果",
    "invalid_provider_response": "返回格式异常",
    "provider_search_error": "联网搜索执行失败",
    "no_results": "未取得合格结果",
    "busy": "当前检索繁忙",
    "deadline_exhausted": "总检索时间已用完",
}

_COAL_TERMS = (
    "煤炭",
    "煤矿",
    "原煤",
    "商品煤",
    "精煤",
    "中煤",
    "煤泥",
    "矸石",
    "洗煤",
    "洗选",
    "选煤",
    "入洗",
    "矿井",
    "采煤",
    "煤流",
    "煤量",
    "产量",
    "销量",
    "吨煤",
    "动力煤",
    "焦煤",
    "无烟煤",
    "褐煤",
    "皮带秤",
    "地磅",
    "筒仓",
    "灰分",
    "硫分",
    "水分",
    "发热量",
    "挥发分",
    "库存",
    "盘煤",
    "质量平衡",
    "物料平衡",
    "五流",
    "产销存",
    "主运",
    "工作面",
    "选煤厂",
    "洗煤厂",
    "产率",
    "回收率",
    "交叉验证",
    "历史基线",
    "传感器漂移",
    "变化点",
    "来源凭证",
    "草稿",
    "填报",
    "导入",
    "预检",
    "数据体检",
    "提交前",
    "计量校准",
    "储运",
    "煤场",
    "煤炭销售",
    "安全生产",
    "环保",
    "燃点",
    "着火点",
    "点燃温度",
    "自燃",
    "煤尘",
    "粉尘爆炸",
    "煤阶",
    "煤化程度",
    "coal",
    "colliery",
    "raw coal",
    "clean coal",
    "coal washing",
    "washing yield",
    "coal inventory",
    "calorific value",
    "ash content",
)
_OUT_OF_DOMAIN_TERMS = (
    "股票",
    "炒股",
    "基金",
    "加密货币",
    "比特币",
    "彩票",
    "天气",
    "星座",
    "娱乐",
    "明星",
    "电影",
    "小说",
    "写诗",
    "翻译",
    "情书",
    "菜谱",
    "旅游",
    "游戏攻略",
    "医学诊断",
    "开药",
    "处方",
    "黑客",
    "外挂",
    "编程",
    "写代码",
    "代码生成",
    "python",
    "javascript",
    "总统",
    "政治",
    "选举",
    "木马",
    "勒索软件",
    "president",
    "politics",
    "election",
    "stock",
    "crypto",
    "weather",
    "programming",
    "write code",
    "game cheat",
    "poem",
    "translate",
)
_BOUNDARY_ATTACK_TERMS = (
    "忽略之前",
    "忽略以上",
    "系统提示词",
    "system prompt",
    "developer message",
    "越狱",
    "不受限制",
    "扮演任意",
    "泄露密钥",
    "api key",
    "api_key",
    "密码",
)
_CONTINUATION = re.compile(
    r"^(那|那么|这个|它|上述|继续|再说|具体|为什么|怎么|如何|"
    r"能否|可以|有哪些|怎么算|是什么意思|依据是什么|风险呢)"
)
_PROHIBITED_ACTION = re.compile(
    r"(?:帮我|替我|自动|直接|立即|无需审批|绕过(?:审批|人工)|代为)"
    r".{0,16}(?:确认|签名|报送|提交)|"
    r"(?:confirm|sign|submit).{0,20}(?:for me|automatically|without approval)",
    re.IGNORECASE,
)
_LOCAL_GREETING = re.compile(
    r"^(你好|您好|嗨|hello|hi|你能做什么|能做什么|帮助|使用帮助|"
    r"能力范围)[！!。.？? ]*$",
    re.IGNORECASE,
)
_ENTERPRISE_DATA_INTENT = re.compile(
    r"(?:当前|现有|这份|这个|上述|以下).{0,8}(?:草稿|填报|报表|台账|"
    r"数据|记录|观测|批次)|"
    r"(?:我矿|本矿|我们矿|我司|本公司|我厂|本厂|本企业|我企业)|"
    r"(?:分析|检查|核验|核对|审查|判断).{0,12}(?:草稿|填报|报表|"
    r"台账|数据|记录|观测|来源|凭证|差额|异常)|"
    r"(?:草稿|填报|报表|台账|数据|记录|观测|来源|凭证|差额).{0,12}"
    r"(?:分析|检查|核验|核对|审查|判断|异常|正常)|"
    r"(?:是否|是不是|算不算).{0,8}(?:异常|正常|合规|违规|瞒报|造假)|"
    r"(?:异常|正常|合规|违规|瞒报|造假).{0,8}(?:吗|么|判断|认定)|"
    r"(?:历史基线|传感器漂移|变化点|交叉验证|来源核验|数据体检|"
    r"提交前|预检)"
)
_GENERAL_KNOWLEDGE_TOPIC = re.compile(
    r"(?:燃点|着火点|点燃温度|自燃|氧化蓄热|煤尘|粉尘爆炸|"
    r"煤种|煤阶|煤化程度|褐煤|烟煤|无烟煤|焦煤|动力煤|"
    r"气煤|肥煤|瘦煤|贫煤|泥炭|煤的形成|煤炭形成|"
    r"灰分|硫分|水分|挥发分|发热量|洗选|浮选|重介|跳汰)"
)
_GENERAL_QUESTION_FORM = re.compile(
    r"(?:什么|多少|为何|为什么|原理|含义|概念|定义|区别|分类|"
    r"特点|性质|怎么形成|如何形成|怎么算|怎么计算|如何计算|"
    r"会不会|是否会|有哪些|有什么)"
)
_NEWS_INTENT = re.compile(
    r"(?:新闻|资讯|行业动态|市场动态|最新消息|热点|要闻|"
    r"news|headline)",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class DomainDecision:
    allowed: bool
    reason: str


def coal_domain_decision(
    content: str, *, has_accepted_context: bool = False
) -> DomainDecision:
    """Fail-closed lexical gate used before any provider or Harness call."""

    normalized = unicodedata.normalize("NFKC", content).casefold()
    normalized = re.sub(r"[\u200b-\u200f\u2060\ufeff]", "", normalized)
    normalized = " ".join(normalized.split())
    if _PROHIBITED_ACTION.search(normalized):
        return DomainDecision(False, "prohibited_action")
    if any(term in normalized for term in _BOUNDARY_ATTACK_TERMS):
        return DomainDecision(False, "boundary_attack")
    if any(term in normalized for term in _OUT_OF_DOMAIN_TERMS):
        return DomainDecision(False, "out_of_domain_topic")
    if _LOCAL_GREETING.fullmatch(normalized):
        return DomainDecision(True, "local_capability_greeting")
    if any(term.casefold() in normalized for term in _COAL_TERMS):
        return DomainDecision(True, "explicit_coal_business")
    if (
        has_accepted_context
        and len(normalized) <= 32
        and _CONTINUATION.search(normalized) is not None
    ):
        return DomainDecision(True, "bounded_coal_follow_up")
    return DomainDecision(False, "coal_scope_not_established")


def coal_general_knowledge_decision(
    content: str, *, has_general_context: bool = False
) -> DomainDecision:
    """Route conceptual coal questions away from enterprise-data analysis.

    This classifier intentionally does not inspect session or draft state.  A
    user may have a draft open while asking an unrelated coal-science question;
    only the current message decides whether any enterprise evidence is needed.
    """

    normalized = unicodedata.normalize("NFKC", content).casefold()
    normalized = re.sub(r"[\u200b-\u200f\u2060\ufeff]", "", normalized)
    normalized = " ".join(normalized.split())
    if _ENTERPRISE_DATA_INTENT.search(normalized):
        return DomainDecision(False, "enterprise_data_intent")
    if _GENERAL_KNOWLEDGE_TOPIC.search(normalized):
        return DomainDecision(True, "general_coal_knowledge")
    if (
        has_general_context
        and len(normalized) <= 64
        and _CONTINUATION.search(normalized) is not None
    ):
        return DomainDecision(True, "general_coal_follow_up")
    if any(
        term.casefold() in normalized for term in _COAL_TERMS
    ) and _GENERAL_QUESTION_FORM.search(normalized):
        return DomainDecision(True, "general_coal_knowledge")
    return DomainDecision(False, "coal_analysis_or_unspecified_intent")


def coal_news_search_decision(content: str) -> DomainDecision:
    """Identify current-news requests after the coal-domain gate."""

    normalized = unicodedata.normalize("NFKC", content).casefold()
    normalized = re.sub(r"[\u200b-\u200f\u2060\ufeff]", "", normalized)
    normalized = " ".join(normalized.split())
    if _NEWS_INTENT.search(normalized) is None:
        return DomainDecision(False, "not_news_intent")
    if not any(term.casefold() in normalized for term in _COAL_TERMS):
        return DomainDecision(False, "coal_news_topic_not_explicit")
    return DomainDecision(True, "coal_news_search")


def _governed_answer(text: str) -> str:
    suffix = "\n\n" + _FINAL_DISCLAIMER
    if _FINAL_DISCLAIMER in text:
        return redact_text(text.strip(), maximum=16_000)
    clean = redact_text(text.strip(), maximum=16_000 - len(suffix))
    return clean + suffix


def _governed_general_answer(text: str) -> str:
    suffix = "\n\n" + _GENERAL_KNOWLEDGE_DISCLAIMER
    if _GENERAL_KNOWLEDGE_DISCLAIMER in text:
        return redact_text(text.strip(), maximum=16_000)
    clean = redact_text(text.strip(), maximum=16_000 - len(suffix))
    return clean + suffix


def _governed_news_answer(text: str) -> str:
    suffix = "\n\n" + _NEWS_DISCLAIMER
    if _NEWS_DISCLAIMER in text:
        return redact_text(text.strip(), maximum=16_000)
    clean = redact_text(text.strip(), maximum=16_000 - len(suffix))
    return clean + suffix


def _news_attempt_summary(value: Any) -> str:
    if not isinstance(value, list):
        return ""
    summaries: list[str] = []
    for attempt in value[:5]:
        if not isinstance(attempt, dict):
            continue
        provider = _NEWS_PROVIDER_LABELS.get(
            str(attempt.get("provider", "")),
            "新闻源",
        )
        failure_code = str(attempt.get("failure_code", ""))
        if failure_code:
            outcome = _NEWS_FAILURE_LABELS.get(failure_code, "未成功")
        else:
            count = attempt.get("result_count")
            outcome = f"取得 {count} 条" if isinstance(count, int) else "成功"
        summaries.append(f"{provider}：{outcome}")
    return "；".join(summaries)


def _validated_general_answer(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > _MAX_GENERAL_ANSWER_CHARS
        or len(value.encode("utf-8")) > 24_000
        or any(
            ord(character) < 32 and character not in {"\n", "\t"} for character in value
        )
        or has_secret_material(value)
    ):
        raise ValueError("模型煤炭通识回答格式非法")
    return value.strip()


def _validated_news_summary_answer(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > 8_000
        or len(value.encode("utf-8")) > 32_000
        or "**AI 新闻摘要**" not in value
        or re.search(r"来源：S(?:[1-9]|10)(?:、S(?:[1-9]|10))*", value) is None
        or any(
            ord(character) < 32 and character not in {"\n", "\t"} for character in value
        )
        or has_secret_material(value)
    ):
        raise ValueError("模型煤炭新闻总结格式非法")
    return value.strip()


def _numbered_news_sources(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    numbered: list[dict[str, Any]] = []
    for source in value[:10]:
        if not isinstance(source, dict):
            continue
        numbered.append({**source, "source_id": f"S{len(numbered) + 1}"})
    return numbered


def _news_source_list(
    news: dict[str, Any],
    sources: list[dict[str, Any]],
    *,
    introduction: str,
) -> str:
    lines = [introduction]
    for source in sources:
        published = (
            source.get("published_at")
            or source.get("published_time_text")
            or "时间未标明"
        )
        lines.append(
            f"- {source['source_id']}｜{source.get('title', '标题缺失')}｜"
            f"{source.get('publisher', '来源未标明')}｜{published}"
        )
    attempt_summary = _news_attempt_summary(news.get("provider_attempts"))
    if news.get("status") == "partial" and attempt_summary:
        lines.append(f"检索说明：{attempt_summary}；结果可能不完整。")
    return "\n".join(lines)


def _local_knowledge(content: str) -> tuple[str, str]:
    """Return curated coal-business knowledge without inventing measurements."""

    text = content.casefold()
    if any(term in text for term in ("燃点", "着火点", "点燃温度", "点火温度")):
        return (
            "coal_ignition_temperature",
            "煤炭没有适用于所有煤种的单一“燃点”。工程上常说的着火温度会受"
            "煤阶、挥发分、水分、粒度、供氧条件、升温速度和试验方法影响，"
            "只能粗略地说是“数百摄氏度”的量级：某些煤样试验结果约在"
            " 300～500℃，但随煤阶和试验形态也可能低于这一范围，或达到"
            " 600～800℃以上。煤样、煤粉气流、煤尘云、煤尘层的点燃温度，"
            "以及煤堆低温自热，属于不同指标，不能互相替代。自燃是在较低"
            "温度下持续氧化并因散热不良逐步蓄热，明显着火前就可能已有风险。"
            "具体应按 GB/T 18511-2017 或现场适用的试验方法检测；任何粗略"
            "范围都不能直接作为报警或处置阈值。",
        )
    if "自燃" in text or "氧化蓄热" in text:
        return (
            "coal_spontaneous_combustion",
            "煤炭自燃通常不是突然达到某个固定燃点，而是低温氧化持续放热、"
            "热量来不及散出后逐步升温。煤阶和活性、粒度、含水变化、供氧、"
            "堆积厚度、堆存时间及通风路径都会影响风险。管理上应关注持续升温、"
            "一氧化碳等气体趋势、异味或烟气等组合信号，不能只看一次温度值。"
            "发现持续升温或烟气时，应按企业应急制度隔离区域并由安全专业人员"
            "处置，不宜自行翻堆、注水或改变通风，以免引入新的供氧和次生风险。",
        )
    if any(term in text for term in ("煤尘", "粉尘爆炸")):
        return (
            "coal_dust_safety",
            "细煤尘具有可燃性；当足量煤尘悬浮在空气中，同时存在氧气和有效"
            "点火源，并处于巷道、设备或建筑等受限空间时，可能发生快速燃烧"
            "甚至爆炸。沉积煤尘还可能被冲击波重新扬起，造成连续传播。风险"
            "不能仅凭肉眼或一个通用浓度值判断，应结合煤尘爆炸性鉴定、粒度、"
            "监测结果和现场条件，落实除尘、清扫、抑尘、消除点火源及适用的"
            "隔爆措施。出现扬尘、异常温升或火情时应立即按现场安全制度处置。",
        )
    if any(term in text for term in ("煤种", "煤阶", "煤化程度")) or (
        "褐煤" in text and "无烟煤" in text
    ):
        return (
            "coal_rank_overview",
            "煤阶反映煤化程度。概括地说，褐煤煤化程度较低，通常水分和挥发分"
            "较高、结构较疏松，储存氧化和自燃风险更需关注；烟煤范围较宽，"
            "不同牌号的黏结性、挥发分和用途差异明显；无烟煤煤化程度较高，"
            "挥发分通常较低、固定碳比例较高，着火相对困难。实际分类与用途"
            "不能只凭外观，应以规定方法测得的煤质指标和适用分类标准为准。",
        )
    if any(
        term in text
        for term in (
            "草稿",
            "填报",
            "导入",
            "预检",
            "数据体检",
            "提交前",
        )
    ):
        return (
            "enterprise_reporting_workflow",
            "企业端可用于建立草稿、导入观测、执行确定性预检和煤炭数据体检。"
            "建议顺序是：核对统计窗口与矿井标识，检查观测单位和时间，补齐来源"
            "凭证，运行物理/历史交叉核对，再由人员审阅。对话只能解释和调用只读"
            "分析工具，不能替人员确认、签名或提交。",
        )
    if any(term in text for term in ("五流", "质量平衡", "物料平衡", "煤流")):
        return (
            "coal_flow_balance",
            "煤流核对可按“期初库存 + 生产流入 + 外购调入 = "
            "销售调出 + 入洗消耗 + 其他有凭证去向 + 期末库存”建立闭合关系。"
            "差额应同时报告绝对吨数和相对差率，不能把差额直接解释成瞒报。"
            "至少需要统计窗口、统一单位、期初/期末库存、各流入流出量及来源编号；"
            "缺少任一关键项时只能标记证据不足。",
        )
    if any(term in text for term in ("洗选", "入洗", "产率", "回收率", "精煤")):
        return (
            "washing_yield",
            "洗选核算中，产品产率 = 产品质量 ÷ 入洗原煤质量 × 100%；"
            "多产品质量闭合差 = 入洗原煤 − 精煤 − 中煤 − 煤泥 − 矸石"
            "（还应纳入明确记录的其他产品或损耗口径）。"
            "不同水分基、计量时点或单位不能直接相加；需要入洗量、各产品量、"
            "单位、统计窗口和计量口径后才能计算。",
        )
    if any(term in text for term in ("库存", "盘煤", "筒仓", "收发存")):
        return (
            "inventory_direction",
            "库存方向应保持一致：期末库存 = 期初库存 + 入库 − 出库。"
            "盘煤结果、仓储台账、皮带秤累计量和销售地磅量应按同一截止时刻对齐。"
            "盘点误差、在途煤、仓内死角和水分变化应作为显式调整项保留凭证，"
            "不能用一个未说明的“损耗”项自动抹平差额。",
        )
    if any(term in text for term in ("时间", "对齐", "延迟", "窗口")):
        return (
            "time_alignment",
            "时间对齐应统一到带时区的 UTC 时间，明确统计窗口采用左闭右开或"
            "其他固定边界，并分别保留观测时间、接收时间和区间起止时间。"
            "跨窗记录、迟到记录、累计表复位和重复序号必须单独标记；"
            "未对齐的数据不应直接进入同一平衡式。",
        )
    if any(term in text for term in ("来源", "凭证", "签名", "哈希", "证据")):
        return (
            "source_evidence",
            "来源核验至少区分三件事：载荷摘要是否与当前记录一致、签名格式是否"
            "完整、是否由持有可信密钥的来源网关完成验签。企业 Agent 不持来源"
            "密钥，因此只能检查摘要和格式并展示来源链，不能自行证明设备真实性。"
            "人工录入、导入文件和设备采集也应分别记录来源类型与定位信息。",
        )
    if any(term in text for term in ("历史", "基线", "异常", "漂移", "变化点")):
        return (
            "historical_anomaly",
            "历史基线宜只使用目标窗口之前、同矿井、同业务工况且已成功提交的"
            "数据，采用中位数和 MAD 等稳健统计降低极端值影响。漂移用于比较时序"
            "早末窗口，变化点用于寻找分段均值差候选；二者只能提示“何时发生变化”，"
            "不能单独判定原因或违规。样本量、单位和工况不匹配时应返回证据不足。",
        )
    if any(term in text for term in ("交叉验证", "交叉核对", "综合核验")):
        return (
            "cross_validation",
            "煤炭交叉核对应并列展示物理平衡、来源凭证、时间对齐、历史基线、"
            "传感器漂移和变化点证据。各证据的缺失与冲突要保留，不能用主观权重"
            "压成一个“合法/违法概率”。建议先定位差额，再追溯到原始观测、来源"
            "编号和统计窗口，最后由人员结合现场事件复核。",
        )
    if any(term in text for term in ("灰分", "硫分", "水分", "发热量", "挥发分")):
        return (
            "coal_quality",
            "煤质指标必须带检验方法、基准状态和采样批次。灰分、水分、硫分、"
            "挥发分及发热量在收到基、空气干燥基、干燥基等口径间不能直接比较。"
            "做历史或上下游核对前，应先统一基准或保留原口径分组，并核对采样时间"
            "是否代表同一煤流批次。",
        )
    if any(term in text for term in ("校准", "计量", "皮带秤", "地磅")):
        return (
            "measurement_calibration",
            "计量核对应保留设备编号、检定/校准有效期、零点与量程检查、累计表"
            "复位记录和维修事件。皮带秤、地磅与仓储台账只能在统一时间窗口和单位"
            "下比较；超期校准或漂移只能标记风险，不能自动判定具体业务原因。",
        )
    if any(term in text for term in ("安全", "环保", "排放", "瓦斯", "粉尘")):
        return (
            "safety_environment",
            "安全环保数据应按监测点、设备、时间窗和适用口径分别核对，保留报警、"
            "检修、停产和校准事件。对话可帮助检查数据完整性与时序异常，但不能"
            "替代现场处置、法定监测、应急指令或监管认定；紧急风险应直接按企业"
            "安全制度上报并由专业人员处理。",
        )
    if any(term in text for term in ("储运", "煤场", "销售", "发运", "装车")):
        return (
            "storage_transport_sales",
            "储运销售核对应串联煤场入库、库存移动、装车/装船、销售过磅和结算"
            "批次，统一统计截止时刻并保留在途量。合同量、发运量和实收量口径"
            "不同，应分别展示；运损、水分变化和退货必须有独立凭证，不能用于"
            "无依据地平衡差额。",
        )
    return (
        "coal_general_fallback",
        "这个问题属于煤炭业务范围，但当前离线知识库没有足够可靠的专门条目。"
        "可以补充你关注的煤种、生产环节或术语，我会解释通用原理；如果问题"
        "涉及某个矿井的实际数值、异常或监管判断，则需要基于草稿和来源凭证"
        "进行只读核验，不能凭空推测。",
    )


class ChatStore:
    def __init__(self, repository: Any):
        self.repository = repository

    @staticmethod
    def _bound_draft(row: Any) -> str | None:
        keys = set(row.keys())
        context = row["context_draft_id"] if "context_draft_id" in keys else None
        return context or row["draft_id"]

    @staticmethod
    def _session_projection(row: Any) -> dict[str, Any]:
        return {
            "session_id": row["session_id"],
            "actor_id": row["actor_id"],
            "client_request_id": row["client_request_id"],
            "title": row["title"],
            "draft_id": ChatStore._bound_draft(row),
            "deleted_at": row["deleted_at"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    @staticmethod
    def _message_projection(row: Any) -> dict[str, Any]:
        return {
            "message_id": row["message_id"],
            "session_id": row["session_id"],
            "sequence": int(row["sequence"]),
            "role": row["role"],
            "client_message_id": row["client_message_id"],
            "content_sha256": sha256_json(row["content"]),
            "status": row["status"],
            "run_id": row["run_id"],
            "domain_allowed": int(row["domain_allowed"]),
            "domain_reason": row["domain_reason"],
            "evidence_sha256": sha256_json(row["evidence_json"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def _append_event(
        self,
        db: sqlite3.Connection,
        *,
        session_id: str,
        event_type: str,
        actor_id: str,
        details: dict[str, Any],
        occurred_at: str | None = None,
    ) -> None:
        session = db.execute(
            """
            SELECT event_count, event_head_hash
            FROM chat_sessions WHERE session_id = ?
            """,
            (session_id,),
        ).fetchone()
        if session is None:
            raise NotFoundError("煤炭对话不存在")
        sequence = int(session["event_count"]) + 1
        previous_hash = str(session["event_head_hash"])
        now = occurred_at or utc_text()
        envelope = {
            "session_id": session_id,
            "sequence": sequence,
            "event_type": event_type,
            "actor_id": actor_id,
            "details": details,
            "occurred_at": now,
            "previous_hash": previous_hash,
        }
        event_hash = sha256_json(envelope)
        db.execute(
            """
            INSERT INTO chat_session_events (
                session_id, sequence, event_type, actor_id, details_json,
                occurred_at, previous_hash, event_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                sequence,
                event_type,
                actor_id,
                canonical_json(details),
                now,
                previous_hash,
                event_hash,
            ),
        )
        db.execute(
            """
            UPDATE chat_sessions
            SET event_count = ?, event_head_hash = ?
            WHERE session_id = ?
            """,
            (sequence, event_hash, session_id),
        )

    def integrity(self, session_id: str, *, actor_id: str) -> dict[str, Any]:
        try:
            with self.repository._read() as db:
                session = db.execute(
                    """
                    SELECT * FROM chat_sessions
                    WHERE session_id = ? AND actor_id = ?
                    """,
                    (session_id, actor_id),
                ).fetchone()
                if session is None:
                    raise NotFoundError("煤炭对话不存在")
                events = db.execute(
                    """
                    SELECT * FROM chat_session_events
                    WHERE session_id = ? ORDER BY sequence
                    """,
                    (session_id,),
                ).fetchall()
                messages = db.execute(
                    """
                    SELECT * FROM chat_messages
                    WHERE session_id = ? ORDER BY sequence
                    """,
                    (session_id,),
                ).fetchall()
            previous_hash = "0" * 64
            latest_session: dict[str, Any] | None = None
            latest_messages: dict[str, dict[str, Any]] = {}
            for expected, event in enumerate(events, 1):
                details = json.loads(event["details_json"])
                envelope = {
                    "session_id": event["session_id"],
                    "sequence": event["sequence"],
                    "event_type": event["event_type"],
                    "actor_id": event["actor_id"],
                    "details": details,
                    "occurred_at": event["occurred_at"],
                    "previous_hash": event["previous_hash"],
                }
                if (
                    int(event["sequence"]) != expected
                    or event["previous_hash"] != previous_hash
                    or event["event_hash"] != sha256_json(envelope)
                ):
                    raise ValueError("chat event chain mismatch")
                session_snapshot = details.get("session")
                if isinstance(session_snapshot, dict):
                    latest_session = session_snapshot
                message_snapshot = details.get("message")
                if isinstance(message_snapshot, dict):
                    message_id = message_snapshot.get("message_id")
                    if not isinstance(message_id, str):
                        raise ValueError("chat message event malformed")
                    latest_messages[message_id] = message_snapshot
                previous_hash = event["event_hash"]
            if (
                len(events) != int(session["event_count"])
                or previous_hash != session["event_head_hash"]
                or latest_session != self._session_projection(session)
                or len(latest_messages) != len(messages)
                or any(
                    latest_messages.get(row["message_id"])
                    != self._message_projection(row)
                    for row in messages
                )
            ):
                raise ValueError("chat projection mismatch")
            return {
                "valid": True,
                "event_count": len(events),
                "head_hash": previous_hash,
            }
        except NotFoundError:
            raise
        except (
            KeyError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
            sqlite3.Error,
        ):
            return {
                "valid": False,
                "event_count": 0,
                "head_hash": None,
            }

    def require_integrity(self, session_id: str, *, actor_id: str) -> None:
        if not self.integrity(session_id, actor_id=actor_id)["valid"]:
            raise ConflictError("煤炭对话审计完整性校验失败，已禁止继续操作")

    @staticmethod
    def _message(row: Any) -> dict[str, Any]:
        try:
            evidence = json.loads(row["evidence_json"])
        except (TypeError, json.JSONDecodeError):
            evidence = {
                "not_a_regulatory_determination": True,
                "integrity": "invalid_evidence_json",
            }
        return {
            "message_id": row["message_id"],
            "session_id": row["session_id"],
            "sequence": int(row["sequence"]),
            "role": row["role"],
            "client_message_id": row["client_message_id"],
            "content": row["content"],
            "status": row["status"],
            "run_id": row["run_id"],
            "domain": {
                "allowed": bool(row["domain_allowed"]),
                "reason": row["domain_reason"],
            },
            "out_of_scope": not bool(row["domain_allowed"]),
            "scope_status": (
                "in_scope" if bool(row["domain_allowed"]) else "out_of_scope"
            ),
            "reason_code": row["domain_reason"],
            "evidence": evidence,
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def create_session(
        self,
        *,
        actor_id: str,
        title: str,
        draft_id: str | None,
        context_draft_id: str | None = None,
        client_request_id: str,
    ) -> dict[str, Any]:
        session_id = str(uuid.uuid4())
        now = utc_text()
        with self.repository._transaction() as db:
            existing = db.execute(
                """
                SELECT * FROM chat_sessions
                WHERE actor_id = ? AND client_request_id = ?
                """,
                (actor_id, client_request_id),
            ).fetchone()
            if existing is not None:
                if (
                    existing["title"] != title
                    or self._bound_draft(existing) != (context_draft_id or draft_id)
                ):
                    raise ConflictError("client_request_id 已用于其他会话参数")
                if existing["deleted_at"] is not None:
                    raise ConflictError("client_request_id 对应的会话已经删除")
                return {
                    "session_id": existing["session_id"],
                    "client_request_id": existing["client_request_id"],
                    "title": existing["title"],
                    "draft_id": existing["draft_id"],
                    "created_at": existing["created_at"],
                    "updated_at": existing["updated_at"],
                }
            count = db.execute(
                """
                SELECT COUNT(*) AS amount FROM chat_sessions
                WHERE actor_id = ? AND deleted_at IS NULL
                """,
                (actor_id,),
            ).fetchone()
            if int(count["amount"]) >= 500:
                raise ConflictError("当前账号对话数量已达上限，请整理后再创建")
            lifetime = db.execute(
                "SELECT COUNT(*) AS amount FROM chat_sessions WHERE actor_id = ?",
                (actor_id,),
            ).fetchone()
            if int(lifetime["amount"]) >= 5_000:
                raise ConflictError("当前账号历史对话总量已达存储上限")
            db.execute(
                """
                INSERT INTO chat_sessions (
                    session_id, actor_id, client_request_id, title, draft_id,
                    context_draft_id, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    actor_id,
                    client_request_id,
                    title,
                    draft_id,
                    context_draft_id,
                    now,
                    now,
                ),
            )
            row = db.execute(
                "SELECT * FROM chat_sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
            self._append_event(
                db,
                session_id=session_id,
                event_type="session_created",
                actor_id=actor_id,
                details={"session": self._session_projection(row)},
                occurred_at=now,
            )
        return self.get_session(session_id, actor_id=actor_id)

    def list_sessions(
        self, *, actor_id: str, limit: int, offset: int
    ) -> tuple[list[dict[str, Any]], int]:
        with self.repository._read() as db:
            rows = db.execute(
                """
                SELECT s.*,
                    (SELECT COUNT(*) FROM chat_messages AS m
                     WHERE m.session_id = s.session_id) AS message_count,
                    (SELECT m.status FROM chat_messages AS m
                     WHERE m.session_id = s.session_id
                     ORDER BY m.sequence DESC LIMIT 1) AS last_status,
                    (SELECT m.content FROM chat_messages AS m
                     WHERE m.session_id = s.session_id
                     ORDER BY m.sequence DESC LIMIT 1) AS last_content
                FROM chat_sessions AS s
                WHERE s.actor_id = ? AND s.deleted_at IS NULL
                ORDER BY s.updated_at DESC, s.session_id DESC
                LIMIT ? OFFSET ?
                """,
                (actor_id, limit, offset),
            ).fetchall()
            total = db.execute(
                """
                SELECT COUNT(*) AS amount FROM chat_sessions
                WHERE actor_id = ? AND deleted_at IS NULL
                """,
                (actor_id,),
            ).fetchone()
        return (
            [
                {
                    "session_id": row["session_id"],
                    "client_request_id": row["client_request_id"],
                    "title": row["title"],
                    "draft_id": self._bound_draft(row),
                    "message_count": int(row["message_count"]),
                    "last_message_status": row["last_status"],
                    "last_message_preview": (
                        str(row["last_content"])[:160]
                        if row["last_content"] is not None
                        else None
                    ),
                    "created_at": row["created_at"],
                    "updated_at": row["updated_at"],
                }
                for row in rows
            ],
            int(total["amount"]),
        )

    def get_session(self, session_id: str, *, actor_id: str) -> dict[str, Any]:
        with self.repository._read() as db:
            row = db.execute(
                """
                SELECT * FROM chat_sessions
                WHERE session_id = ? AND actor_id = ? AND deleted_at IS NULL
                """,
                (session_id, actor_id),
            ).fetchone()
        if row is None:
            raise NotFoundError("煤炭对话不存在")
        return {
            "session_id": row["session_id"],
            "client_request_id": row["client_request_id"],
            "title": row["title"],
            "draft_id": self._bound_draft(row),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def soft_delete_session(self, session_id: str, *, actor_id: str) -> dict[str, Any]:
        now = utc_text()
        with self.repository._transaction() as db:
            row = db.execute(
                """
                SELECT * FROM chat_sessions
                WHERE session_id = ? AND actor_id = ? AND deleted_at IS NULL
                """,
                (session_id, actor_id),
            ).fetchone()
            if row is None:
                raise NotFoundError("煤炭对话不存在")
            pending = db.execute(
                """
                SELECT 1 FROM chat_messages
                WHERE session_id = ? AND role = 'assistant'
                  AND status = 'queued'
                LIMIT 1
                """,
                (session_id,),
            ).fetchone()
            if pending is not None:
                raise ConflictError("对话仍在分析，完成后才能删除")
            db.execute(
                """
                UPDATE chat_sessions
                SET deleted_at = ?, updated_at = ?
                WHERE session_id = ? AND actor_id = ? AND deleted_at IS NULL
                """,
                (now, now, session_id, actor_id),
            )
            updated = db.execute(
                "SELECT * FROM chat_sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
            self._append_event(
                db,
                session_id=session_id,
                event_type="session_deleted",
                actor_id=actor_id,
                details={"session": self._session_projection(updated)},
                occurred_at=now,
            )
        return {
            "session_id": session_id,
            "deleted": True,
            "deleted_at": now,
        }

    def messages(
        self, session_id: str, *, actor_id: str
    ) -> tuple[list[dict[str, Any]], int]:
        self.get_session(session_id, actor_id=actor_id)
        with self.repository._read() as db:
            rows = db.execute(
                """
                SELECT * FROM (
                    SELECT * FROM chat_messages
                    WHERE session_id = ?
                    ORDER BY sequence DESC LIMIT ?
                ) ORDER BY sequence
                """,
                (session_id, _MAX_PUBLIC_MESSAGES),
            ).fetchall()
            count = db.execute(
                "SELECT COUNT(*) AS amount FROM chat_messages WHERE session_id = ?",
                (session_id,),
            ).fetchone()
        return [self._message(row) for row in rows], int(count["amount"])

    def message(self, message_id: str, *, actor_id: str) -> dict[str, Any]:
        with self.repository._read() as db:
            row = db.execute(
                """
                SELECT m.* FROM chat_messages AS m
                JOIN chat_sessions AS s ON s.session_id = m.session_id
                WHERE m.message_id = ? AND s.actor_id = ?
                  AND s.deleted_at IS NULL
                """,
                (message_id, actor_id),
            ).fetchone()
        if row is None:
            raise NotFoundError("煤炭对话消息不存在")
        return self._message(row)

    def has_accepted_context(self, session_id: str, *, actor_id: str) -> bool:
        self.get_session(session_id, actor_id=actor_id)
        with self.repository._read() as db:
            row = db.execute(
                """
                SELECT 1 FROM chat_messages
                WHERE session_id = ? AND role = 'user'
                  AND domain_allowed = 1
                LIMIT 1
                """,
                (session_id,),
            ).fetchone()
        return row is not None

    def begin_turn(
        self,
        session_id: str,
        *,
        actor_id: str,
        content: str,
        decision: DomainDecision,
        draft_id: str | None,
        client_message_id: str,
        refusal: str | None = None,
    ) -> tuple[str, str, bool]:
        now = utc_text()
        user_message_id = str(uuid.uuid4())
        assistant_message_id = str(uuid.uuid4())
        assistant_status = "refused" if refusal is not None else "queued"
        with self.repository._transaction() as db:
            session = db.execute(
                """
                SELECT * FROM chat_sessions
                WHERE session_id = ? AND actor_id = ?
                """,
                (session_id, actor_id),
            ).fetchone()
            if session is None:
                raise NotFoundError("煤炭对话不存在")
            existing = db.execute(
                """
                SELECT * FROM chat_messages
                WHERE session_id = ? AND client_message_id = ?
                  AND role = 'user'
                """,
                (session_id, client_message_id),
            ).fetchone()
            if existing is not None:
                if existing["content"] != content:
                    raise ConflictError("client_message_id 已用于其他消息内容")
                if draft_id is not None and self._bound_draft(session) != draft_id:
                    raise ConflictError("client_message_id 已用于其他草稿参数")
                assistant = db.execute(
                    """
                    SELECT * FROM chat_messages
                    WHERE session_id = ? AND sequence = ? AND role = 'assistant'
                    """,
                    (session_id, int(existing["sequence"]) + 1),
                ).fetchone()
                if assistant is None:
                    raise ConflictError("幂等消息轮次不完整")
                return (
                    str(existing["message_id"]),
                    str(assistant["message_id"]),
                    False,
                )
            pending = db.execute(
                """
                SELECT 1 FROM chat_messages
                WHERE session_id = ? AND role = 'assistant'
                  AND status = 'queued'
                LIMIT 1
                """,
                (session_id,),
            ).fetchone()
            if pending is not None:
                raise ConflictError("上一条煤炭对话仍在分析，请稍后再发送")
            count = db.execute(
                """
                SELECT COUNT(*) AS amount, COALESCE(MAX(sequence), 0) AS maximum
                FROM chat_messages WHERE session_id = ?
                """,
                (session_id,),
            ).fetchone()
            if int(count["amount"]) + 2 > _MAX_MESSAGES_PER_SESSION:
                raise ConflictError("当前对话消息已达上限，请新建对话")
            current_draft = self._bound_draft(session)
            if current_draft is not None and draft_id not in {
                None,
                current_draft,
            }:
                raise ConflictError("对话已绑定其他草稿，不能在中途切换")
            selected_draft = draft_id or current_draft
            if current_draft is None and selected_draft is not None:
                db.execute(
                    "UPDATE chat_sessions SET context_draft_id = ? WHERE session_id = ?",
                    (selected_draft, session_id),
                )
            sequence = int(count["maximum"]) + 1
            db.execute(
                """
                INSERT INTO chat_messages (
                    message_id, session_id, sequence, role, client_message_id,
                    content, status, run_id, domain_allowed, domain_reason,
                    evidence_json, created_at, updated_at
                ) VALUES (?, ?, ?, 'user', ?, ?, 'completed', NULL, ?, ?, ?, ?, ?)
                """,
                (
                    user_message_id,
                    session_id,
                    sequence,
                    client_message_id,
                    content,
                    int(decision.allowed),
                    decision.reason,
                    canonical_json(
                        {
                            "domain_gate": "server",
                            "not_a_regulatory_determination": True,
                        }
                    ),
                    now,
                    now,
                ),
            )
            db.execute(
                """
                INSERT INTO chat_messages (
                    message_id, session_id, sequence, role, client_message_id,
                    content, status, run_id, domain_allowed, domain_reason,
                    evidence_json, created_at, updated_at
                ) VALUES (?, ?, ?, 'assistant', NULL, ?, ?, NULL, ?, ?, ?, ?, ?)
                """,
                (
                    assistant_message_id,
                    session_id,
                    sequence + 1,
                    refusal or "",
                    assistant_status,
                    int(decision.allowed),
                    decision.reason,
                    canonical_json(
                        {
                            "domain_gate": "server",
                            "not_a_regulatory_determination": True,
                            "provider_called": False,
                        }
                    ),
                    now,
                    now,
                ),
            )
            db.execute(
                "UPDATE chat_sessions SET updated_at = ? WHERE session_id = ?",
                (now, session_id),
            )
            session_after = db.execute(
                "SELECT * FROM chat_sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
            user_after = db.execute(
                "SELECT * FROM chat_messages WHERE message_id = ?",
                (user_message_id,),
            ).fetchone()
            assistant_after = db.execute(
                "SELECT * FROM chat_messages WHERE message_id = ?",
                (assistant_message_id,),
            ).fetchone()
            if current_draft is None and selected_draft is not None:
                self._append_event(
                    db,
                    session_id=session_id,
                    event_type="session_draft_bound",
                    actor_id=actor_id,
                    details={"session": self._session_projection(session_after)},
                    occurred_at=now,
                )
            self._append_event(
                db,
                session_id=session_id,
                event_type="message_created",
                actor_id=actor_id,
                details={
                    "session": self._session_projection(session_after),
                    "message": self._message_projection(user_after),
                },
                occurred_at=now,
            )
            self._append_event(
                db,
                session_id=session_id,
                event_type="message_created",
                actor_id="assistant",
                details={
                    "session": self._session_projection(session_after),
                    "message": self._message_projection(assistant_after),
                },
                occurred_at=now,
            )
        return user_message_id, assistant_message_id, True

    def attach_run(
        self,
        assistant_message_id: str,
        *,
        actor_id: str,
        run_id: str,
    ) -> None:
        now = utc_text()
        with self.repository._transaction() as db:
            changed = db.execute(
                """
                UPDATE chat_messages
                SET run_id = ?, updated_at = ?
                WHERE message_id = ? AND role = 'assistant'
                  AND status = 'queued' AND run_id IS NULL
                  AND session_id IN (
                      SELECT session_id FROM chat_sessions WHERE actor_id = ?
                  )
                """,
                (run_id, now, assistant_message_id, actor_id),
            ).rowcount
            if changed != 1:
                raise ConflictError("对话任务绑定状态已变化")
            row = db.execute(
                "SELECT * FROM chat_messages WHERE message_id = ?",
                (assistant_message_id,),
            ).fetchone()
            session = db.execute(
                "SELECT * FROM chat_sessions WHERE session_id = ?",
                (row["session_id"],),
            ).fetchone()
            self._append_event(
                db,
                session_id=row["session_id"],
                event_type="message_run_attached",
                actor_id=actor_id,
                details={
                    "session": self._session_projection(session),
                    "message": self._message_projection(row),
                },
                occurred_at=now,
            )

    def complete_message(
        self,
        message_id: str,
        *,
        actor_id: str,
        status: str,
        content: str,
        evidence: dict[str, Any],
    ) -> None:
        if status not in {"completed", "failed"}:
            raise ValueError("对话消息终态非法")
        now = utc_text()
        with self.repository._transaction() as db:
            row = db.execute(
                """
                SELECT m.session_id FROM chat_messages AS m
                JOIN chat_sessions AS s ON s.session_id = m.session_id
                WHERE m.message_id = ? AND s.actor_id = ?
                """,
                (message_id, actor_id),
            ).fetchone()
            if row is None:
                raise NotFoundError("煤炭对话消息不存在")
            changed = db.execute(
                """
                UPDATE chat_messages
                SET status = ?, content = ?, evidence_json = ?, updated_at = ?
                WHERE message_id = ? AND status = 'queued'
                """,
                (
                    status,
                    content,
                    canonical_json(evidence),
                    now,
                    message_id,
                ),
            )
            if changed.rowcount != 1:
                return
            db.execute(
                "UPDATE chat_sessions SET updated_at = ? WHERE session_id = ?",
                (now, row["session_id"]),
            )
            message = db.execute(
                "SELECT * FROM chat_messages WHERE message_id = ?",
                (message_id,),
            ).fetchone()
            session = db.execute(
                "SELECT * FROM chat_sessions WHERE session_id = ?",
                (row["session_id"],),
            ).fetchone()
            self._append_event(
                db,
                session_id=row["session_id"],
                event_type=f"message_{status}",
                actor_id=actor_id,
                details={
                    "session": self._session_projection(session),
                    "message": self._message_projection(message),
                },
                occurred_at=now,
            )

    def pending(self, session_id: str, *, actor_id: str) -> list[dict[str, Any]]:
        self.get_session(session_id, actor_id=actor_id)
        with self.repository._read() as db:
            rows = db.execute(
                """
                SELECT * FROM chat_messages
                WHERE session_id = ? AND role = 'assistant'
                  AND status = 'queued'
                ORDER BY sequence
                """,
                (session_id,),
            ).fetchall()
        return [self._message(row) for row in rows]

    def context(self, session_id: str, *, actor_id: str) -> list[dict[str, str]]:
        self.get_session(session_id, actor_id=actor_id)
        with self.repository._read() as db:
            rows = db.execute(
                """
                SELECT sequence, role, content, evidence_json
                FROM chat_messages
                WHERE session_id = ? AND domain_allowed = 1
                  AND (
                      role = 'user'
                      OR (role = 'assistant' AND status = 'completed')
                  )
                ORDER BY sequence DESC LIMIT ?
                """,
                (session_id, _MAX_CONTEXT_MESSAGES * 2),
            ).fetchall()
        excluded_sequences: set[int] = set()
        for row in rows:
            if str(row["role"]) != "assistant":
                continue
            try:
                evidence = json.loads(row["evidence_json"])
            except (TypeError, json.JSONDecodeError):
                continue
            if (
                isinstance(evidence, dict)
                and evidence.get("answer_kind") == "news_retrieval"
            ):
                sequence = int(row["sequence"])
                excluded_sequences.update({sequence - 1, sequence})
        selected: list[dict[str, str]] = []
        used = 0
        for row in reversed(rows):
            if int(row["sequence"]) in excluded_sequences:
                continue
            if len(selected) >= _MAX_CONTEXT_MESSAGES:
                break
            content = str(row["content"])
            remaining = _MAX_CONTEXT_CHARS - used
            if remaining <= 0:
                break
            selected.append({"role": str(row["role"]), "content": content[:remaining]})
            used += min(len(content), remaining)
        return selected

    def latest_general_knowledge_context(
        self, session_id: str, *, actor_id: str
    ) -> dict[str, str] | None:
        """Return only the latest governed common-knowledge turn.

        Refusals, Harness answers and arbitrary conversation history are never
        eligible for the dedicated general-knowledge provider request.
        """

        self.get_session(session_id, actor_id=actor_id)
        with self.repository._read() as db:
            rows = db.execute(
                """
                SELECT assistant.content AS answer,
                       assistant.evidence_json AS evidence_json,
                       assistant.status AS assistant_status,
                       assistant.domain_allowed AS domain_allowed,
                       user.content AS question
                FROM chat_messages AS assistant
                JOIN chat_messages AS user
                  ON user.session_id = assistant.session_id
                 AND user.sequence = assistant.sequence - 1
                 AND user.role = 'user'
                WHERE assistant.session_id = ?
                  AND assistant.role = 'assistant'
                ORDER BY assistant.sequence DESC
                LIMIT 1
                """,
                (session_id,),
            ).fetchall()
        for row in rows:
            if row["assistant_status"] != "completed" or not bool(
                row["domain_allowed"]
            ):
                continue
            try:
                evidence = json.loads(row["evidence_json"])
            except (TypeError, json.JSONDecodeError):
                continue
            if (
                not isinstance(evidence, dict)
                or evidence.get("general_knowledge") is not True
                or evidence.get("answer_kind")
                not in {"model_common_knowledge", "local_knowledge"}
            ):
                continue
            question = str(row["question"]).strip()
            answer = str(row["answer"]).strip()
            for disclaimer in (
                _GENERAL_KNOWLEDGE_DISCLAIMER,
                _FINAL_DISCLAIMER,
            ):
                answer = answer.removesuffix(disclaimer).rstrip()
            if not question or not answer:
                continue
            return {
                "question": redact_text(
                    question,
                    maximum=_MAX_GENERAL_CONTEXT_QUESTION_CHARS,
                ),
                "answer": redact_text(
                    answer,
                    maximum=_MAX_GENERAL_CONTEXT_ANSWER_CHARS,
                ),
            }
        return None

    def latest_user_content(self, session_id: str, *, actor_id: str) -> str:
        self.get_session(session_id, actor_id=actor_id)
        with self.repository._read() as db:
            row = db.execute(
                """
                SELECT content FROM chat_messages
                WHERE session_id = ? AND role = 'user'
                ORDER BY sequence DESC LIMIT 1
                """,
                (session_id,),
            ).fetchone()
        return str(row["content"]) if row is not None else ""


class CoalChatRuntime:
    def __init__(
        self,
        service: Any,
        harness: Any,
        *,
        skills: SkillRegistry | None = None,
    ):
        self.service = service
        self.harness = harness
        self.skills = skills or SkillRegistry()
        self.store = ChatStore(service.repository)
        self._model_provider_lock = threading.Lock()
        self._model_provider_active = 0
        self._model_provider_by_actor: dict[str, int] = {}

    def _acquire_model_provider(self, actor_id: str) -> bool:
        with self._model_provider_lock:
            actor_active = self._model_provider_by_actor.get(actor_id, 0)
            if (
                self._model_provider_active >= _MAX_CHAT_PROVIDER_GLOBAL
                or actor_active >= _MAX_CHAT_PROVIDER_PER_ACTOR
            ):
                return False
            self._model_provider_active += 1
            self._model_provider_by_actor[actor_id] = actor_active + 1
            return True

    def _release_model_provider(self, actor_id: str) -> None:
        with self._model_provider_lock:
            actor_active = self._model_provider_by_actor.get(actor_id, 0)
            if actor_active <= 1:
                self._model_provider_by_actor.pop(actor_id, None)
            else:
                self._model_provider_by_actor[actor_id] = actor_active - 1
            if self._model_provider_active > 0:
                self._model_provider_active -= 1

    @staticmethod
    def _actor(value: Any) -> str:
        if not isinstance(value, str) or not value or len(value) > 128:
            raise ValueError("actor_id 格式非法")
        return value

    def _draft(self, value: Any) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str) or _DRAFT_ID.fullmatch(value) is None:
            raise ValueError("draft_id 格式非法")
        self.service.get_analysis_draft(value)
        return value

    @staticmethod
    def _session_id(value: Any) -> str:
        if not isinstance(value, str) or _SESSION_ID.fullmatch(value) is None:
            raise NotFoundError("煤炭对话不存在")
        return value

    def create_session(
        self,
        *,
        actor_id: str,
        title: Any = None,
        draft_id: Any = None,
        client_request_id: Any = None,
    ) -> dict[str, Any]:
        actor = self._actor(actor_id)
        if title is None:
            normalized_title = "煤炭业务对话"
        elif (
            not isinstance(title, str)
            or not title.strip()
            or len(title.strip()) > 80
            or has_secret_material(title)
        ):
            raise ValueError("title 必须是 1 到 80 字符且不能包含凭证")
        else:
            normalized_title = title.strip()
        if client_request_id is None:
            normalized_request_id = "server-" + str(uuid.uuid4())
        elif (
            not isinstance(client_request_id, str)
            or _CLIENT_MESSAGE_ID.fullmatch(client_request_id) is None
        ):
            raise ValueError("client_request_id 必须是 1 到 128 字符的安全标识")
        else:
            normalized_request_id = client_request_id
        normalized_draft = self._draft(draft_id)
        production_context = False
        if normalized_draft is not None:
            view = self.service.get_analysis_draft(normalized_draft)
            production_context = (
                view.get("_meta", {}).get("source_kind")
                == "production_data_batch"
            )
        session = self.store.create_session(
            actor_id=actor,
            title=normalized_title,
            draft_id=None if production_context else normalized_draft,
            context_draft_id=(normalized_draft if production_context else None),
            client_request_id=normalized_request_id,
        )
        return {
            "session": {
                **session,
                "messages": [],
                "integrity": self.store.integrity(
                    session["session_id"], actor_id=actor
                ),
            },
            "messages": [],
            "message_count": 0,
            "integrity": self.store.integrity(session["session_id"], actor_id=actor),
        }

    def list_sessions(
        self, *, actor_id: str, limit: int, offset: int
    ) -> tuple[list[dict[str, Any]], int]:
        actor = self._actor(actor_id)
        items, total = self.store.list_sessions(
            actor_id=actor, limit=limit, offset=offset
        )
        for item in items:
            integrity = self.store.integrity(item["session_id"], actor_id=actor)
            item["integrity"] = integrity
            if not integrity["valid"]:
                item["title"] = "对话完整性异常"
                item["last_message_preview"] = None
                item["last_message_status"] = "failed"
        return items, total

    def get_session(self, session_id: Any, *, actor_id: str) -> dict[str, Any]:
        actor = self._actor(actor_id)
        selected = self._session_id(session_id)
        integrity = self.store.integrity(selected, actor_id=actor)
        if not integrity["valid"]:
            session = self.store.get_session(selected, actor_id=actor)
            return {
                "session": {
                    **session,
                    "title": "对话完整性异常",
                    "messages": [],
                    "integrity": integrity,
                },
                "messages": [],
                "message_count": 0,
                "messages_truncated": False,
                "integrity": integrity,
                "actionable": False,
            }
        self._reconcile(selected, actor_id=actor)
        integrity = self.store.integrity(selected, actor_id=actor)
        if not integrity["valid"]:
            session = self.store.get_session(selected, actor_id=actor)
            return {
                "session": {
                    **session,
                    "title": "对话完整性异常",
                    "messages": [],
                    "integrity": integrity,
                },
                "messages": [],
                "message_count": 0,
                "messages_truncated": False,
                "integrity": integrity,
                "actionable": False,
            }
        session = self.store.get_session(selected, actor_id=actor)
        messages, total = self.store.messages(selected, actor_id=actor)
        return {
            "session": {
                **session,
                "messages": messages,
                "integrity": integrity,
            },
            "messages": messages,
            "message_count": total,
            "messages_truncated": total > len(messages),
            "integrity": integrity,
            "actionable": True,
        }

    def delete_session(self, session_id: Any, *, actor_id: str) -> dict[str, Any]:
        actor = self._actor(actor_id)
        selected = self._session_id(session_id)
        self.store.require_integrity(selected, actor_id=actor)
        self._reconcile(selected, actor_id=actor)
        self.store.require_integrity(selected, actor_id=actor)
        return self.store.soft_delete_session(selected, actor_id=actor)

    def post_message(
        self,
        session_id: Any,
        *,
        actor_id: str,
        content: Any,
        draft_id: Any = None,
        client_message_id: Any = None,
    ) -> dict[str, Any]:
        actor = self._actor(actor_id)
        selected = self._session_id(session_id)
        self.store.require_integrity(selected, actor_id=actor)
        self._reconcile(selected, actor_id=actor)
        self.store.require_integrity(selected, actor_id=actor)
        if (
            not isinstance(content, str)
            or not content.strip()
            or len(content.strip()) > _MAX_MESSAGE_CHARS
        ):
            raise ValueError("content 必须是 1 到 2000 字符的文本")
        contains_secret = has_secret_material(content)
        safe_content = redact_text(content.strip(), maximum=_MAX_MESSAGE_CHARS)
        if client_message_id is None:
            normalized_client_id = "server-" + str(uuid.uuid4())
        elif (
            not isinstance(client_message_id, str)
            or _CLIENT_MESSAGE_ID.fullmatch(client_message_id) is None
        ):
            raise ValueError("client_message_id 必须是 1 到 128 字符的安全标识")
        else:
            normalized_client_id = client_message_id
        has_context = self.store.has_accepted_context(selected, actor_id=actor)
        decision = (
            DomainDecision(False, "credential_material")
            if contains_secret
            else coal_domain_decision(safe_content, has_accepted_context=has_context)
        )
        news_decision = (
            coal_news_search_decision(safe_content)
            if decision.allowed
            else DomainDecision(False, "domain_denied")
        )
        # A standalone news query must not bind, load or send a supplied
        # enterprise draft. A session that was already bound remains bound,
        # but the skill receives only the locally normalized news request.
        normalized_draft = None if news_decision.allowed else self._draft(draft_id)
        general_context = (
            self.store.latest_general_knowledge_context(selected, actor_id=actor)
            if decision.allowed
            else None
        )
        if not decision.allowed:
            refusal = _governed_answer(
                "对话不能代替人员执行确认、签名、报送、提交或绕过审批，"
                "因此已在服务端拒绝；未调用模型或工具。"
                if decision.reason == "prohibited_action"
                else "这条请求不在煤炭生产、洗选、计量、煤质、库存、"
                "来源凭证或交叉核对业务范围内，因此已在服务端拒绝；"
                "未调用模型或工具。请改为明确的煤炭业务问题。"
            )
            _user_id, assistant_id, _created = self.store.begin_turn(
                selected,
                actor_id=actor,
                content=safe_content,
                decision=decision,
                draft_id=normalized_draft,
                client_message_id=normalized_client_id,
                refusal=refusal,
            )
            assistant = self.store.message(assistant_id, actor_id=actor)
            return {
                **self.get_session(selected, actor_id=actor),
                "run_id": assistant["run_id"],
            }

        _user_id, assistant_id, created = self.store.begin_turn(
            selected,
            actor_id=actor,
            content=safe_content,
            decision=decision,
            draft_id=normalized_draft,
            client_message_id=normalized_client_id,
        )
        if not created:
            assistant = self.store.message(assistant_id, actor_id=actor)
            return {
                **self.get_session(selected, actor_id=actor),
                "run_id": assistant["run_id"],
            }
        session = self.store.get_session(selected, actor_id=actor)
        if news_decision.allowed:
            try:
                news = self.skills.call(
                    "coal-news-search",
                    {"question": safe_content},
                )
            except Exception:
                news = {
                    "status": "failed",
                    "searched_at": utc_text(),
                    "window_days": 7,
                    "result_count": 0,
                    "provider": "multi-provider",
                    "providers": [],
                    "provider_attempts": [],
                    "fallback_used": False,
                    "cached": False,
                    "failure_code": "skill_error",
                    "sources": [],
                }
            status = news.get("status")
            sources = _numbered_news_sources(news.get("sources"))
            summary_status = "not_attempted"
            summary_failure_code: str | None = None
            summary_provider_called = False
            model_generated = False
            if status in {"succeeded", "partial"} and sources:
                provider = self.harness.llm_provider
                summary_method = getattr(provider, "summarize_coal_news", None)
                if provider is None:
                    summary_status = "unavailable"
                    summary_failure_code = "not_configured"
                elif not callable(summary_method):
                    summary_status = "unavailable"
                    summary_failure_code = "unsupported"
                elif not self._acquire_model_provider(actor):
                    summary_status = "unavailable"
                    summary_failure_code = "busy"
                else:
                    summary_provider_called = True
                    try:
                        summary_sources = [
                            {
                                key: source.get(key)
                                for key in (
                                    "source_id",
                                    "title",
                                    "publisher",
                                    "published_at",
                                    "published_time_text",
                                    "retrieval_provider",
                                    "search_snippet",
                                    "snippet_truncated",
                                )
                            }
                            for source in sources
                        ]
                        try:
                            answer = _validated_news_summary_answer(
                                summary_method(
                                    topic=str(news.get("topic") or "煤炭"),
                                    window_days=int(news.get("window_days") or 7),
                                    searched_at=str(
                                        news.get("searched_at") or utc_text()
                                    ),
                                    sources=summary_sources,
                                )
                            )
                        except ValueError:
                            summary_status = "failed"
                            summary_failure_code = "invalid_response"
                        except Exception:
                            summary_status = "failed"
                            summary_failure_code = "provider_error"
                        else:
                            summary_status = "succeeded"
                            model_generated = True
                    finally:
                        self._release_model_provider(actor)
                if model_generated:
                    answer += (
                        f"\n\n检索范围：最近 {news.get('window_days')} 天，"
                        f"共采用 {len(sources)} 条公开搜索结果；"
                        "摘要基于标题和搜索片段，未读取新闻全文。"
                    )
                    attempt_summary = _news_attempt_summary(
                        news.get("provider_attempts")
                    )
                    if status == "partial" and attempt_summary:
                        answer += f"\n检索覆盖说明：{attempt_summary}；结果可能不完整。"
                else:
                    reason = {
                        "not_configured": "未配置可用的总结模型",
                        "unsupported": "当前模型接口不支持新闻总结",
                        "busy": "总结任务繁忙",
                        "provider_error": "总结模型暂时不可用",
                        "invalid_response": "总结结果未通过引用校验",
                    }.get(summary_failure_code, "自动总结暂时不可用")
                    answer = _news_source_list(
                        news,
                        sources,
                        introduction=(
                            f"已检索最近 {news.get('window_days')} 天的煤炭新闻，"
                            f"取得 {len(sources)} 条可核验来源；但{reason}。"
                            "以下先列出检索结果，不用模型记忆补写摘要："
                        ),
                    )
            elif news.get("failure_code") == "no_results":
                summary_status = "not_attempted"
                summary_failure_code = "no_sources"
                answer = (
                    f"已完成最近 {news.get('window_days')} 天的公开煤炭新闻"
                    "检索，但没有找到通过时间、相关性和安全校验的结果。"
                    "这不代表期间一定没有相关新闻，可以稍后重试或调整为"
                    " 24 小时、7 天、30 天窗口。"
                )
            else:
                summary_status = "not_attempted"
                summary_failure_code = "retrieval_failed"
                attempt_summary = _news_attempt_summary(news.get("provider_attempts"))
                failure_code = str(news.get("failure_code", ""))
                reason = _NEWS_FAILURE_LABELS.get(
                    failure_code,
                    "所有已配置新闻源均未返回可核验结果",
                )
                answer = f"煤炭新闻检索未完成：{reason}。"
                if attempt_summary:
                    answer += f"\n已尝试：{attempt_summary}。"
                answer += (
                    "\n请检查服务器 DNS/代理与模型、联网搜索服务配置后重试；"
                    "本次没有用离线知识冒充最新新闻，也没有读取或发送企业草稿。"
                )
            provider_attempts = (
                news.get("provider_attempts")
                if isinstance(news.get("provider_attempts"), list)
                else []
            )
            deepseek_search_called = any(
                isinstance(attempt, dict)
                and attempt.get("provider") == "deepseek-web-search"
                for attempt in provider_attempts
            )
            self.store.complete_message(
                assistant_id,
                actor_id=actor,
                status="completed",
                content=_governed_news_answer(answer),
                evidence={
                    "not_a_regulatory_determination": True,
                    "answer_kind": "news_retrieval",
                    "skill_name": "coal-news-search",
                    "provider_called": bool(provider_attempts)
                    or summary_provider_called,
                    "retrieval_provider_called": bool(provider_attempts),
                    "summary_provider_called": summary_provider_called,
                    "model_provider_called": (
                        deepseek_search_called or summary_provider_called
                    ),
                    "model_generated": model_generated,
                    "public_search_evidence_sent_to_model": (summary_provider_called),
                    "raw_user_question_sent_to_summary_model": False,
                    "enterprise_data_sent_to_provider": False,
                    "draft_data_sent_to_skill": False,
                    "summary": {
                        "status": summary_status,
                        "provider": (
                            "openai-compatible-chat-completions"
                            if summary_provider_called
                            else None
                        ),
                        "grounding": "search_title_and_snippet",
                        "source_count": (
                            len(sources) if status in {"succeeded", "partial"} else 0
                        ),
                        "failure_code": summary_failure_code,
                    },
                    "retrieval": {
                        key: news.get(key)
                        for key in (
                            "status",
                            "searched_at",
                            "topic",
                            "window_days",
                            "result_count",
                            "provider",
                            "providers",
                            "provider_attempts",
                            "fallback_used",
                            "partial_reasons",
                            "cached",
                            "failure_code",
                        )
                        if news.get(key) is not None
                    },
                    "sources": sources,
                },
            )
            return {
                **self.get_session(selected, actor_id=actor),
                "run_id": None,
            }
        knowledge_decision = coal_general_knowledge_decision(
            safe_content, has_general_context=general_context is not None
        )
        if decision.reason == "local_capability_greeting":
            topic, local = _local_knowledge(safe_content)
            self.store.complete_message(
                assistant_id,
                actor_id=actor,
                status="completed",
                content=_governed_answer(local),
                evidence={
                    "not_a_regulatory_determination": True,
                    "provider_called": False,
                    "tool_profile": "chat_read_only",
                    "local_knowledge_topic": topic,
                },
            )
            return {
                **self.get_session(selected, actor_id=actor),
                "run_id": None,
            }
        if knowledge_decision.allowed:
            local_question = safe_content
            if (
                knowledge_decision.reason == "general_coal_follow_up"
                and general_context is not None
            ):
                local_question = general_context["question"] + " " + safe_content
            topic, local = _local_knowledge(local_question)
            provider = self.harness.llm_provider
            answer_method = getattr(provider, "answer_coal_general_knowledge", None)
            provider_called = False
            provider_rate_limited = False
            model_answer: str | None = None
            if callable(answer_method):
                if self._acquire_model_provider(actor):
                    provider_called = True
                    try:
                        provider_arguments: dict[str, str] = {"question": safe_content}
                        if (
                            knowledge_decision.reason == "general_coal_follow_up"
                            and general_context is not None
                        ):
                            provider_arguments.update(
                                {
                                    "previous_question": general_context["question"],
                                    "previous_answer": general_context["answer"],
                                }
                            )
                        # Only the current question and one governed common-
                        # knowledge turn cross this boundary. Drafts, tool
                        # results, Harness answers and refusals never do.
                        model_answer = _validated_general_answer(
                            answer_method(**provider_arguments)
                        )
                    except Exception:
                        model_answer = None
                    finally:
                        self._release_model_provider(actor)
                else:
                    provider_rate_limited = True
            model_generated = model_answer is not None
            self.store.complete_message(
                assistant_id,
                actor_id=actor,
                status="completed",
                content=_governed_general_answer(model_answer or local),
                evidence={
                    "not_a_regulatory_determination": True,
                    "not_regulatory": True,
                    "general_knowledge": True,
                    "model_generated": model_generated,
                    "answer_kind": (
                        "model_common_knowledge"
                        if model_generated
                        else "local_knowledge"
                    ),
                    "provider_called": provider_called,
                    "provider_failure_fallback": (
                        provider_called and not model_generated
                    ),
                    "provider_rate_limited": provider_rate_limited,
                    "tool_profile": "chat_read_only",
                    "local_knowledge_topic": (None if model_generated else topic),
                    "routing_reason": knowledge_decision.reason,
                    "enterprise_data_sent_to_provider": False,
                },
            )
            return {
                **self.get_session(selected, actor_id=actor),
                "run_id": None,
            }
        if session["draft_id"] is None and self.harness.llm_provider is None:
            topic, local = _local_knowledge(safe_content)
            self.store.complete_message(
                assistant_id,
                actor_id=actor,
                status="completed",
                content=_governed_answer(local),
                evidence={
                    "not_a_regulatory_determination": True,
                    "provider_called": False,
                    "tool_profile": "chat_read_only",
                    "local_knowledge_topic": topic,
                },
            )
            return {
                **self.get_session(selected, actor_id=actor),
                "run_id": None,
            }
        context = self.store.context(selected, actor_id=actor)
        task = self._task(context)
        try:
            run = self.harness.create(
                actor_id=actor,
                task=task,
                draft_id=session["draft_id"],
                mode="auto",
                allow_mutations=False,
                tool_profile="chat_read_only",
            )
            run_id = run["run_id"]
            self.store.attach_run(assistant_id, actor_id=actor, run_id=run_id)
        except Exception:
            self.store.complete_message(
                assistant_id,
                actor_id=actor,
                status="failed",
                content=_governed_answer(
                    "煤炭分析任务未能启动；未执行任何确认、签名或提交。"
                ),
                evidence={
                    "not_a_regulatory_determination": True,
                    "tool_profile": "chat_read_only",
                    "run_started": False,
                },
            )
            raise
        return {**self.get_session(selected, actor_id=actor), "run_id": run_id}

    @staticmethod
    def _task(context: list[dict[str, str]]) -> str:
        payload = canonical_json(
            {
                "conversation": context,
                "instruction": (
                    "只处理当前煤炭业务问题；只能调用只读确定性工具。"
                    "不得规划或执行草稿修改、确认、签名、提交，不得把缺失事实"
                    "当作已知，不得给出监管认定。"
                ),
            }
        )
        return redact_text(payload, maximum=3_900)

    def _reconcile(self, session_id: str, *, actor_id: str) -> None:
        for pending in self.store.pending(session_id, actor_id=actor_id):
            run_id = pending["run_id"]
            if run_id is None:
                try:
                    updated = parse_aware_datetime(
                        pending["updated_at"], "chat message updated_at"
                    )
                except ValueError:
                    updated = datetime.min.replace(tzinfo=UTC)
                if (datetime.now(UTC) - updated).total_seconds() < 30:
                    continue
                self.store.complete_message(
                    pending["message_id"],
                    actor_id=actor_id,
                    status="failed",
                    content=_governed_answer(
                        "服务在建立煤炭分析任务前中断；请重新发送。"
                    ),
                    evidence={
                        "not_a_regulatory_determination": True,
                        "run_started": False,
                    },
                )
                continue
            try:
                run = self.harness.get(run_id, actor_id=actor_id)
            except NotFoundError:
                self.store.complete_message(
                    pending["message_id"],
                    actor_id=actor_id,
                    status="failed",
                    content=_governed_answer(
                        "关联的煤炭分析任务不存在；未形成业务结论。"
                    ),
                    evidence={
                        "not_a_regulatory_determination": True,
                        "run_id": run_id,
                        "run_integrity_valid": False,
                    },
                )
                continue
            if run["status"] not in {"completed", "failed", "cancelled"}:
                continue
            integrity = run.get("integrity")
            if not isinstance(integrity, dict) or not integrity.get("valid"):
                self.store.complete_message(
                    pending["message_id"],
                    actor_id=actor_id,
                    status="failed",
                    content=_governed_answer(
                        "关联任务的审计完整性校验失败，已隐藏结果。"
                    ),
                    evidence={
                        "not_a_regulatory_determination": True,
                        "run_id": run_id,
                        "run_integrity_valid": False,
                    },
                )
                continue
            calls = run.get("tool_calls", [])
            unsafe = False
            tool_evidence: list[dict[str, Any]] = []
            for call in calls if isinstance(calls, list) else []:
                try:
                    spec = self.harness.registry.get(call["tool_name"])
                except Exception:
                    unsafe = True
                    break
                if spec.mutating or spec.requires_approval:
                    unsafe = True
                    break
                tool_evidence.append(
                    {
                        "tool_name": call["tool_name"],
                        "status": call["status"],
                        "evidence_grounding": call["evidence_grounding"],
                        "arguments_sha256": call["arguments_sha256"],
                        "result_sha256": call["result_sha256"],
                    }
                )
            if unsafe or run.get("approvals"):
                self.store.complete_message(
                    pending["message_id"],
                    actor_id=actor_id,
                    status="failed",
                    content=_governed_answer(
                        "关联任务出现非只读动作，结果已拒绝展示且未获批准。"
                    ),
                    evidence={
                        "not_a_regulatory_determination": True,
                        "run_id": run_id,
                        "run_integrity_valid": True,
                        "tool_profile": "chat_read_only",
                        "unsafe_action_rejected": True,
                    },
                )
                continue
            session = self.store.get_session(session_id, actor_id=actor_id)
            if run["status"] == "completed" and tool_evidence:
                content = _governed_answer(str(run.get("answer") or run["summary"]))
                status = "completed"
                knowledge_topic = None
            elif session["draft_id"] is None:
                latest = self.store.latest_user_content(session_id, actor_id=actor_id)
                knowledge_topic, local = _local_knowledge(latest)
                content = _governed_answer(local)
                status = "completed"
            else:
                knowledge_topic = None
                content = _governed_answer(
                    "本次草稿分析未完成，未形成可展示的工具证据；请核对草稿数据后重试。"
                )
                status = "failed"
            self.store.complete_message(
                pending["message_id"],
                actor_id=actor_id,
                status=status,
                content=content,
                evidence={
                    "not_a_regulatory_determination": True,
                    "run_id": run_id,
                    "run_status": run["status"],
                    "run_integrity_valid": True,
                    "tool_profile": "chat_read_only",
                    "provider_text_used_as_business_conclusion": False,
                    "tools": tool_evidence,
                    "local_knowledge_topic": knowledge_topic,
                },
            )
