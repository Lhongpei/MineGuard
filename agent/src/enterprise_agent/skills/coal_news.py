"""Fail-closed, multi-provider retrieval for current coal news.

Only locally normalized coal topics and a date window leave the process.
Enterprise drafts, identifiers, chat history, and user-provided URLs are never
sent to a search provider.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import re
import threading
import time
import unicodedata
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from datetime import time as datetime_time
from email.utils import parsedate_to_datetime
from html import unescape
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit
from zoneinfo import ZoneInfo

from ..llm import LLMConfig
from ..util import utc_text

_BAIDU_ENDPOINT = "https://www.baidu.com/s"
_BING_ENDPOINT = "https://www.bing.com/news/search"
_BAIDU_PROVIDER = "baidu-news-search"
_DEEPSEEK_PROVIDER = "deepseek-web-search"
_BING_PROVIDER = "bing-news-rss"
_MULTI_PROVIDER = "multi-provider"
_ALLOWED_WINDOWS = frozenset({1, 7, 30})
_MAX_QUESTION_CHARS = 2_000
_MAX_URL_CHARS = 2_048
_MAX_TITLE_CHARS = 300
_MAX_PUBLISHER_CHARS = 160
_MAX_SEARCH_SNIPPET_CHARS = 1_000
_MAX_PROVIDER_ATTEMPTS = 8
_SCHEDULING_GRACE_SECONDS = 0.15
_PROVIDER_SCHEDULING_GRACE_SECONDS = 0.05
_DISALLOWED_XML = re.compile(rb"<!\s*(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_UNSAFE_FORMAT = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]")
_XML_ENCODING = re.compile(
    rb"""<\?xml[^>]{0,200}\bencoding\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)
_XML_ENCODING_TEXT = re.compile(
    r"""(<\?xml[^>]{0,200})\s+encoding\s*=\s*["'][^"']+["']""",
    re.IGNORECASE,
)
_CHINA_TZ = ZoneInfo("Asia/Shanghai")

_TOPICS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("焦煤", "炼焦煤"), "焦煤"),
    (("动力煤",), "动力煤"),
    (("无烟煤",), "无烟煤"),
    (("褐煤",), "褐煤"),
    (("煤矿安全", "矿难", "事故", "安全生产"), "煤矿安全"),
    (("煤价", "价格", "行情"), "煤炭 市场价格"),
    (("政策", "监管", "法规"), "煤炭 政策"),
    (("供需", "库存", "产量", "进口", "出口"), "煤炭 供需"),
    (("运输", "铁路", "港口", "发运"), "煤炭 运输"),
    (("环保", "碳排放", "低碳"), "煤炭 环保"),
    (("洗选", "选煤"), "煤炭 洗选"),
    (("煤炭", "煤矿", "原煤", "商品煤"), "煤炭"),
)
_COAL_RELEVANCE = (
    "煤",
    "矿井",
    "矿山",
    "焦炭",
    "火电",
    "coal",
    "colliery",
    "mining",
)
_PROVIDER_LABELS = {
    _BAIDU_PROVIDER: "百度新闻",
    _DEEPSEEK_PROVIDER: "DeepSeek 联网搜索",
    _BING_PROVIDER: "Bing News RSS",
}
_DOMAIN_LABELS = {
    "cnenergynews.cn": "中国能源报",
    "coalchina.org.cn": "中国煤炭运销协会",
    "stats.gov.cn": "国家统计局",
    "ndrc.gov.cn": "国家发展改革委",
    "chinamine-safety.gov.cn": "国家矿山安全监察局",
    "sxcoal.com": "煤炭资源网",
    "mysteel.com": "我的钢铁网",
}


@dataclass(frozen=True, slots=True)
class CoalNewsConfig:
    enabled: bool = True
    timeout_seconds: float = 25.0
    baidu_timeout_seconds: float = 3.0
    deepseek_timeout_seconds: float = 24.0
    cache_ttl_seconds: int = 300
    max_results: int = 8
    max_response_bytes: int = 1024 * 1024
    max_concurrency: int = 4
    baidu_enabled: bool = True
    deepseek_web_search_enabled: bool = True
    bing_fallback_enabled: bool = False

    def __post_init__(self) -> None:
        if not 1.0 <= self.timeout_seconds <= 60.0:
            raise ValueError("煤炭新闻搜索总超时必须在 1-60 秒之间")
        if not 0.1 <= self.baidu_timeout_seconds <= 10.0:
            raise ValueError("百度新闻搜索超时必须在 0.1-10 秒之间")
        if not 3.0 <= self.deepseek_timeout_seconds <= 60.0:
            raise ValueError("DeepSeek 新闻搜索超时必须在 3-60 秒之间")
        if self.baidu_enabled and self.baidu_timeout_seconds >= self.timeout_seconds:
            raise ValueError("百度新闻搜索超时必须小于总超时")
        if not 30 <= self.cache_ttl_seconds <= 3_600:
            raise ValueError("煤炭新闻缓存时间必须在 30-3600 秒之间")
        if not 1 <= self.max_results <= 20:
            raise ValueError("煤炭新闻结果数必须在 1-20 之间")
        if not 64 * 1024 <= self.max_response_bytes <= 2 * 1024 * 1024:
            raise ValueError("煤炭新闻响应上限必须在 64 KiB-2 MiB 之间")
        if not 1 <= self.max_concurrency <= 8:
            raise ValueError("煤炭新闻并发数必须在 1-8 之间")


@dataclass(frozen=True, slots=True)
class NormalizedNewsRequest:
    topic: str
    window_days: int


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Return redirects as HTTP errors so providers cannot change origins."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        return None


class _MarkupTextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)


class _BaiduSDataParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self.payloads: list[str] = []

    def handle_comment(self, data: str) -> None:
        value = data.strip()
        if value.startswith("s-data:") and len(self.payloads) < 100:
            self.payloads.append(value[len("s-data:") :])


def _default_opener(request: urllib.request.Request, timeout_seconds: float) -> Any:
    opener = urllib.request.build_opener(_NoRedirectHandler())
    return opener.open(request, timeout=timeout_seconds)


def _now() -> datetime:
    return datetime.now(UTC)


def _strip_markup(value: str) -> str:
    parser = _MarkupTextExtractor()
    try:
        parser.feed(value)
        parser.close()
    except Exception:
        return value
    return "".join(parser.parts)


def _normal_text(
    value: Any,
    *,
    maximum: int,
    strip_markup: bool = False,
) -> str | None:
    if not isinstance(value, str):
        return None
    source = _strip_markup(value) if strip_markup else value
    cleaned = unicodedata.normalize("NFKC", unescape(source))
    cleaned = " ".join(cleaned.split())
    if (
        not cleaned
        or len(cleaned) > maximum
        or _CONTROL.search(cleaned) is not None
        or _UNSAFE_FORMAT.search(cleaned) is not None
    ):
        return None
    return cleaned


def normalize_news_request(
    question: str, *, window_days: int | None = None
) -> NormalizedNewsRequest:
    """Map arbitrary coal wording to a local, finite outbound vocabulary."""

    if (
        not isinstance(question, str)
        or not question.strip()
        or len(question.strip()) > _MAX_QUESTION_CHARS
    ):
        raise ValueError("新闻问题格式非法")
    normalized = unicodedata.normalize("NFKC", question).casefold()
    normalized = re.sub(r"[\u200b-\u200f\u2060\ufeff]", "", normalized)
    normalized = " ".join(normalized.split())
    topic = next(
        (
            canonical
            for terms, canonical in _TOPICS
            if any(term.casefold() in normalized for term in terms)
        ),
        None,
    )
    if topic is None:
        raise ValueError("新闻搜索只接受可归一化的煤炭主题")
    inferred_window = 7
    if re.search(
        r"(?:24\s*(?:小时|h)|近\s*1\s*天|过去\s*1\s*天|"
        r"今天|今日|当天|最新)",
        normalized,
    ):
        inferred_window = 1
    elif re.search(
        r"(?:30\s*天|近\s*一\s*月|过去\s*一\s*月|"
        r"一个月|本月|近月)",
        normalized,
    ):
        inferred_window = 30
    elif re.search(r"(?:7\s*天|一周|本周|近周)", normalized):
        inferred_window = 7
    selected_window = inferred_window if window_days is None else window_days
    if isinstance(selected_window, bool) or selected_window not in _ALLOWED_WINDOWS:
        raise ValueError("window_days 只支持 1、7、30")
    return NormalizedNewsRequest(topic=topic, window_days=int(selected_window))


def _baidu_url(request: NormalizedNewsRequest) -> str:
    query = urlencode(
        {
            "ie": "utf-8",
            "tn": "news",
            "word": request.topic,
            "rtt": "4",
            "bsst": "1",
            "cl": "2",
            "rn": "10",
        }
    )
    return f"{_BAIDU_ENDPOINT}?{query}"


def _bing_url(request: NormalizedNewsRequest) -> str:
    query = urlencode(
        {
            "q": f"{request.topic} when:{request.window_days}d",
            "format": "rss",
            "setlang": "zh-hans",
            "cc": "CN",
        }
    )
    return f"{_BING_ENDPOINT}?{query}"


def _deepseek_url(config: LLMConfig) -> str:
    base = config.base_url.rstrip("/")
    if base.endswith("/anthropic"):
        return base + "/v1/messages"
    return base + "/anthropic/v1/messages"


def _is_public_https_url(value: str) -> bool:
    if (
        not value
        or len(value) > _MAX_URL_CHARS
        or _CONTROL.search(value) is not None
        or any(character.isspace() for character in value)
        or "\\" in value
    ):
        return False
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return False
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
    ):
        return False
    hostname = parsed.hostname.rstrip(".").casefold()
    if (
        hostname == "localhost"
        or hostname.endswith(".localhost")
        or hostname.endswith(".local")
        or hostname.endswith(".internal")
    ):
        return False
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return True
    return not any(
        (
            address.is_private,
            address.is_loopback,
            address.is_link_local,
            address.is_multicast,
            address.is_reserved,
            address.is_unspecified,
        )
    )


def _canonical_public_url(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = unescape(value).strip()
    if not _is_public_https_url(candidate):
        return None
    parsed = urlsplit(candidate)
    return urlunsplit(("https", parsed.netloc, parsed.path or "/", parsed.query, ""))


def _safe_bing_article_url(value: str) -> str | None:
    candidate = unescape(value).strip()
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return None
    if (
        parsed.scheme == "https"
        and parsed.hostname == "www.bing.com"
        and parsed.username is None
        and parsed.password is None
    ):
        originals = parse_qs(parsed.query, keep_blank_values=False).get("url", [])
        if len(originals) == 1:
            candidate = originals[0].strip()
    return _canonical_public_url(candidate)


def _response_header(response: Any, name: str) -> str | None:
    headers = getattr(response, "headers", None)
    if headers is None:
        return None
    getter = getattr(headers, "get", None)
    if callable(getter):
        value = getter(name)
        if isinstance(value, str):
            return value.strip()
    if isinstance(headers, Mapping):
        for key, value in headers.items():
            if str(key).casefold() == name.casefold() and isinstance(value, str):
                return value.strip()
    return None


def _content_type(response: Any) -> tuple[str | None, str | None]:
    raw = _response_header(response, "Content-Type")
    if raw is None:
        return None, None
    parts = [part.strip() for part in raw.split(";")]
    media_type = parts[0].casefold() if parts[0] else None
    charset = None
    for part in parts[1:]:
        if part.casefold().startswith("charset="):
            charset = part.split("=", 1)[1].strip("\"' ").casefold()
            break
    return media_type, charset


def _expected_final_url(provider: str, expected: str, actual: str) -> bool:
    try:
        expected_url = urlsplit(expected)
        actual_url = urlsplit(actual)
        expected_port = expected_url.port
        actual_port = actual_url.port
    except (TypeError, ValueError):
        return False
    if (
        actual_url.scheme != expected_url.scheme
        or actual_url.hostname != expected_url.hostname
        or actual_port != expected_port
        or actual_url.username is not None
        or actual_url.password is not None
    ):
        return False
    if provider == _BAIDU_PROVIDER:
        return actual_url.path == "/s"
    if provider == _BING_PROVIDER:
        return actual_url.path == "/news/search"
    return actual_url.path == expected_url.path


def _publisher_from_url(value: str) -> str:
    hostname = (urlsplit(value).hostname or "").casefold().removeprefix("www.")
    for suffix, label in _DOMAIN_LABELS.items():
        if hostname == suffix or hostname.endswith("." + suffix):
            return label
    return hostname or "来源未标明"


def _child_text(item: ET.Element, name: str) -> str:
    for child in item:
        if child.tag.rsplit("}", 1)[-1].casefold() == name.casefold():
            return "".join(child.itertext())
    return ""


def _published_at(value: str) -> datetime | None:
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _local_midnight(value: date) -> datetime:
    return datetime.combine(value, datetime_time.min, tzinfo=_CHINA_TZ)


def _parse_baidu_time(value: Any, *, now: datetime) -> tuple[datetime | None, bool]:
    text = _normal_text(value, maximum=64)
    if text is None:
        return None, False
    local_now = now.astimezone(_CHINA_TZ)
    if text == "刚刚":
        return now, True
    match = re.fullmatch(r"(\d{1,4})分钟前", text)
    if match:
        return now - timedelta(minutes=int(match.group(1))), True
    match = re.fullmatch(r"(\d{1,3})小时前", text)
    if match:
        return now - timedelta(hours=int(match.group(1))), True
    match = re.fullmatch(r"(\d{1,3})天前", text)
    if match:
        return now - timedelta(days=int(match.group(1))), True
    match = re.fullmatch(r"昨天(?:\s*(\d{1,2}):(\d{2}))?", text)
    if match:
        target = local_now.date() - timedelta(days=1)
        hour = int(match.group(1) or 0)
        minute = int(match.group(2) or 0)
        if hour > 23 or minute > 59:
            return None, False
        return datetime.combine(
            target,
            datetime_time(hour=hour, minute=minute),
            tzinfo=_CHINA_TZ,
        ).astimezone(UTC), True
    match = re.fullmatch(r"(\d{4})年(\d{1,2})月(\d{1,2})日", text)
    if match:
        try:
            target = date(*(int(group) for group in match.groups()))
        except ValueError:
            return None, False
        return _local_midnight(target).astimezone(UTC), True
    match = re.fullmatch(r"(\d{1,2})月(\d{1,2})日", text)
    if match:
        try:
            target = date(local_now.year, int(match.group(1)), int(match.group(2)))
        except ValueError:
            return None, False
        parsed = _local_midnight(target)
        if parsed > local_now + timedelta(days=1):
            try:
                parsed = parsed.replace(year=parsed.year - 1)
            except ValueError:
                return None, False
        return parsed.astimezone(UTC), True
    return None, False


def _parse_search_result_date(
    page_age: Any,
    title: str,
    *,
    now: datetime,
) -> tuple[datetime | None, str, str | None]:
    if isinstance(page_age, str) and page_age.strip():
        raw = page_age.strip()
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            parsed = None
        if parsed is not None:
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
            return parsed.astimezone(UTC), "provider", raw
        baidu_style, _estimated = _parse_baidu_time(raw, now=now)
        if baidu_style is not None:
            return baidu_style, "provider", raw
    patterns = (
        r"(?P<y>20\d{2})[年./-](?P<m>\d{1,2})[月./-](?P<d>\d{1,2})日?",
        r"(?P<y>20\d{2})(?P<m>\d{2})(?P<d>\d{2})",
    )
    for pattern in patterns:
        match = re.search(pattern, title)
        if match is None:
            continue
        try:
            target = date(
                int(match.group("y")),
                int(match.group("m")),
                int(match.group("d")),
            )
        except ValueError:
            continue
        return (
            _local_midnight(target).astimezone(UTC),
            "title",
            match.group(0),
        )
    return None, "unavailable", None


def _decode_xml(
    raw: bytes,
    *,
    header_charset: str | None,
) -> str | None:
    declared = None
    match = _XML_ENCODING.search(raw[:512])
    if match is not None:
        declared = match.group(1).decode("ascii", "ignore").casefold()
    selected = (header_charset or declared or "utf-8").replace("_", "-")
    aliases = {
        "utf8": "utf-8",
        "utf-8": "utf-8",
        "us-ascii": "ascii",
        "ascii": "ascii",
        "gb2312": "gb18030",
        "gbk": "gb18030",
        "gb18030": "gb18030",
    }
    codec = aliases.get(selected)
    if codec is None:
        return None
    try:
        decoded = raw.decode(codec, "strict")
    except UnicodeDecodeError:
        return None
    return _XML_ENCODING_TEXT.sub(r"\1", decoded, count=1)


def _source_key(source: Mapping[str, Any]) -> tuple[str, str]:
    title = re.sub(r"\W+", "", str(source.get("title", "")).casefold())
    return str(source.get("url", "")), title


class CoalNewsSearchSkill:
    name = "coal-news-search"

    def __init__(
        self,
        config: CoalNewsConfig | None = None,
        *,
        llm_config: LLMConfig | None = None,
        configuration_guard: Callable[[], Any] | None = None,
        opener: Callable[[urllib.request.Request, float], Any] | None = None,
        clock: Callable[[], datetime] | None = None,
        monotonic: Callable[[], float] | None = None,
    ):
        self.config = config or CoalNewsConfig()
        self.llm_config = llm_config
        self._configuration_guard = configuration_guard
        self._opener = opener or _default_opener
        self._clock = clock or _now
        self._monotonic = monotonic or time.monotonic
        self._cache: dict[tuple[str, int], tuple[datetime, dict[str, Any]]] = {}
        self._cache_lock = threading.Lock()
        self._concurrency = threading.BoundedSemaphore(self.config.max_concurrency)
        self._provider_concurrency = {
            provider: threading.BoundedSemaphore(self.config.max_concurrency)
            for provider in (
                _BAIDU_PROVIDER,
                _DEEPSEEK_PROVIDER,
                _BING_PROVIDER,
            )
        }
        self._runtime_lock = threading.Lock()
        self._runtime_status = (
            "disabled" if not self.config.enabled else "configured_unverified"
        )
        self._last_checked_at: str | None = None
        self._last_provider: str | None = None

    def _configured_providers(self) -> list[str]:
        providers: list[str] = []
        if self.config.baidu_enabled:
            providers.append(_BAIDU_PROVIDER)
        if self.config.deepseek_web_search_enabled and self.llm_config is not None:
            providers.append(_DEEPSEEK_PROVIDER)
        if self.config.bing_fallback_enabled:
            providers.append(_BING_PROVIDER)
        return providers

    def public_definition(self) -> dict[str, Any]:
        with self._runtime_lock:
            runtime_status = self._runtime_status
            last_checked_at = self._last_checked_at
            last_provider = self._last_provider
        return {
            "name": self.name,
            "version": "2.1",
            "description": "百度优先检索近期煤炭新闻，并支持基于搜索证据的 AI 总结",
            "enabled": self.config.enabled,
            "read_only": True,
            "network_access": "fixed_providers_only",
            "providers": self._configured_providers(),
            "provider": _MULTI_PROVIDER,
            "provider_labels": {
                provider: _PROVIDER_LABELS[provider]
                for provider in self._configured_providers()
            },
            "supported_windows_days": [1, 7, 30],
            "accepts_user_url": False,
            "data_boundary": {
                "retrieval": "normalized_coal_topic_and_window_only",
                "summary": (
                    "public_source_id_title_publisher_time_and_search_snippet_only"
                ),
                "enterprise_data": "never",
            },
            "ai_summary_configured": self.llm_config is not None,
            "ai_summary_grounding": "search_title_and_snippet",
            "runtime_status": runtime_status,
            "last_checked_at": last_checked_at,
            "last_provider": last_provider,
        }

    def invoke(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        if not self.config.enabled:
            result = self._failure(
                window_days=7,
                failure_code="disabled",
                status="unavailable",
            )
            self._record_runtime(result)
            return result
        unknown = set(arguments) - {"question", "window_days"}
        if unknown:
            raise ValueError("煤炭新闻技能不支持参数：" + ", ".join(sorted(unknown)))
        normalized = normalize_news_request(
            arguments.get("question"),  # type: ignore[arg-type]
            window_days=arguments.get("window_days"),  # type: ignore[arg-type]
        )
        now = self._aware_now()
        cache_key = (normalized.topic, normalized.window_days)
        with self._cache_lock:
            cached = self._cache.get(cache_key)
            if cached is not None and cached[0] > now:
                result = copy.deepcopy(cached[1])
                result["cached"] = True
                self._record_runtime(result)
                return result
            if cached is not None:
                self._cache.pop(cache_key, None)
        if not self._concurrency.acquire(blocking=False):
            result = self._failure(
                window_days=normalized.window_days,
                topic=normalized.topic,
                failure_code="busy",
                searched_at=utc_text(now),
                status="unavailable",
            )
            self._record_runtime(result)
            return result

        completed = threading.Event()
        result_box: dict[str, dict[str, Any]] = {}

        def retrieve_in_background() -> None:
            try:
                try:
                    result = self._retrieve(normalized, now=now)
                except Exception:
                    result = self._failure(
                        window_days=normalized.window_days,
                        topic=normalized.topic,
                        failure_code="skill_error",
                        searched_at=utc_text(now),
                    )
                result_box["result"] = result
                if result["status"] in {"succeeded", "partial"}:
                    ttl = (
                        self.config.cache_ttl_seconds
                        if result["status"] == "succeeded"
                        else min(60, self.config.cache_ttl_seconds)
                    )
                    with self._cache_lock:
                        self._cache[cache_key] = (
                            now + timedelta(seconds=ttl),
                            copy.deepcopy(result),
                        )
            finally:
                self._concurrency.release()
                completed.set()

        worker = threading.Thread(
            target=retrieve_in_background,
            name="coal-news-search",
            daemon=True,
        )
        try:
            worker.start()
        except RuntimeError:
            self._concurrency.release()
            result = self._failure(
                window_days=normalized.window_days,
                topic=normalized.topic,
                failure_code="worker_unavailable",
                searched_at=utc_text(now),
                status="unavailable",
            )
            self._record_runtime(result)
            return result
        if not completed.wait(self.config.timeout_seconds + _SCHEDULING_GRACE_SECONDS):
            result = self._failure(
                window_days=normalized.window_days,
                topic=normalized.topic,
                failure_code="network_timeout",
                searched_at=utc_text(now),
            )
            self._record_runtime(result)
            return result
        result = result_box["result"]
        self._record_runtime(result)
        return result

    def _aware_now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime):
            raise ValueError("技能时钟必须返回 datetime")
        if value.tzinfo is None:
            raise ValueError("技能时钟必须带时区")
        return value.astimezone(UTC)

    def _record_runtime(self, result: Mapping[str, Any]) -> None:
        status = result.get("status")
        runtime = (
            "reachable"
            if status == "succeeded"
            else "degraded"
            if status == "partial"
            else "disabled"
            if result.get("failure_code") == "disabled"
            else "unreachable"
        )
        with self._runtime_lock:
            self._runtime_status = runtime
            self._last_checked_at = (
                result.get("searched_at")
                if isinstance(result.get("searched_at"), str)
                else utc_text()
            )
            self._last_provider = (
                result.get("provider")
                if isinstance(result.get("provider"), str)
                else None
            )

    def _failure(
        self,
        *,
        window_days: int,
        topic: str | None = None,
        failure_code: str,
        searched_at: str | None = None,
        status: str = "failed",
        attempts: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        result = {
            "status": status,
            "searched_at": searched_at or utc_text(self._aware_now()),
            "window_days": window_days,
            "result_count": 0,
            "provider": _MULTI_PROVIDER,
            "providers": self._configured_providers(),
            "provider_attempts": attempts or [],
            "fallback_used": bool(attempts and len(attempts) > 1),
            "cached": False,
            "failure_code": failure_code,
            "sources": [],
        }
        if topic is not None:
            result["topic"] = topic
        return result

    def _provider_failure(
        self,
        provider: str,
        failure_code: str,
        *,
        status: str = "failed",
    ) -> dict[str, Any]:
        return {
            "provider": provider,
            "status": status,
            "failure_code": failure_code,
            "result_count": 0,
            "sources": [],
        }

    def _run_provider(
        self,
        provider: str,
        operation: Callable[[float], dict[str, Any]],
        timeout_seconds: float,
    ) -> dict[str, Any]:
        started = self._monotonic()
        slot = self._provider_concurrency[provider]
        if not slot.acquire(blocking=False):
            result = self._provider_failure(provider, "busy", status="unavailable")
            result["elapsed_ms"] = 0
            return result
        completed = threading.Event()
        box: dict[str, dict[str, Any]] = {}

        def run() -> None:
            try:
                try:
                    box["result"] = operation(timeout_seconds)
                except Exception:
                    box["result"] = self._provider_failure(provider, "provider_error")
            finally:
                slot.release()
                completed.set()

        worker = threading.Thread(
            target=run,
            name=f"coal-news-{provider}",
            daemon=True,
        )
        try:
            worker.start()
        except RuntimeError:
            slot.release()
            result = self._provider_failure(
                provider, "worker_unavailable", status="unavailable"
            )
            result["elapsed_ms"] = 0
            return result
        if not completed.wait(timeout_seconds + _PROVIDER_SCHEDULING_GRACE_SECONDS):
            result = self._provider_failure(provider, "network_timeout")
        else:
            result = box["result"]
        result["elapsed_ms"] = max(0, int((self._monotonic() - started) * 1_000))
        return result

    def _retrieve(
        self, normalized: NormalizedNewsRequest, *, now: datetime
    ) -> dict[str, Any]:
        searched_at = utc_text(now)
        providers = self._configured_providers()
        if not providers:
            return self._failure(
                window_days=normalized.window_days,
                topic=normalized.topic,
                failure_code="no_provider_configured",
                searched_at=searched_at,
                status="unavailable",
            )
        deadline = self._monotonic() + self.config.timeout_seconds - 0.1
        attempts: list[dict[str, Any]] = []
        gathered: list[dict[str, Any]] = []

        for provider in providers[:_MAX_PROVIDER_ATTEMPTS]:
            remaining = deadline - self._monotonic()
            if remaining < 0.25:
                attempts.append(
                    {
                        "provider": provider,
                        "status": "failed",
                        "failure_code": "deadline_exhausted",
                        "result_count": 0,
                        "elapsed_ms": 0,
                    }
                )
                break
            if provider == _BAIDU_PROVIDER:
                timeout = min(self.config.baidu_timeout_seconds, remaining)

                def operation(selected_timeout: float) -> dict[str, Any]:
                    return self._retrieve_baidu(
                        normalized,
                        now=now,
                        timeout_seconds=selected_timeout,
                    )

            elif provider == _DEEPSEEK_PROVIDER:
                timeout = min(self.config.deepseek_timeout_seconds, remaining)

                def operation(selected_timeout: float) -> dict[str, Any]:
                    return self._retrieve_deepseek(
                        normalized,
                        now=now,
                        timeout_seconds=selected_timeout,
                    )

            else:
                timeout = min(5.0, remaining)

                def operation(selected_timeout: float) -> dict[str, Any]:
                    return self._retrieve_bing(
                        normalized,
                        now=now,
                        timeout_seconds=selected_timeout,
                    )

            attempt = self._run_provider(provider, operation, max(0.1, timeout))
            sources = attempt.pop("sources", [])
            attempts.append(attempt)
            if isinstance(sources, list):
                gathered.extend(
                    source for source in sources if isinstance(source, dict)
                )
            if gathered:
                break

        sources = self._merge_sources(gathered)[: self.config.max_results]
        if not sources:
            codes = [
                str(attempt.get("failure_code"))
                for attempt in attempts
                if attempt.get("failure_code")
            ]
            if len(attempts) == 1 and codes:
                failure_code = codes[0]
            elif attempts and codes and all(code == "no_results" for code in codes):
                failure_code = "no_results"
            elif "network_timeout" in codes or "deadline_exhausted" in codes:
                failure_code = "network_timeout"
            elif codes and all(
                code in {"network_unavailable", "network_timeout"} for code in codes
            ):
                failure_code = "network_unavailable"
            else:
                failure_code = "providers_exhausted"
            return self._failure(
                window_days=normalized.window_days,
                topic=normalized.topic,
                failure_code=failure_code,
                searched_at=searched_at,
                attempts=attempts,
            )

        provider_names = list(
            dict.fromkeys(
                str(source["retrieval_provider"])
                for source in sources
                if source.get("retrieval_provider")
            )
        )
        material_failures = [
            attempt
            for attempt in attempts
            if attempt.get("status") == "partial"
            or attempt.get("failure_code") not in {None, "no_results"}
        ]
        unknown_dates = any(not source.get("published_at") for source in sources)
        status = "partial" if material_failures or unknown_dates else "succeeded"
        partial_reasons: list[str] = []
        if material_failures:
            partial_reasons.append("provider_failure")
        if unknown_dates:
            partial_reasons.append("published_time_unverified")
        return {
            "status": status,
            "searched_at": searched_at,
            "topic": normalized.topic,
            "window_days": normalized.window_days,
            "result_count": len(sources),
            "provider": (
                provider_names[0] if len(provider_names) == 1 else _MULTI_PROVIDER
            ),
            "providers": providers,
            "provider_attempts": attempts,
            "fallback_used": len(attempts) > 1,
            "partial_reasons": partial_reasons,
            "cached": False,
            "failure_code": ("partial_results" if status == "partial" else None),
            "sources": sources,
        }

    def _merge_sources(self, candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
        selected: list[dict[str, Any]] = []
        seen_urls: set[str] = set()
        seen_titles: set[str] = set()
        for source in candidates:
            url_key, title_key = _source_key(source)
            if not url_key or not title_key:
                continue
            if url_key in seen_urls or title_key in seen_titles:
                continue
            seen_urls.add(url_key)
            seen_titles.add(title_key)
            selected.append(source)
        selected.sort(
            key=lambda item: (
                bool(item.get("published_at")),
                str(item.get("published_at") or ""),
                str(item.get("title") or ""),
            ),
            reverse=True,
        )
        return selected

    def _fetch(
        self,
        request: urllib.request.Request,
        *,
        provider: str,
        timeout_seconds: float,
    ) -> tuple[bytes | None, str | None, str | None, str | None]:
        response: Any = None
        try:
            response = self._opener(request, timeout_seconds)
            final_url = (
                response.geturl()
                if callable(getattr(response, "geturl", None))
                else request.full_url
            )
            if not _expected_final_url(provider, request.full_url, final_url):
                final_host = (urlsplit(final_url).hostname or "").casefold()
                code = (
                    "challenge_required"
                    if provider == _BAIDU_PROVIDER and final_host == "wappass.baidu.com"
                    else "unsafe_response_url"
                )
                return None, None, None, code
            media_type, charset = _content_type(response)
            raw = response.read(self.config.max_response_bytes + 1)
            if len(raw) > self.config.max_response_bytes:
                return None, media_type, charset, "response_too_large"
            return raw, media_type, charset, None
        except urllib.error.HTTPError as error:
            location = (
                error.headers.get("Location") if error.headers is not None else None
            )
            location_host = (
                (urlsplit(location).hostname or "").casefold()
                if isinstance(location, str)
                else ""
            )
            if provider == _BAIDU_PROVIDER and location_host == "wappass.baidu.com":
                code = "challenge_required"
            elif error.code == 401:
                code = "authentication_failed"
            elif error.code == 403:
                code = "upstream_blocked"
            elif error.code == 429:
                code = "rate_limited"
            elif 500 <= error.code <= 599:
                code = "upstream_unavailable"
            elif 300 <= error.code <= 399:
                code = "unsafe_redirect"
            else:
                code = "upstream_http_error"
            return None, None, None, code
        except TimeoutError:
            return None, None, None, "network_timeout"
        except urllib.error.URLError as error:
            reason = getattr(error, "reason", None)
            code = (
                "network_timeout"
                if isinstance(reason, TimeoutError)
                else "network_unavailable"
            )
            return None, None, None, code
        except OSError:
            return None, None, None, "network_unavailable"
        finally:
            close = getattr(response, "close", None)
            if callable(close):
                close()

    def _retrieve_baidu(
        self,
        normalized: NormalizedNewsRequest,
        *,
        now: datetime,
        timeout_seconds: float,
    ) -> dict[str, Any]:
        request = urllib.request.Request(
            _baidu_url(normalized),
            headers={
                "Accept": "text/html,application/xhtml+xml;q=0.9",
                "Accept-Encoding": "identity",
                "Accept-Language": "zh-CN,zh;q=0.9",
                "User-Agent": (
                    "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 "
                    "Chrome/120 Mobile Safari/537.36"
                ),
            },
            method="GET",
        )
        raw, media_type, charset, failure = self._fetch(
            request,
            provider=_BAIDU_PROVIDER,
            timeout_seconds=timeout_seconds,
        )
        if failure is not None:
            return self._provider_failure(_BAIDU_PROVIDER, failure)
        assert raw is not None
        if media_type is not None and media_type != "text/html":
            return self._provider_failure(_BAIDU_PROVIDER, "invalid_content_type")
        selected_charset = (charset or "utf-8").replace("_", "-")
        if selected_charset not in {"utf-8", "utf8"}:
            return self._provider_failure(_BAIDU_PROVIDER, "invalid_content_encoding")
        try:
            text = raw.decode("utf-8", "strict")
        except UnicodeDecodeError:
            return self._provider_failure(_BAIDU_PROVIDER, "invalid_content_encoding")
        lowered = text.casefold()
        if (
            "百度安全验证" in text
            or "wappass.baidu.com" in lowered
            or "tuxing_v2" in lowered
        ):
            return self._provider_failure(_BAIDU_PROVIDER, "challenge_required")
        parser = _BaiduSDataParser()
        try:
            parser.feed(text)
            parser.close()
        except Exception:
            return self._provider_failure(_BAIDU_PROVIDER, "invalid_search_page")
        cutoff = now - timedelta(days=normalized.window_days)
        searched_at = utc_text(now)
        sources: list[dict[str, Any]] = []
        rejected_invalid = False
        for payload in parser.payloads:
            try:
                item = json.loads(payload)
            except (json.JSONDecodeError, RecursionError):
                rejected_invalid = True
                continue
            if not isinstance(item, dict) or not {
                "title",
                "titleUrl",
                "dispTime",
                "sourceName",
            }.issubset(item):
                continue
            title = _normal_text(
                item.get("title"),
                maximum=_MAX_TITLE_CHARS,
                strip_markup=True,
            )
            url = _canonical_public_url(item.get("titleUrl"))
            publisher = _normal_text(
                item.get("sourceName"),
                maximum=_MAX_PUBLISHER_CHARS,
                strip_markup=True,
            )
            search_snippet = _normal_text(
                item.get("summary"),
                maximum=_MAX_SEARCH_SNIPPET_CHARS,
                strip_markup=True,
            )
            published, estimated = _parse_baidu_time(item.get("dispTime"), now=now)
            time_text = _normal_text(item.get("dispTime"), maximum=64)
            if title is None or url is None or publisher is None or published is None:
                rejected_invalid = True
                continue
            if published > now + timedelta(minutes=5) or published < cutoff:
                continue
            if not any(term in title.casefold() for term in _COAL_RELEVANCE):
                continue
            sources.append(
                {
                    "title": title,
                    "publisher": publisher,
                    "url": url,
                    "search_snippet": search_snippet,
                    "snippet_origin": (
                        "baidu_search_result" if search_snippet is not None else None
                    ),
                    "snippet_truncated": bool(
                        search_snippet
                        and search_snippet.rstrip().endswith(("...", "…"))
                    ),
                    "published_at": utc_text(published),
                    "published_time_text": time_text,
                    "published_at_estimated": estimated,
                    "date_confidence": "relative_time",
                    "retrieved_at": searched_at,
                    "retrieval_provider": _BAIDU_PROVIDER,
                }
            )
        if not sources:
            code = "invalid_search_page" if not parser.payloads else "no_results"
            return self._provider_failure(_BAIDU_PROVIDER, code)
        return {
            "provider": _BAIDU_PROVIDER,
            "status": "partial" if rejected_invalid else "succeeded",
            "failure_code": None,
            "result_count": len(sources),
            "sources": sources,
        }

    def _retrieve_deepseek(
        self,
        normalized: NormalizedNewsRequest,
        *,
        now: datetime,
        timeout_seconds: float,
    ) -> dict[str, Any]:
        if self.llm_config is None:
            return self._provider_failure(
                _DEEPSEEK_PROVIDER,
                "not_configured",
                status="unavailable",
            )
        # A managed credential is re-verified immediately before every
        # authenticated request.  Rotation requires a service restart and a
        # tampered/expired lock therefore fails before the API key can leave
        # the process.  Public Baidu/Bing retrieval does not use this guard.
        if self._configuration_guard is not None:
            self._configuration_guard()
        start = (now - timedelta(days=normalized.window_days)).date().isoformat()
        end = now.date().isoformat()
        prompt = (
            f"搜索 {start} 至 {end} 的中国{normalized.topic}行业新闻。"
            "优先政府、行业协会和可信行业媒体，只搜索，不使用模型记忆；"
            "结果必须来自这个日期窗口。"
        )
        body = {
            "model": self.llm_config.model,
            "max_tokens": 700,
            "temperature": 0,
            "thinking": {"type": "disabled"},
            "output_config": {"effort": "low"},
            "tools": [
                {
                    "type": "web_search_20250305",
                    "name": "web_search",
                    "max_uses": 2,
                }
            ],
            "messages": [{"role": "user", "content": prompt}],
        }
        request = urllib.request.Request(
            _deepseek_url(self.llm_config),
            data=json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode(),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "EnterpriseCoalAgent/0.2",
                "anthropic-version": "2023-06-01",
                "x-api-key": self.llm_config.api_key,
            },
            method="POST",
        )
        raw, media_type, _charset, failure = self._fetch(
            request,
            provider=_DEEPSEEK_PROVIDER,
            timeout_seconds=timeout_seconds,
        )
        if failure is not None:
            return self._provider_failure(_DEEPSEEK_PROVIDER, failure)
        assert raw is not None
        if media_type is not None and media_type not in {
            "application/json",
            "application/problem+json",
        }:
            return self._provider_failure(_DEEPSEEK_PROVIDER, "invalid_content_type")
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            return self._provider_failure(
                _DEEPSEEK_PROVIDER, "invalid_provider_response"
            )
        content = payload.get("content") if isinstance(payload, dict) else None
        if not isinstance(content, list):
            return self._provider_failure(
                _DEEPSEEK_PROVIDER, "invalid_provider_response"
            )
        results: list[dict[str, Any]] = []
        result_error = False
        for block in content[:100]:
            if not isinstance(block, dict):
                continue
            if block.get("type") != "web_search_tool_result":
                continue
            block_content = block.get("content")
            if isinstance(block_content, dict):
                result_error = True
                continue
            if not isinstance(block_content, list):
                continue
            results.extend(
                item
                for item in block_content[:100]
                if isinstance(item, dict) and item.get("type") == "web_search_result"
            )
        cutoff = now - timedelta(days=normalized.window_days)
        searched_at = utc_text(now)
        sources: list[dict[str, Any]] = []
        rejected_invalid = False
        for item in results[:100]:
            title = _normal_text(
                item.get("title"),
                maximum=_MAX_TITLE_CHARS,
                strip_markup=True,
            )
            url = _canonical_public_url(item.get("url"))
            search_snippet = _normal_text(
                item.get("snippet") or item.get("description"),
                maximum=_MAX_SEARCH_SNIPPET_CHARS,
                strip_markup=True,
            )
            if title is None or url is None:
                rejected_invalid = True
                continue
            if not any(term in title.casefold() for term in _COAL_RELEVANCE):
                continue
            published, date_confidence, time_text = _parse_search_result_date(
                item.get("page_age"),
                title,
                now=now,
            )
            if published is not None and (
                published > now + timedelta(days=1) or published < cutoff
            ):
                continue
            sources.append(
                {
                    "title": title,
                    "publisher": _publisher_from_url(url),
                    "url": url,
                    "search_snippet": search_snippet,
                    "snippet_origin": (
                        "deepseek_web_search_result"
                        if search_snippet is not None
                        else None
                    ),
                    "snippet_truncated": False,
                    "published_at": (
                        utc_text(published) if published is not None else None
                    ),
                    "published_time_text": time_text,
                    "published_at_estimated": date_confidence == "title",
                    "date_confidence": date_confidence,
                    "retrieved_at": searched_at,
                    "retrieval_provider": _DEEPSEEK_PROVIDER,
                }
            )
        if not sources:
            return self._provider_failure(
                _DEEPSEEK_PROVIDER,
                "provider_search_error" if result_error else "no_results",
            )
        return {
            "provider": _DEEPSEEK_PROVIDER,
            "status": "partial" if rejected_invalid else "succeeded",
            "failure_code": None,
            "result_count": len(sources),
            "sources": sources,
        }

    def _retrieve_bing(
        self,
        normalized: NormalizedNewsRequest,
        *,
        now: datetime,
        timeout_seconds: float,
    ) -> dict[str, Any]:
        request = urllib.request.Request(
            _bing_url(normalized),
            headers={
                "Accept": "application/rss+xml, application/xml;q=0.9",
                "Accept-Encoding": "identity",
                "User-Agent": "EnterpriseCoalAgent/0.2",
            },
            method="GET",
        )
        raw, media_type, charset, failure = self._fetch(
            request,
            provider=_BING_PROVIDER,
            timeout_seconds=timeout_seconds,
        )
        if failure is not None:
            return self._provider_failure(_BING_PROVIDER, failure)
        assert raw is not None
        if media_type is not None and media_type not in {
            "application/rss+xml",
            "application/xml",
            "text/xml",
        }:
            return self._provider_failure(_BING_PROVIDER, "invalid_content_type")
        if _DISALLOWED_XML.search(raw):
            return self._provider_failure(_BING_PROVIDER, "unsafe_xml")
        decoded = _decode_xml(raw, header_charset=charset)
        if decoded is None:
            return self._provider_failure(_BING_PROVIDER, "invalid_feed_encoding")
        try:
            root = ET.fromstring(decoded)
        except (ET.ParseError, ValueError):
            return self._provider_failure(_BING_PROVIDER, "invalid_feed")
        if root.tag.rsplit("}", 1)[-1].casefold() != "rss":
            return self._provider_failure(_BING_PROVIDER, "invalid_feed_structure")
        cutoff = now - timedelta(days=normalized.window_days)
        searched_at = utc_text(now)
        sources: list[dict[str, Any]] = []
        rejected_invalid = False
        items = [
            element
            for element in root.iter()
            if element.tag.rsplit("}", 1)[-1].casefold() == "item"
        ]
        for item in items:
            title = _normal_text(_child_text(item, "title"), maximum=_MAX_TITLE_CHARS)
            url = _safe_bing_article_url(_child_text(item, "link"))
            published = _published_at(_child_text(item, "pubDate"))
            publisher = _normal_text(
                _child_text(item, "source"),
                maximum=_MAX_PUBLISHER_CHARS,
            )
            search_snippet = _normal_text(
                _child_text(item, "description"),
                maximum=_MAX_SEARCH_SNIPPET_CHARS,
                strip_markup=True,
            )
            if publisher is None and url is not None:
                publisher = _publisher_from_url(url)
            if title is None or publisher is None or url is None or published is None:
                rejected_invalid = True
                continue
            if published > now or published < cutoff:
                continue
            if not any(
                term in f"{title} {publisher}".casefold() for term in _COAL_RELEVANCE
            ):
                continue
            sources.append(
                {
                    "title": title,
                    "publisher": publisher,
                    "url": url,
                    "search_snippet": search_snippet,
                    "snippet_origin": (
                        "bing_rss_description"
                        if search_snippet is not None
                        else None
                    ),
                    "snippet_truncated": False,
                    "published_at": utc_text(published),
                    "published_time_text": None,
                    "published_at_estimated": False,
                    "date_confidence": "provider",
                    "retrieved_at": searched_at,
                    "retrieval_provider": _BING_PROVIDER,
                }
            )
        if not sources:
            return self._provider_failure(_BING_PROVIDER, "no_results")
        return {
            "provider": _BING_PROVIDER,
            "status": "partial" if rejected_invalid else "succeeded",
            "failure_code": None,
            "result_count": len(sources),
            "sources": sources,
        }
