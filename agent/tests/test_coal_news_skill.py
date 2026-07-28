from __future__ import annotations

import http.client
import json
import threading
import time
import urllib.error
from datetime import UTC, datetime, timedelta
from io import BytesIO
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from enterprise_agent.chat import coal_news_search_decision
from enterprise_agent.http_api import EnterpriseAgentHTTPServer
from enterprise_agent.llm import LLMConfig
from enterprise_agent.service import EnterpriseAgentService
from enterprise_agent.skills import (
    CoalNewsConfig,
    CoalNewsSearchSkill,
    SkillRegistry,
)
from enterprise_agent.storage import Repository

NOW = datetime(2026, 7, 28, 9, 0, tzinfo=UTC)


def _rfc(value: datetime) -> str:
    return value.strftime("%a, %d %b %Y %H:%M:%S +0000")


def _feed(*items: str) -> bytes:
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        "<rss><channel>" + "".join(items) + "</channel></rss>"
    ).encode()


def _item(
    *,
    title: str = "全国煤炭市场供需保持稳定",
    link: str = "https://news.example.com/coal/1",
    publisher: str = "能源日报",
    published: datetime = NOW - timedelta(hours=2),
) -> str:
    escaped_link = link.replace("&", "&amp;")
    return (
        "<item>"
        f"<title>{title}</title>"
        f"<link>{escaped_link}</link>"
        f"<source>{publisher}</source>"
        f"<pubDate>{_rfc(published)}</pubDate>"
        "</item>"
    )


class Response(BytesIO):
    pass


class NetworkResponse(Response):
    def __init__(
        self,
        payload: bytes,
        *,
        final_url: str,
        content_type: str,
    ) -> None:
        super().__init__(payload)
        self._final_url = final_url
        self.headers = {"Content-Type": content_type}

    def geturl(self) -> str:
        return self._final_url


def _registry(skill: CoalNewsSearchSkill) -> SkillRegistry:
    registry = SkillRegistry()
    registry.register(skill)
    return registry


def _bing_config(**overrides: Any) -> CoalNewsConfig:
    values: dict[str, Any] = {
        "baidu_enabled": False,
        "deepseek_web_search_enabled": False,
        "bing_fallback_enabled": True,
    }
    values.update(overrides)
    return CoalNewsConfig(**values)


def _bing_skill(
    *,
    opener: Any,
    clock: Any = lambda: NOW,
    config: CoalNewsConfig | None = None,
) -> CoalNewsSearchSkill:
    return CoalNewsSearchSkill(
        config or _bing_config(),
        opener=opener,
        clock=clock,
    )


def _baidu_page(*items: dict[str, Any]) -> bytes:
    comments = "".join(
        "<!--s-data:" + json.dumps(item, ensure_ascii=False) + "-->" for item in items
    )
    return (
        "<!doctype html><html><head><title>百度新闻</title></head>"
        f"<body>{comments}</body></html>"
    ).encode()


def _deepseek_payload(*items: dict[str, Any]) -> bytes:
    return json.dumps(
        {
            "content": [
                {"type": "server_tool_use", "name": "web_search"},
                {
                    "type": "web_search_tool_result",
                    "content": [
                        {"type": "web_search_result", **item} for item in items
                    ],
                },
                {"type": "text", "text": "ignored model summary"},
            ]
        },
        ensure_ascii=False,
    ).encode()


def _llm_config(*, timeout_seconds: float = 3.0) -> LLMConfig:
    return LLMConfig(
        api_key="test-secret",
        base_url="https://api.deepseek.com",
        model="deepseek-v4-flash",
        timeout_seconds=timeout_seconds,
        max_retries=0,
    )


def test_skill_normalizes_query_parses_dates_redirect_and_deduplicates() -> None:
    requested: list[tuple[str, float]] = []
    original = "https://news.example.com/coal/redirected?id=1"
    redirected = (
        "https://www.bing.com/news/apiclick.aspx?url="
        "https%3A%2F%2Fnews.example.com%2Fcoal%2Fredirected%3Fid%3D1"
    )
    payload = _feed(
        _item(link=redirected),
        _item(link=original),
        _item(
            title="未来煤炭报道",
            link="https://news.example.com/future",
            published=NOW + timedelta(minutes=1),
        ),
        _item(
            title="过期煤炭报道",
            link="https://news.example.com/old",
            published=NOW - timedelta(days=8),
        ),
        _item(
            title="足球比赛消息",
            link="https://sports.example.com/1",
        ),
    )

    def opener(request: Any, timeout: float) -> Response:
        requested.append((request.full_url, timeout))
        return Response(payload)

    skill = _bing_skill(opener=opener)
    result = skill.invoke(
        {"question": ("请看最近煤炭新闻；机密企业=不要发送；https://127.0.0.1/admin")}
    )

    assert result["status"] == "succeeded"
    assert result["window_days"] == 7
    assert result["result_count"] == 1
    assert result["sources"][0]["url"] == original
    assert result["sources"][0]["published_at"] == "2026-07-28T07:00:00Z"
    assert result["sources"][0]["retrieved_at"] == "2026-07-28T09:00:00Z"
    outbound, timeout = requested[0]
    parsed = urlsplit(outbound)
    assert (parsed.scheme, parsed.hostname, parsed.path) == (
        "https",
        "www.bing.com",
        "/news/search",
    )
    query = parse_qs(parsed.query)
    assert query["q"] == ["煤炭 when:7d"]
    assert query["format"] == ["rss"]
    assert timeout == 5.0
    assert "机密企业" not in outbound
    assert "127.0.0.1" not in outbound


def test_skill_filters_unsafe_and_malformed_items_as_partial() -> None:
    payload = _feed(
        _item(),
        _item(
            title="煤炭内网消息",
            link="https://127.0.0.1/private",
        ),
        _item(
            title="煤炭凭据链接",
            link="https://user:password@news.example.com/private",
        ),
        (
            "<item><title>煤炭日期损坏</title>"
            "<link>https://news.example.com/bad-date</link>"
            "<source>能源日报</source><pubDate>not-a-date</pubDate></item>"
        ),
    )
    skill = _bing_skill(
        opener=lambda _request, _timeout: Response(payload),
    )

    result = skill.invoke({"question": "过去24小时煤炭资讯"})

    assert result["status"] == "partial"
    assert result["window_days"] == 1
    assert result["result_count"] == 1
    serialized = json.dumps(result, ensure_ascii=False)
    assert "127.0.0.1" not in serialized
    assert "password" not in serialized


@pytest.mark.parametrize(
    ("failure", "failure_code"),
    [
        (TimeoutError(), "network_timeout"),
        (urllib.error.URLError("dns failed"), "network_unavailable"),
    ],
)
def test_skill_network_failures_are_safe(failure: Exception, failure_code: str) -> None:
    def opener(_request: Any, _timeout: float) -> Response:
        raise failure

    result = _bing_skill(opener=opener).invoke({"question": "最近30天煤炭新闻"})

    assert result["status"] == "failed"
    assert result["searched_at"] == "2026-07-28T09:00:00Z"
    assert result["window_days"] == 30
    assert result["result_count"] == 0
    assert result["provider"] == "multi-provider"
    assert result["failure_code"] == failure_code
    assert result["sources"] == []
    assert result["provider_attempts"][0]["provider"] == "bing-news-rss"
    assert result["provider_attempts"][0]["failure_code"] == failure_code


def test_skill_rejects_unsafe_xml_and_oversized_response() -> None:
    unsafe = b'<!DOCTYPE rss [<!ENTITY x "coal">]><rss>&x;</rss>'
    unsafe_result = _bing_skill(
        opener=lambda _request, _timeout: Response(unsafe),
    ).invoke({"question": "煤炭新闻"})
    assert unsafe_result["status"] == "failed"
    assert unsafe_result["failure_code"] == "unsafe_xml"

    oversized = b"x" * (64 * 1024 + 1)
    too_large = _bing_skill(
        config=_bing_config(max_response_bytes=64 * 1024),
        opener=lambda _request, _timeout: Response(oversized),
    ).invoke({"question": "煤炭新闻"})
    assert too_large["failure_code"] == "response_too_large"


def test_skill_requires_a_source_for_succeeded_and_reports_no_results() -> None:
    skill = _bing_skill(
        opener=lambda _request, _timeout: Response(_feed()),
    )

    result = skill.invoke({"question": "最近煤炭新闻"})

    assert result["status"] == "failed"
    assert result["failure_code"] == "no_results"
    assert result["result_count"] == 0
    assert result["sources"] == []


@pytest.mark.parametrize(
    ("final_url", "content_type", "failure_code"),
    [
        (
            "https://127.0.0.1/news/search?format=rss",
            "application/rss+xml",
            "unsafe_response_url",
        ),
        (
            "https://www.bing.com/news/search?format=rss",
            "text/html; charset=utf-8",
            "invalid_content_type",
        ),
    ],
)
def test_skill_validates_real_response_url_and_content_type(
    final_url: str,
    content_type: str,
    failure_code: str,
) -> None:
    skill = _bing_skill(
        opener=lambda _request, _timeout: NetworkResponse(
            _feed(_item()),
            final_url=final_url,
            content_type=content_type,
        ),
    )

    result = skill.invoke({"question": "煤炭新闻"})

    assert result["status"] == "failed"
    assert result["failure_code"] == failure_code
    assert result["sources"] == []


def test_skill_cache_and_concurrency_limit() -> None:
    calls = 0

    def cached_opener(_request: Any, _timeout: float) -> Response:
        nonlocal calls
        calls += 1
        return Response(_feed(_item()))

    skill = _bing_skill(
        opener=cached_opener,
    )
    first = skill.invoke({"question": "最近煤炭新闻"})
    second = skill.invoke({"question": "煤炭新闻近7天"})
    assert first["cached"] is False
    assert second["cached"] is True
    assert calls == 1

    entered = threading.Event()
    release = threading.Event()

    def blocking_opener(_request: Any, _timeout: float) -> Response:
        entered.set()
        assert release.wait(timeout=2)
        return Response(_feed(_item()))

    limited = _bing_skill(
        config=_bing_config(max_concurrency=1),
        opener=blocking_opener,
    )
    completed: list[dict[str, Any]] = []
    worker = threading.Thread(
        target=lambda: completed.append(limited.invoke({"question": "煤炭新闻"}))
    )
    worker.start()
    assert entered.wait(timeout=1)
    busy = limited.invoke({"question": "煤炭新闻"})
    assert busy["status"] == "unavailable"
    assert busy["failure_code"] == "busy"
    release.set()
    worker.join(timeout=2)
    assert completed[0]["status"] == "succeeded"


def test_skill_enforces_wall_clock_deadline_and_bounds_daemon_workers() -> None:
    release = threading.Event()
    two_entered = threading.Event()
    all_exited = threading.Event()
    state_lock = threading.Lock()
    active = 0
    maximum_active = 0
    daemon_flags: list[bool] = []

    def blocking_opener(_request: Any, _timeout: float) -> Response:
        nonlocal active, maximum_active
        with state_lock:
            active += 1
            maximum_active = max(maximum_active, active)
            daemon_flags.append(threading.current_thread().daemon)
            if active == 2:
                two_entered.set()
        release.wait()
        with state_lock:
            active -= 1
            if active == 0:
                all_exited.set()
        return Response(_feed(_item()))

    skill = _bing_skill(
        config=_bing_config(timeout_seconds=1.0, max_concurrency=2),
        opener=blocking_opener,
    )
    completed: list[tuple[dict[str, Any], float]] = []

    def call() -> None:
        started = time.monotonic()
        result = skill.invoke({"question": "煤炭新闻"})
        completed.append((result, time.monotonic() - started))

    callers = [threading.Thread(target=call) for _ in range(2)]
    try:
        for caller in callers:
            caller.start()
        assert two_entered.wait(timeout=0.5)

        busy_started = time.monotonic()
        busy = skill.invoke({"question": "煤炭新闻"})
        busy_elapsed = time.monotonic() - busy_started
        assert busy["status"] == "unavailable"
        assert busy["failure_code"] == "busy"
        assert busy_elapsed < 0.25

        for caller in callers:
            caller.join(timeout=1.4)
            assert not caller.is_alive()
        assert len(completed) == 2
        assert all(
            result["status"] == "failed" and result["failure_code"] == "network_timeout"
            for result, _elapsed in completed
        )
        assert all(elapsed < 1.3 for _result, elapsed in completed)

        # Timed-out operations still own both slots until their actual
        # blocking network calls finish.
        still_busy = skill.invoke({"question": "煤炭新闻"})
        assert still_busy["failure_code"] == "busy"
        assert maximum_active == 2
        assert daemon_flags == [True, True]
    finally:
        release.set()
        for caller in callers:
            caller.join(timeout=2)

    assert all_exited.wait(timeout=1)
    # A late, valid result may be safely cached, but cannot revise either
    # network_timeout result already returned to the callers.
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline:
        late = skill.invoke({"question": "煤炭新闻"})
        if late["status"] == "succeeded":
            break
        time.sleep(0.01)
    assert late["status"] == "succeeded"
    assert all(
        result["failure_code"] == "network_timeout" for result, _elapsed in completed
    )


def test_baidu_primary_parses_s_data_and_short_circuits_fallback() -> None:
    requested: list[str] = []
    page = _baidu_page(
        {
            "title": "唤醒40%“沉睡”<em>煤炭</em>资源",
            "titleUrl": "https://www.stdaily.com/web/gdxw/2026-07/22/content.html",
            "dispTime": "6天前",
            "sourceName": "中国科技网",
            "summary": (
                "项目通过<em>煤炭</em>绿色智能开发技术，"
                "提高呆滞资源利用水平..."
            ),
        }
    )

    def opener(request: Any, _timeout: float) -> NetworkResponse:
        requested.append(request.full_url)
        return NetworkResponse(
            page,
            final_url=request.full_url,
            content_type="text/html;charset=utf-8",
        )

    skill = CoalNewsSearchSkill(
        CoalNewsConfig(
            timeout_seconds=4,
            baidu_timeout_seconds=1,
            max_results=1,
        ),
        llm_config=_llm_config(),
        opener=opener,
        clock=lambda: NOW,
    )

    result = skill.invoke({"question": "最近煤炭新闻；绝密一号矿不得出站"})

    assert result["status"] == "succeeded"
    assert result["provider"] == "baidu-news-search"
    assert len(requested) == 1
    outbound = requested[0]
    parsed = urlsplit(outbound)
    assert (parsed.scheme, parsed.hostname, parsed.path) == (
        "https",
        "www.baidu.com",
        "/s",
    )
    assert parse_qs(parsed.query)["word"] == ["煤炭"]
    assert "绝密" not in outbound
    source = result["sources"][0]
    assert source["title"] == "唤醒40%“沉睡”煤炭资源"
    assert source["publisher"] == "中国科技网"
    assert source["search_snippet"] == (
        "项目通过煤炭绿色智能开发技术,提高呆滞资源利用水平..."
    )
    assert source["snippet_origin"] == "baidu_search_result"
    assert source["snippet_truncated"] is True
    assert source["published_at"] == "2026-07-22T09:00:00Z"
    assert source["published_at_estimated"] is True
    assert source["retrieval_provider"] == "baidu-news-search"


def test_baidu_challenge_falls_back_to_deepseek_web_search() -> None:
    request_bodies: list[str] = []
    deepseek = _deepseek_payload(
        {
            "title": "中国煤炭运销协会：7月中旬重点煤企产量更新",
            "url": "https://news.mysteel.com/a/26072717/example.html",
            "page_age": None,
            "encrypted_content": "must-not-be-stored",
        },
        {
            "title": "煤矿安全监管新规（2026年7月24日）",
            "url": "https://www.chinamine-safety.gov.cn/example.shtml",
            "page_age": None,
        },
    )

    def opener(request: Any, _timeout: float) -> NetworkResponse:
        if urlsplit(request.full_url).hostname == "www.baidu.com":
            return NetworkResponse(
                "百度安全验证".encode(),
                final_url=("https://wappass.baidu.com/static/captcha/tuxing_v2.html"),
                content_type="text/html;charset=utf-8",
            )
        request_bodies.append(request.data.decode())
        return NetworkResponse(
            deepseek,
            final_url=request.full_url,
            content_type="application/json",
        )

    skill = CoalNewsSearchSkill(
        CoalNewsConfig(timeout_seconds=5, baidu_timeout_seconds=1),
        llm_config=_llm_config(),
        opener=opener,
        clock=lambda: NOW,
    )

    result = skill.invoke({"question": "最近煤炭新闻；企业机密不要发送"})

    assert result["status"] == "partial"
    assert result["result_count"] == 2
    assert [attempt["provider"] for attempt in result["provider_attempts"]] == [
        "baidu-news-search",
        "deepseek-web-search",
    ]
    assert result["provider_attempts"][0]["failure_code"] == "challenge_required"
    assert result["provider_attempts"][1]["result_count"] == 2
    assert result["fallback_used"] is True
    assert len(request_bodies) == 1
    assert "企业机密" not in request_bodies[0]
    assert "must-not-be-stored" not in json.dumps(result, ensure_ascii=False)
    dated = next(
        source for source in result["sources"] if "安全监管" in source["title"]
    )
    assert dated["published_at"] == "2026-07-23T16:00:00Z"
    assert dated["date_confidence"] == "title"


def test_baidu_provider_timeout_does_not_block_deepseek_fallback() -> None:
    release = threading.Event()
    baidu_started = threading.Event()
    deepseek = _deepseek_payload(
        {
            "title": "2026年7月27日煤炭行业运行情况",
            "url": "https://www.cnenergynews.cn/article/coal",
            "page_age": None,
        }
    )

    def opener(request: Any, _timeout: float) -> NetworkResponse:
        if urlsplit(request.full_url).hostname == "www.baidu.com":
            baidu_started.set()
            release.wait()
            return NetworkResponse(
                _baidu_page(),
                final_url=request.full_url,
                content_type="text/html;charset=utf-8",
            )
        return NetworkResponse(
            deepseek,
            final_url=request.full_url,
            content_type="application/json",
        )

    skill = CoalNewsSearchSkill(
        CoalNewsConfig(
            timeout_seconds=2,
            baidu_timeout_seconds=0.2,
            max_concurrency=1,
        ),
        llm_config=_llm_config(timeout_seconds=1),
        opener=opener,
        clock=lambda: NOW,
    )
    started = time.monotonic()
    try:
        result = skill.invoke({"question": "最近煤炭新闻"})
    finally:
        release.set()

    assert baidu_started.is_set()
    assert time.monotonic() - started < 1.5
    assert result["status"] == "partial"
    assert result["result_count"] == 1
    assert result["provider_attempts"][0]["failure_code"] == "network_timeout"
    assert result["provider_attempts"][1]["provider"] == "deepseek-web-search"


def test_multi_provider_failure_is_diagnostic_and_does_not_leak_errors() -> None:
    def opener(request: Any, _timeout: float) -> NetworkResponse:
        if urlsplit(request.full_url).hostname == "www.baidu.com":
            return NetworkResponse(
                "百度安全验证".encode(),
                final_url=request.full_url,
                content_type="text/html;charset=utf-8",
            )
        raise urllib.error.URLError("private resolver detail")

    result = CoalNewsSearchSkill(
        CoalNewsConfig(timeout_seconds=4, baidu_timeout_seconds=1),
        llm_config=_llm_config(),
        opener=opener,
        clock=lambda: NOW,
    ).invoke({"question": "最近煤炭新闻"})

    assert result["status"] == "failed"
    assert result["failure_code"] == "providers_exhausted"
    assert [attempt["failure_code"] for attempt in result["provider_attempts"]] == [
        "challenge_required",
        "network_unavailable",
    ]
    assert "private resolver detail" not in json.dumps(result, ensure_ascii=False)


def test_bing_gb18030_feed_is_decoded_strictly() -> None:
    xml = (
        '<?xml version="1.0" encoding="gb2312"?>'
        "<rss><channel>" + _item(title="煤炭市场运行平稳") + "</channel></rss>"
    ).encode("gb18030")

    def opener(request: Any, _timeout: float) -> NetworkResponse:
        return NetworkResponse(
            xml,
            final_url=request.full_url,
            content_type="application/xml;charset=GBK",
        )

    result = _bing_skill(opener=opener).invoke({"question": "煤炭新闻"})

    assert result["status"] == "succeeded"
    assert result["sources"][0]["title"] == "煤炭市场运行平稳"


def test_registry_lists_and_calls_read_only_skill() -> None:
    skill = _bing_skill(
        opener=lambda _request, _timeout: Response(_feed(_item())),
    )
    registry = _registry(skill)
    definitions = registry.list_public()
    assert definitions[0]["name"] == "coal-news-search"
    assert definitions[0]["accepts_user_url"] is False
    assert definitions[0]["read_only"] is True
    assert definitions[0]["ai_summary_grounding"] == "search_title_and_snippet"
    assert definitions[0]["ai_summary_configured"] is False
    assert definitions[0]["data_boundary"]["enterprise_data"] == "never"
    assert (
        registry.call("coal-news-search", {"question": "煤炭新闻"})["status"]
        == "succeeded"
    )


def test_chat_news_without_summary_model_lists_sources_without_leaking_draft() -> None:
    outbound: list[str] = []

    def opener(request: Any, _timeout: float) -> Response:
        outbound.append(request.full_url)
        return Response(_feed(_item()))

    service = EnterpriseAgentService(
        Repository(":memory:"),
        skill_registry=_registry(_bing_skill(opener=opener)),
    )
    draft = service.create_draft(
        {
            "enterprise_name": "绝密煤业集团",
            "mine_name": "未公开一号矿",
        },
        actor="operator-1",
    )
    service.enable_harness()
    session = service.chat.create_session(
        actor_id="leader-1",
        draft_id=draft["draft_id"],
        client_request_id="news-bound-session",
    )["session"]

    turn = service.chat.post_message(
        session["session_id"],
        actor_id="leader-1",
        content="帮我看看最近煤炭相关新闻",
        client_message_id="news-turn-1",
    )

    assistant = turn["messages"][-1]
    assert turn["run_id"] is None
    assert assistant["status"] == "completed"
    assert assistant["evidence"]["answer_kind"] == "news_retrieval"
    assert assistant["evidence"]["skill_name"] == "coal-news-search"
    assert assistant["evidence"]["retrieval"]["status"] == "succeeded"
    assert assistant["evidence"]["sources"][0]["url"].startswith("https://")
    assert assistant["evidence"]["enterprise_data_sent_to_provider"] is False
    assert assistant["evidence"]["draft_data_sent_to_skill"] is False
    assert assistant["evidence"]["model_generated"] is False
    assert assistant["evidence"]["summary"]["status"] == "unavailable"
    assert assistant["evidence"]["summary"]["failure_code"] == "not_configured"
    assert "AI 摘要暂不可用" not in assistant["content"]
    assert "未配置可用的总结模型" in assistant["content"]
    assert len(outbound) == 1
    assert "绝密" not in outbound[0]
    assert "未公开" not in outbound[0]
    assert service.harness.list(actor_id="leader-1", limit=20, offset=0)[1] == 0
    service.disable_harness()


def test_chat_uses_ai_to_summarize_baidu_evidence_then_keeps_sources() -> None:
    outbound: list[str] = []
    page = _baidu_page(
        {
            "title": "煤炭绿色智能开采取得新进展",
            "titleUrl": "https://www.stdaily.com/web/gdxw/2026-07/22/content.html",
            "dispTime": "6天前",
            "sourceName": "中国科技网",
            "summary": (
                "搜索片段显示，相关项目聚焦稀缺煤炭资源绿色智能开发..."
            ),
        }
    )

    def opener(request: Any, _timeout: float) -> NetworkResponse:
        outbound.append(request.full_url)
        return NetworkResponse(
            page,
            final_url=request.full_url,
            content_type="text/html;charset=utf-8",
        )

    class NewsSummaryProvider:
        def __init__(self) -> None:
            self.news_requests: list[dict[str, Any]] = []

        def summarize_coal_news(self, **request: Any) -> str:
            self.news_requests.append(request)
            return (
                "**AI 新闻摘要**\n"
                "近期检索结果聚焦煤炭绿色智能开发。（来源：S1）\n\n"
                "**重点动态**\n"
                "- 相关项目强调稀缺资源利用。（来源：S1）"
            )

        def complete_with_tools(self, **_request: Any) -> dict[str, Any]:
            raise AssertionError("新闻摘要不应进入 Harness 工具循环")

    provider = NewsSummaryProvider()
    skill = CoalNewsSearchSkill(
        CoalNewsConfig(
            timeout_seconds=4,
            baidu_timeout_seconds=1,
            max_results=1,
        ),
        llm_config=_llm_config(),
        opener=opener,
        clock=lambda: NOW,
    )
    service = EnterpriseAgentService(
        Repository(":memory:"),
        llm_provider=provider,  # type: ignore[arg-type]
        skill_registry=_registry(skill),
    )
    draft = service.create_draft(
        {
            "enterprise_name": "绝密煤业集团",
            "mine_name": "未公开一号矿",
        },
        actor="operator-1",
    )
    service.enable_harness()
    session_id = service.chat.create_session(
        actor_id="leader-1",
        draft_id=draft["draft_id"],
        client_request_id="news-ai-session",
    )["session"]["session_id"]

    turn = service.chat.post_message(
        session_id,
        actor_id="leader-1",
        content="帮我看看最近煤炭相关新闻；不要发送绝密一号矿",
        client_message_id="news-ai-turn",
    )

    assistant = turn["messages"][-1]
    assert turn["run_id"] is None
    assert "**AI 新闻摘要**" in assistant["content"]
    assert "未读取新闻全文" in assistant["content"]
    assert assistant["evidence"]["model_generated"] is True
    assert assistant["evidence"]["summary_provider_called"] is True
    assert assistant["evidence"]["summary"]["status"] == "succeeded"
    assert assistant["evidence"]["summary"]["grounding"] == (
        "search_title_and_snippet"
    )
    assert assistant["evidence"]["sources"][0]["source_id"] == "S1"
    assert assistant["evidence"]["sources"][0]["search_snippet"].startswith(
        "搜索片段显示"
    )
    assert len(outbound) == 1
    assert urlsplit(outbound[0]).hostname == "www.baidu.com"
    assert len(provider.news_requests) == 1
    summary_request = provider.news_requests[0]
    assert set(summary_request) == {
        "topic",
        "window_days",
        "searched_at",
        "sources",
    }
    assert summary_request["topic"] == "煤炭"
    assert "url" not in summary_request["sources"][0]
    serialized = json.dumps(summary_request, ensure_ascii=False)
    assert "绝密" not in serialized
    assert "未公开" not in serialized
    assert draft["draft_id"] not in serialized
    assert service.chat.store.context(session_id, actor_id="leader-1") == []
    assert service.harness.list(actor_id="leader-1", limit=20, offset=0)[1] == 0
    service.disable_harness()


def test_invalid_ai_news_summary_keeps_successful_baidu_sources() -> None:
    requested: list[str] = []
    page = _baidu_page(
        {
            "title": "煤炭行业公开动态",
            "titleUrl": "https://news.example.com/coal/summary-fallback",
            "dispTime": "1小时前",
            "sourceName": "行业媒体",
            "summary": "煤炭行业搜索片段。",
        }
    )

    def opener(request: Any, _timeout: float) -> NetworkResponse:
        requested.append(request.full_url)
        return NetworkResponse(
            page,
            final_url=request.full_url,
            content_type="text/html;charset=utf-8",
        )

    class InvalidSummaryProvider:
        def summarize_coal_news(self, **_request: Any) -> str:
            return "没有来源编号的自由文本"

        def complete_with_tools(self, **_request: Any) -> dict[str, Any]:
            raise AssertionError("新闻摘要不应进入 Harness")

    service = EnterpriseAgentService(
        Repository(":memory:"),
        llm_provider=InvalidSummaryProvider(),  # type: ignore[arg-type]
        skill_registry=_registry(
            CoalNewsSearchSkill(
                CoalNewsConfig(timeout_seconds=4, baidu_timeout_seconds=1),
                llm_config=_llm_config(),
                opener=opener,
                clock=lambda: NOW,
            )
        ),
    )
    service.enable_harness()
    session_id = service.chat.create_session(
        actor_id="leader-1",
        client_request_id="invalid-summary-session",
    )["session"]["session_id"]

    turn = service.chat.post_message(
        session_id,
        actor_id="leader-1",
        content="最近煤炭新闻",
        client_message_id="invalid-summary-turn",
    )

    assistant = turn["messages"][-1]
    assert assistant["evidence"]["retrieval"]["status"] == "succeeded"
    assert assistant["evidence"]["retrieval"]["fallback_used"] is False
    assert assistant["evidence"]["summary"]["status"] == "failed"
    assert assistant["evidence"]["summary"]["failure_code"] == "invalid_response"
    assert assistant["evidence"]["model_generated"] is False
    assert "总结结果未通过引用校验" in assistant["content"]
    assert "S1｜煤炭行业公开动态" in assistant["content"]
    assert "**AI 新闻摘要**" not in assistant["content"]
    assert len(requested) == 1
    service.disable_harness()


def test_news_failure_does_not_fall_back_to_local_knowledge_or_bind_draft() -> None:
    skill = _bing_skill(
        opener=lambda _request, _timeout: (_ for _ in ()).throw(TimeoutError()),
    )
    service = EnterpriseAgentService(
        Repository(":memory:"),
        skill_registry=_registry(skill),
    )
    draft = service.create_draft(
        {"enterprise_name": "不应绑定企业"}, actor="operator-1"
    )
    service.enable_harness()
    session_id = service.chat.create_session(
        actor_id="leader-1",
        client_request_id="news-unbound-session",
    )["session"]["session_id"]

    turn = service.chat.post_message(
        session_id,
        actor_id="leader-1",
        content="最近煤炭新闻",
        draft_id=draft["draft_id"],
    )

    assert turn["session"]["draft_id"] is None
    assistant = turn["messages"][-1]
    assert assistant["evidence"]["retrieval"]["status"] == "failed"
    assert assistant["evidence"]["answer_kind"] == "news_retrieval"
    assert "请检查服务器 DNS/代理" in assistant["content"]
    assert "离线知识库没有足够" not in assistant["content"]
    assert "这是煤炭通识说明" not in assistant["content"]
    assert "现场安全阈值" not in assistant["content"]
    service.disable_harness()


def test_chat_distinguishes_no_results_from_network_failure() -> None:
    service = EnterpriseAgentService(
        Repository(":memory:"),
        skill_registry=_registry(
            _bing_skill(
                opener=lambda _request, _timeout: Response(_feed()),
            )
        ),
    )
    service.enable_harness()
    session_id = service.chat.create_session(
        actor_id="leader-1",
        client_request_id="news-empty-session",
    )["session"]["session_id"]

    turn = service.chat.post_message(
        session_id,
        actor_id="leader-1",
        content="最近煤炭新闻",
    )

    assistant = turn["messages"][-1]
    assert assistant["evidence"]["retrieval"]["status"] == "failed"
    assert assistant["evidence"]["retrieval"]["failure_code"] == "no_results"
    assert "没有找到通过时间、相关性和安全校验的结果" in assistant["content"]
    assert "请检查服务器 DNS/代理" not in assistant["content"]
    assert "这是煤炭通识说明" not in assistant["content"]
    service.disable_harness()


def _request(
    connection: http.client.HTTPConnection,
    method: str,
    path: str,
) -> tuple[int, dict[str, Any]]:
    connection.request(method, path)
    response = connection.getresponse()
    return response.status, json.loads(response.read())


def test_health_and_skills_http_contract_distinguishes_configuration() -> None:
    service = EnterpriseAgentService(Repository(":memory:"))
    server = EnterpriseAgentHTTPServer(("127.0.0.1", 0), service)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    connection = http.client.HTTPConnection(
        "127.0.0.1", server.server_address[1], timeout=3
    )
    try:
        status, health = _request(connection, "GET", "/api/v1/health")
        assert status == 200
        assert health["llm_configured"] is False
        assert health["llm_connection_status"] == "not_configured"
        assert health["news_search_available"] is True
        assert health["news_search_status"] == "configured_unverified"
        assert health["news_ai_summary_configured"] is False
        assert health["news_ai_summary_status"] == "not_configured"
        assert health["news_ai_summary_grounding"] == (
            "search_title_and_snippet"
        )

        status, payload = _request(connection, "GET", "/api/v1/agent/skills")
        assert status == 200
        assert payload["count"] == 1
        assert payload["skills"][0]["name"] == "coal-news-search"
        assert "url" not in payload["skills"][0]
    finally:
        connection.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_news_intent_requires_explicit_coal_topic() -> None:
    assert coal_news_search_decision("最近煤炭相关新闻").allowed
    assert not coal_news_search_decision("看看最近相关新闻").allowed
