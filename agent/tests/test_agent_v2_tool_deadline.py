from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import threading

import pytest

from enterprise_agent.agent_v2.workflows import _run_tool_group, _tool
from enterprise_agent.tools import (
    ToolProtocolError,
    ToolRegistry,
    ToolResult,
    ToolSpec,
)


def _blocking_registry(timeout: float) -> tuple[ToolRegistry, threading.Event]:
    release = threading.Event()

    def block(_arguments, _context):
        release.wait()
        return ToolResult(data={}, summary="finished")

    registry = ToolRegistry(
        (
            ToolSpec(
                name="blocking_read",
                description="test-only blocking read",
                input_schema={
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {},
                },
                output_schema={
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {},
                },
                execute=block,
                timeout_seconds=timeout,
            ),
        )
    )
    return registry, release


def test_tool_deadline_preserves_specific_error_code() -> None:
    registry, release = _blocking_registry(0.02)
    try:
        with pytest.raises(ToolProtocolError) as captured:
            _tool(registry, "blocking_read", {})
        result = _run_tool_group(
            registry,
            specialist="test",
            plan=(("blocking_read", {}),),
        )
    finally:
        release.set()

    assert captured.value.code == "tool_timeout"
    assert result["errors"][0]["code"] == "tool_timeout"


def test_timed_out_tool_cannot_block_interpreter_exit() -> None:
    script = textwrap.dedent(
        """
        import threading
        from enterprise_agent.agent_v2.workflows import _tool
        from enterprise_agent.tools import (
            ToolProtocolError, ToolRegistry, ToolResult, ToolSpec
        )

        def block(_arguments, _context):
            threading.Event().wait()
            return ToolResult(data={}, summary="never")

        registry = ToolRegistry((ToolSpec(
            name="blocking_read",
            description="test-only blocking read",
            input_schema={
                "type": "object",
                "additionalProperties": False,
                "properties": {},
            },
            output_schema={
                "type": "object",
                "additionalProperties": False,
                "properties": {},
            },
            execute=block,
            timeout_seconds=0.02,
        ),))
        try:
            _tool(registry, "blocking_read", {})
        except ToolProtocolError as error:
            assert error.code == "tool_timeout"
        else:
            raise AssertionError("timeout was not enforced")
        """
    )
    environment = dict(os.environ)
    environment["PYTHONPATH"] = os.pathsep.join(
        item
        for item in (
            os.path.abspath("src"),
            environment.get("PYTHONPATH", ""),
        )
        if item
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=2,
    )
    assert completed.returncode == 0, completed.stderr
