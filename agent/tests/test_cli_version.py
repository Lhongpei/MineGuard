from __future__ import annotations

import pytest

from enterprise_agent import __version__
from enterprise_agent.cli import _parser


def test_cli_reports_installed_package_version(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as raised:
        _parser().parse_args(["--version"])

    assert raised.value.code == 0
    assert capsys.readouterr().out.strip() == f"enterprise-agent {__version__}"
