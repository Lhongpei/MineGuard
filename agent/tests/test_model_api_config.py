from __future__ import annotations

import json
from pathlib import Path

import pytest

import enterprise_agent.service as service_module
from enterprise_agent.model_api_config import (
    ModelApiConfigError,
    load_model_api_config,
    save_model_api_config,
    validate_model_api_config,
    verify_model_api_config,
)
from enterprise_agent.service import EnterpriseAgentService
from enterprise_agent.storage import Repository


def test_model_api_config_is_encrypted_masked_and_tamper_evident(
    tmp_path: Path,
) -> None:
    path = (tmp_path / "model-api.json").resolve()
    api_key = "sk-local-secret-value-2026"
    saved = save_model_api_config(
        path,
        api_key=api_key,
        base_url="https://models.mineguard.cn/v1",
        model="coal-model-v1",
        actor_id="api_admin",
    )

    encoded = path.read_text(encoding="utf-8")
    assert api_key not in encoded
    loaded, status = load_model_api_config(path)
    assert loaded == saved
    assert status["state"] == "configured"
    assert status["updated_by"] == "api_admin"
    assert "api_key" not in status
    verify_model_api_config(path, saved)

    document = json.loads(encoded)
    document["model"] = "tampered-model"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ModelApiConfigError, match="完整性"):
        load_model_api_config(path)


def test_only_fixed_api_admin_can_save_model_api_config(tmp_path: Path) -> None:
    with pytest.raises(ModelApiConfigError, match="api_admin"):
        save_model_api_config(
            (tmp_path / "model-api.json").resolve(),
            api_key="secret-value",
            base_url="https://models.mineguard.cn/v1",
            model="coal-model-v1",
            actor_id="business-admin",
        )


@pytest.mark.parametrize(
    "base_url",
    (
        "https://user:password@models.mineguard.cn/v1",
        "https://models.mineguard.cn/v1?tenant=other",
        "https://models.mineguard.cn/v1#fragment",
    ),
)
def test_model_api_url_is_rejected_before_provider_request(
    base_url: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    constructed = False

    class UnexpectedProvider:
        def __init__(self, *_args, **_kwargs) -> None:
            nonlocal constructed
            constructed = True

    monkeypatch.setattr(
        service_module,
        "OpenAICompatibleProvider",
        UnexpectedProvider,
    )
    service = EnterpriseAgentService(
        Repository(":memory:"),
        model_config_path=str((tmp_path / "model-api.json").resolve()),
    )
    with pytest.raises(ModelApiConfigError, match="不能包含"):
        service.configure_model_api(
            api_key="sk-must-not-be-sent",
            base_url=base_url,
            model="coal-model-v1",
            actor_id="api_admin",
        )
    assert constructed is False


def test_model_api_validation_normalizes_trailing_slash() -> None:
    config = validate_model_api_config(
        " sk-local-secret ",
        "https://models.mineguard.cn/v1/",
        " coal-model-v1 ",
    )
    assert config.api_key == "sk-local-secret"
    assert config.base_url == "https://models.mineguard.cn/v1"
    assert config.model == "coal-model-v1"


def test_service_tests_connection_before_save_and_hot_applies(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probes: list[tuple[str, str]] = []

    class FakeProvider:
        def __init__(self, config, **_kwargs):
            self.config = config

        def test_connection(self) -> dict[str, str]:
            probes.append((self.config.base_url, self.config.model))
            return {"status": "ok", "model": self.config.model}

    monkeypatch.setattr(service_module, "OpenAICompatibleProvider", FakeProvider)
    path = (tmp_path / "model-api.json").resolve()
    service = EnterpriseAgentService(
        Repository(":memory:"),
        model_config_path=str(path),
    )
    result = service.configure_model_api(
        api_key="sk-hot-reload-secret",
        base_url="https://models.mineguard.cn/v1",
        model="coal-model-v1",
        actor_id="api_admin",
    )

    assert probes == [("https://models.mineguard.cn/v1", "coal-model-v1")]
    assert result["state"] == "configured"
    assert result["connection_test"] == "ok"
    assert "api_key" not in result
    assert service.llm_provider is not None
    assert service.model_api_status()["model"] == "coal-model-v1"
