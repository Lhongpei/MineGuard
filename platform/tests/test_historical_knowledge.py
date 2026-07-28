from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from mineguard.casework import (
    AlgorithmRecordIntegrityError,
    LegitimateScenarioConflictError,
    LocalRepository,
    VersionConflictError,
    match_legitimate_scenarios,
)


def _save_run(
    repository: LocalRepository,
    *,
    batch_id: str,
    mine_id: str,
) -> str:
    repository.save_portfolio_batch(
        {
            "batch_id": batch_id,
            "portfolio_name": "历史知识测试",
            "expected_mine_ids": [mine_id],
            "analyses": [
                {
                    "mine_id": mine_id,
                    "window_start": "2026-07-01T00:00:00Z",
                    "window_end": "2026-07-02T00:00:00Z",
                    "parameters": {},
                    "observations": [],
                }
            ],
        },
        {
            "items": [
                {
                    "mine_id": mine_id,
                    "technical_status": "NORMAL",
                    "review_priority": "NONE",
                    "summary": "正常",
                    "analysis": {
                        "mine_id": mine_id,
                        "status": "NORMAL",
                    },
                }
            ]
        },
        "test-engine",
    )
    return repository.list_runs(batch_id)[0]["run_id"]


def _scenario(
    *,
    scenario_id: str = "planned-maintenance",
    version: int = 1,
    active: bool = True,
) -> dict[str, object]:
    return {
        "scenario_id": scenario_id,
        "version": version,
        "name": "计划检修",
        "description": "审批事件存在且产量处于检修工况区间。",
        "mine_ids": ["M002", "M001", "M001"],
        "regime": "reduced-output",
        "shift": "night",
        "season": None,
        "maintenance": True,
        "required_event_codes": ["MAINTENANCE-APPROVED"],
        "required_tags": ["planned"],
        "feature_bounds": {
            "reported_output_t": {"lower": 10, "upper": 50},
            "transport_ratio": {"lower": 0.8},
        },
        "active": active,
        "created_by": "knowledge-admin",
    }


def test_old_repository_migrates_and_reference_labels_are_chained(
    tmp_path: Path,
) -> None:
    database = tmp_path / "legacy.sqlite3"
    first = LocalRepository(database)
    run_id = _save_run(first, batch_id="legacy-batch", mine_id="M001")
    first.close()
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TABLE run_reference_labels")
        connection.execute("DROP TABLE legitimate_scenarios")

    repository = LocalRepository(database)
    try:
        first_label = repository.append_run_reference_label(
            run_id,
            label="verified_normal",
            actor=" reviewer ",
            note=" 已核对原始凭证。 ",
            expected_sequence=0,
        )
        assert first_label["sequence"] == 1
        assert first_label["previous_hash"] == ""
        assert first_label["actor"] == "reviewer"
        assert first_label["note"] == "已核对原始凭证。"

        with pytest.raises(VersionConflictError, match="sequence changed"):
            repository.append_run_reference_label(
                run_id,
                label="unresolved",
                actor="reviewer",
                note="过期客户端提交。",
                expected_sequence=0,
            )

        second = repository.append_run_reference_label(
            run_id,
            label="legitimate_exception",
            scenario_id="planned-maintenance",
            actor="supervisor",
            note="检修审批凭证已核实。",
            expected_sequence=1,
        )
        assert second["sequence"] == 2
        assert second["previous_hash"] == first_label["event_hash"]
        assert repository.verify_run_reference_label_chain(run_id)
        assert [item["sequence"] for item in (
            repository.get_run_reference_label_history(run_id)
        )] == [1, 2]
        current = repository.get_current_run_reference_label(run_id)
        assert current is not None
        assert current["label"] == "legitimate_exception"
        assert current["reference_eligible"] is True
    finally:
        repository.close()


def test_reference_list_excludes_tampering_and_invalidated_batches(
    tmp_path: Path,
) -> None:
    database = tmp_path / "reference-integrity.sqlite3"
    repository = LocalRepository(database)
    tampered_label_run = _save_run(
        repository,
        batch_id="label-tamper",
        mine_id="M001",
    )
    tampered_run = _save_run(
        repository,
        batch_id="run-tamper",
        mine_id="M002",
    )
    invalidated_run = _save_run(
        repository,
        batch_id="invalidated",
        mine_id="M003",
    )
    valid_run = _save_run(
        repository,
        batch_id="valid",
        mine_id="M004",
    )
    response_tamper_run = _save_run(
        repository,
        batch_id="response-tamper",
        mine_id="M005",
    )
    context_tamper_run = _save_run(
        repository,
        batch_id="context-tamper",
        mine_id="M006",
    )
    for run_id in (
        tampered_label_run,
        tampered_run,
        invalidated_run,
        valid_run,
        response_tamper_run,
        context_tamper_run,
    ):
        repository.append_run_reference_label(
            run_id,
            label="verified_normal",
            actor="reviewer",
            note="双人复核完成。",
            expected_sequence=0,
        )
    repository.set_batch_active(
        "invalidated",
        active=False,
        expected_version=1,
        actor="admin",
        reason="原始批次撤销。",
    )
    with repository._lock, repository._connection:
        repository._connection.execute(
            """
            UPDATE run_reference_labels
            SET note = '越权修改'
            WHERE run_id = ? AND sequence = 1
            """,
            (tampered_label_run,),
        )
        repository._connection.execute(
            """
            UPDATE analysis_runs
            SET result_json = '{"status":"tampered"}'
            WHERE run_id = ?
            """,
            (tampered_run,),
        )
        repository._connection.execute(
            """
            UPDATE batches
            SET response_json = '{"items":[]}'
            WHERE batch_id = 'response-tamper'
            """
        )
        repository._connection.execute(
            """
            UPDATE batches
            SET context_json = '{"tampered":true}'
            WHERE batch_id = 'context-tamper'
            """
        )

    try:
        eligible = repository.list_current_run_reference_labels()
        assert [item["run_id"] for item in eligible] == [valid_run]
        all_current = repository.list_run_reference_labels(
            include_ineligible=True
        )
        eligibility = {
            item["run_id"]: item["reference_eligible"]
            for item in all_current
        }
        assert eligibility == {
            tampered_label_run: False,
            tampered_run: False,
            invalidated_run: False,
            valid_run: True,
            response_tamper_run: False,
            context_tamper_run: False,
        }
        assert (
            repository.get_run_reference_label(tampered_label_run)[
                "label_chain_valid"
            ]
            is False
        )
        assert (
            repository.get_run_reference_label(tampered_run)["run_hash_valid"]
            is False
        )
        assert (
            repository.get_run_reference_label(invalidated_run)["batch_active"]
            is False
        )
        assert (
            repository.get_run_reference_label(response_tamper_run)[
                "batch_integrity_valid"
            ]
            is False
        )
        assert (
            repository.get_run_reference_label(context_tamper_run)[
                "batch_integrity_valid"
            ]
            is False
        )
    finally:
        repository.close()


def test_scenario_versions_are_immutable_idempotent_and_filterable(
    tmp_path: Path,
) -> None:
    repository = LocalRepository(tmp_path / "scenarios.sqlite3")
    try:
        first = repository.save_legitimate_scenario(_scenario())
        assert first["created"] is True
        assert first["hash_valid"] is True
        assert first["mine_ids"] == ["M001", "M002"]
        assert first["feature_bounds"]["reported_output_t"] == {
            "lower": 10.0,
            "upper": 50.0,
        }

        retry = _scenario()
        retry["required_tags"] = ["planned", "planned"]
        retry["mine_ids"] = ["M001", "M002"]
        assert repository.save_legitimate_scenario(retry)["created"] is False

        changed = _scenario()
        changed["description"] = "同一版本的不同定义"
        with pytest.raises(LegitimateScenarioConflictError):
            repository.save_legitimate_scenario(changed)

        inactive_v2 = _scenario(version=2, active=False)
        stored_v2 = repository.save_legitimate_scenario(inactive_v2)
        assert stored_v2["version_chain_valid"] is True
        assert (
            stored_v2["previous_definition_sha256"]
            == first["definition_sha256"]
        )
        with pytest.raises(
            LegitimateScenarioConflictError,
            match="continuous",
        ):
            repository.save_legitimate_scenario(
                _scenario(scenario_id="starts-at-two", version=2)
            )
        repository.save_legitimate_scenario(
            {
                **_scenario(scenario_id="global-event"),
                "mine_ids": None,
                "regime": None,
                "shift": None,
                "maintenance": None,
                "required_event_codes": ["GLOBAL-APPROVED"],
                "required_tags": [],
                "feature_bounds": {
                    "reported_output_t": {
                        "lower": 0.0,
                        "upper": 100.0,
                    }
                },
            }
        )

        assert repository.get_legitimate_scenario(
            "planned-maintenance"
        ) is None
        assert repository.get_legitimate_scenario(
            "planned-maintenance",
            include_inactive=True,
        )["version"] == 2
        assert repository.get_legitimate_scenario(
            "planned-maintenance",
            version=1,
        )["version"] == 1
        assert [
            item["scenario_id"]
            for item in repository.list_legitimate_scenarios(mine_id="M999")
        ] == ["global-event"]
        history = repository.list_legitimate_scenarios(
            include_inactive=True,
            all_versions=True,
        )
        assert [
            (item["scenario_id"], item["version"])
            for item in history
        ] == [
            ("global-event", 1),
            ("planned-maintenance", 2),
            ("planned-maintenance", 1),
        ]
    finally:
        repository.close()


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        (
            "feature_bounds",
            {"x": {"lower": float("nan")}},
            "must be finite",
        ),
        (
            "feature_bounds",
            {"x": {"lower": 2, "upper": 1}},
            "must not exceed",
        ),
        ("maintenance", "yes", "boolean or null"),
        ("required_tags", "tag", "must be an array"),
    ],
)
def test_scenario_definition_rejects_ambiguous_or_non_finite_values(
    field: str,
    value: object,
    message: str,
) -> None:
    repository = LocalRepository()
    scenario = _scenario()
    scenario[field] = value
    try:
        with pytest.raises(ValueError, match=message):
            repository.save_legitimate_scenario(scenario)
    finally:
        repository.close()


def test_scenario_integrity_failure_is_not_an_idempotent_retry(
    tmp_path: Path,
) -> None:
    repository = LocalRepository(tmp_path / "scenario-integrity.sqlite3")
    scenario = _scenario()
    repository.save_legitimate_scenario(scenario)
    with repository._lock, repository._connection:
        repository._connection.execute(
            """
            UPDATE legitimate_scenarios
            SET name = '被篡改'
            WHERE scenario_id = ? AND version = ?
            """,
            ("planned-maintenance", 1),
        )
    try:
        with pytest.raises(AlgorithmRecordIntegrityError):
            repository.save_legitimate_scenario(scenario)
        stored = repository.get_legitimate_scenario(
            "planned-maintenance"
        )
        assert stored is not None
        assert stored["hash_valid"] is False
    finally:
        repository.close()


def test_matcher_supports_operational_context_aliases_and_explains_failures(
    tmp_path: Path,
) -> None:
    repository = LocalRepository(tmp_path / "matcher.sqlite3")
    repository.save_legitimate_scenario(_scenario())
    try:
        matched = repository.match_legitimate_scenarios(
            mine_id="M001",
            operational_context={
                "regime_code": "reduced-output",
                "shift_code": "night",
                "season_code": "summer",
                "maintenance": True,
                "approved_event_codes": ["MAINTENANCE-APPROVED"],
                "tags": ["planned"],
            },
            features={
                "reported_output_t": 30,
                "transport_ratio": 0.9,
            },
        )
        assert [
            item["scenario_id"] for item in matched["matched_scenarios"]
        ] == ["planned-maintenance"]
        assert matched["evaluations"][0]["unmet_reasons"] == []
        assert matched["operational_context"]["regime"] == "reduced-output"

        failed = match_legitimate_scenarios(
            repository.list_legitimate_scenarios(),
            mine_id="M002",
            operational_context={
                "regime": "reduced-output",
                "shift": "day",
                "maintenance": True,
                "event_codes": [],
                "tags": [],
            },
            features={"reported_output_t": 60},
        )
        reasons = failed["evaluations"][0]["unmet_reasons"]
        assert "context_mismatch:shift" in reasons
        assert "missing_event_code:MAINTENANCE-APPROVED" in reasons
        assert "missing_tag:planned" in reasons
        assert "feature_above_upper:reported_output_t" in reasons
        assert "missing_feature:transport_ratio" in reasons
        assert failed["matched_scenarios"] == []

        with pytest.raises(ValueError, match="conflict"):
            repository.match_legitimate_scenarios(
                mine_id="M001",
                operational_context={
                    "regime": "normal",
                    "regime_code": "reduced-output",
                },
                features={},
            )
    finally:
        repository.close()
