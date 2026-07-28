"""Application service connecting edge observations to the safety engine."""

from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import json
from typing import Any

from .edge_ingest import EdgeTelemetryBatch
from .edge_store import EdgeTelemetryRepository
from .safety import (
    DEFAULT_RULE_SNAPSHOT,
    MeasurementQuality,
    MeasurementUnit,
    MethaneLocation,
    MethaneObservation,
    MineGasCategory,
    MineSafetyProfile,
    ObservationSource,
    PersonnelObservation,
    SafetyEvaluationRequest,
    SafetyMetric,
    SafetyRuleSnapshot,
    SafetySignalState,
    SourceChannel,
    VentilationObservation,
    evaluate_safety,
)


_METHANE_LOCATIONS: dict[str, MethaneLocation] = {
    "working_face_t1": MethaneLocation.WORKING_FACE_T1,
    "working-face-t1": MethaneLocation.WORKING_FACE_T1,
    "t1": MethaneLocation.WORKING_FACE_T1,
    "return_air_t2": MethaneLocation.RETURN_AIR_T2,
    "return-air-t2": MethaneLocation.RETURN_AIR_T2,
    "working-face-return-t2": MethaneLocation.RETURN_AIR_T2,
    "t2": MethaneLocation.RETURN_AIR_T2,
    "return_air_middle": MethaneLocation.RETURN_AIR_MIDDLE,
    "return-air-middle": MethaneLocation.RETURN_AIR_MIDDLE,
    "total_return_air": MethaneLocation.TOTAL_RETURN_AIR,
    "total-return-air": MethaneLocation.TOTAL_RETURN_AIR,
    "main-return": MethaneLocation.TOTAL_RETURN_AIR,
}

_SCOPE_TITLES = {
    "personnel": "井下人员数量预警",
    "methane": "甲烷监测预警",
    "ventilation": "通风系统预警",
}

_DIRECT_SAFETY_METRICS = {
    "personnel.unauthorized_entry_count",
    "personnel.no_card_entry_count",
    "personnel.person_card_mismatch_count",
    "personnel.overtime_count",
    "ventilation.main_fan_running",
    "ventilation.main_fan_fault",
    "ventilation.main_fan_changeover",
}

_SOURCE_HEALTH_METRICS = {
    "source.heartbeat_age_seconds",
    "source.consecutive_failures",
    "source.missing_state",
}
_SOURCE_HEALTH_RECOVERY_STATUS_CODES = {
    "ok",
    "partial_records_rejected",
}
_SOURCE_HEALTH_RULE_VERSION = "edge-source-health-integrity-v1"
_SOURCE_HEALTH_RULE_FINGERPRINT = hashlib.sha256(
    (
        "source.missing_state == 1 opens an operational technical warning;"
        "a valid clock-synchronised missing_state == 0 with an explicitly"
        " data-bearing recovery status resolves it"
    ).encode()
).hexdigest()


def _profile_for(
    repository: EdgeTelemetryRepository,
    mine_id: str,
) -> MineSafetyProfile | None:
    items = repository.list_mines({mine_id})
    if not items:
        return None
    item = items[0]
    category = item.get("gas_category")
    capacity = item.get("approved_underground_personnel")
    if category not in {"low_gas", "high_gas"} or not capacity:
        return None
    return MineSafetyProfile(
        mine_id=mine_id,
        gas_category=MineGasCategory(category),
        approved_personnel_capacity=int(capacity),
    )


def _source(observation: Any) -> ObservationSource:
    return ObservationSource(
        source_id=observation.source_id,
        system_name="registered-mine-edge-source",
        channel=(
            SourceChannel.MANUAL
            if observation.acquisition_mode
            == "authenticated_manual_entry"
            else SourceChannel.AUTOMATIC
        ),
        lineage_ref=(
            f"{observation.source_record_id}:"
            f"{observation.source_record_sha256}"
        ),
        # This flag means the observation arrived through the authenticated
        # registered edge channel. Device-level signatures remain separately
        # visible as source_signature and are not fabricated here.
        signature_valid=True,
    )


def _quality(observation: Any) -> MeasurementQuality:
    quality = observation.quality
    return MeasurementQuality(
        score=min(quality.completeness, quality.timeliness),
        complete=quality.valid and quality.completeness >= 0.5,
        device_healthy=quality.device_health == "healthy",
        clock_synchronised=quality.clock_synchronized,
        blocking_flags=tuple(sorted(quality.flags)),
    )


def _adapt_observations(
    batch: EdgeTelemetryBatch,
) -> tuple[list[Any], list[dict[str, str]]]:
    result: list[Any] = []
    rejected: list[dict[str, str]] = []
    for item in batch.observations:
        common = {
            "observation_id": item.observation_id,
            "revision": item.revision,
            "mine_id": batch.mine_id,
            "observed_at": item.observed_at,
            "received_at": item.received_at,
            "source": _source(item),
            "quality": _quality(item),
        }
        if item.metric_code == "personnel.underground_count":
            result.append(
                PersonnelObservation(
                    **common,
                    metric=SafetyMetric.PERSONNEL_COUNT,
                    value=int(item.value),
                    unit=MeasurementUnit.PERSON,
                )
            )
        elif item.metric_code == "methane.concentration_percent":
            location = _METHANE_LOCATIONS.get(
                item.location_code.strip().lower()
            )
            if location is None:
                rejected.append(
                    {
                        "observation_id": item.observation_id,
                        "code": "unsupported_methane_location",
                        "explanation": (
                            "甲烷点位未映射到 T1、T2、中部回风或总回风口径"
                        ),
                    }
                )
                continue
            result.append(
                MethaneObservation(
                    **common,
                    metric=SafetyMetric.METHANE_CONCENTRATION,
                    point_id=item.location_code,
                    location=location,
                    value=item.value,
                    unit=MeasurementUnit.PERCENT_CH4,
                )
            )
        elif item.metric_code == "ventilation.airflow_m3_min":
            result.append(
                VentilationObservation(
                    **common,
                    metric=SafetyMetric.VENTILATION_FLOW,
                    point_id=item.location_code,
                    value=item.value / 60.0,
                    unit=MeasurementUnit.CUBIC_METRE_PER_SECOND,
                )
            )
    return result, rejected


def _latest_source_health(
    batch: EdgeTelemetryBatch,
) -> dict[str, dict[str, Any]]:
    """Select one deterministic latest health value per source and metric."""

    result: dict[str, dict[str, Any]] = {}
    ranks: dict[tuple[str, str], tuple[Any, ...]] = {}
    for item in batch.observations:
        if item.metric_code not in _SOURCE_HEALTH_METRICS:
            continue
        key = (item.source_id, item.metric_code)
        rank = (
            item.observed_at,
            item.revision,
            item.sequence_no,
            item.received_at,
            item.observation_id,
        )
        if key in ranks and rank <= ranks[key]:
            continue
        ranks[key] = rank
        result.setdefault(item.source_id, {})[item.metric_code] = item
    return result


def _evaluate_source_health(
    repository: EdgeTelemetryRepository,
    batch: EdgeTelemetryBatch,
) -> dict[str, Any]:
    """Turn explicit missing-state telemetry into a technical alert lifecycle."""

    sources: list[dict[str, Any]] = []
    alert_ids: list[str] = []
    for source_id, metrics in sorted(_latest_source_health(batch).items()):
        missing = metrics.get("source.missing_state")
        evidence = sorted(
            {item.observation_id for item in metrics.values()}
        )
        details: dict[str, Any] = {
            "source_id": source_id,
            "data_freshness": "unknown",
            "technical_warning": True,
            "advisory_only": True,
            "production_control_permitted": False,
            "observation_ids": evidence,
        }
        heartbeat = metrics.get("source.heartbeat_age_seconds")
        if heartbeat is not None:
            details["heartbeat_age_seconds"] = float(heartbeat.value)
        failures = metrics.get("source.consecutive_failures")
        if failures is not None:
            details["consecutive_failures"] = int(failures.value)
        if missing is None:
            sources.append(
                {
                    "source_id": source_id,
                    "status": "not_evaluated_no_missing_state",
                    "details": details,
                }
            )
            continue

        status_code = missing.status_code
        is_missing = bool(missing.value)
        details.update(
            {
                "missing_state": is_missing,
                "data_freshness": (
                    "missing" if is_missing else "recovery_unconfirmed"
                ),
                "status_code": status_code,
                "observed_at": missing.observed_at.isoformat(),
                "quality": missing.quality.model_dump(mode="json"),
            }
        )
        if is_missing:
            alert = repository.upsert_platform_alert(
                mine_id=batch.mine_id,
                category="data_quality",
                rule_code="source_data_missing",
                level="yellow",
                title="数据来源断流技术预警",
                summary=(
                    f"来源 {source_id} 已超过边缘节点配置的缺数时限，"
                    "当前数据不可视为正常或完整，请核对采集链路。"
                ),
                location_code=source_id,
                detected_at=missing.observed_at,
                observation_ids=evidence,
                details=details,
                rule_profile={
                    "version": _SOURCE_HEALTH_RULE_VERSION,
                    "fingerprint": _SOURCE_HEALTH_RULE_FINGERPRINT,
                    "approval_status": "system_integrity_control",
                    "rule": "source.missing_state == 1",
                },
                operational=True,
            )
            alert_ids.append(alert["alert_id"])
            sources.append(
                {
                    "source_id": source_id,
                    "status": "missing_alert_active",
                    "alert_id": alert["alert_id"],
                    "details": details,
                }
            )
            continue

        recovery_trusted = (
            missing.quality.valid
            and missing.quality.clock_synchronized
            and status_code in _SOURCE_HEALTH_RECOVERY_STATUS_CODES
        )
        details["recovery_trusted"] = recovery_trusted
        if not recovery_trusted:
            # A startup grace period, disabled connector, stopped worker or
            # invalid health sample must never turn a prior missing alert into
            # a visually normal source.
            sources.append(
                {
                    "source_id": source_id,
                    "status": "recovery_deferred",
                    "details": details,
                }
            )
            continue
        resolved = repository.auto_resolve_platform_alert(
            mine_id=batch.mine_id,
            category="data_quality",
            rule_code="source_data_missing",
            location_code=source_id,
            operational=True,
            note=(
                f"来源 {source_id} 已重新产生有效数据，"
                "边缘节点明确报告缺数状态恢复；转为待人工关闭。"
            ),
        )
        details["data_freshness"] = "available"
        sources.append(
            {
                "source_id": source_id,
                "status": (
                    "missing_alert_recovered"
                    if resolved is not None
                    else "available"
                ),
                "alert_id": (
                    resolved["alert_id"] if resolved is not None else None
                ),
                "details": details,
            }
        )
    return {
        "sources": sources,
        "alert_ids": sorted(set(alert_ids)),
    }


def evaluate_edge_batch_safety(
    repository: EdgeTelemetryRepository,
    batch: EdgeTelemetryBatch,
    *,
    decision_time: datetime | None = None,
) -> dict[str, Any]:
    """Independently evaluate a received batch and persist deterministic state."""

    now = (decision_time or datetime.now(UTC)).astimezone(UTC)
    relevant, adapter_rejections = _adapt_observations(batch)
    direct_observations = [
        item
        for item in batch.observations
        if item.metric_code in _DIRECT_SAFETY_METRICS
    ]
    has_source_health = any(
        item.metric_code in _SOURCE_HEALTH_METRICS
        for item in batch.observations
    )
    if (
        not relevant
        and not adapter_rejections
        and not direct_observations
        and not has_source_health
    ):
        return {
            "status": "not_applicable",
            "mine_id": batch.mine_id,
            "reason": "batch contains no supported safety observations",
            "adapter_rejections": [],
            "alert_ids": [],
        }

    mine_records = repository.list_mines({batch.mine_id})
    if mine_records and not bool(mine_records[0].get("enabled", True)):
        return {
            "status": "monitoring_disabled",
            "mine_id": batch.mine_id,
            "reason": (
                "mine monitoring is disabled; raw observations were retained "
                "without platform safety evaluation or notification"
            ),
            "adapter_rejections": adapter_rejections,
            "alert_ids": [],
        }

    source_health = _evaluate_source_health(repository, batch)
    created_alert_ids: list[str] = list(source_health["alert_ids"])
    if not relevant and not adapter_rejections and not direct_observations:
        return {
            "status": "evaluated_source_health",
            "mine_id": batch.mine_id,
            "reason": (
                "explicit source-health telemetry was independently evaluated"
            ),
            "source_health": source_health["sources"],
            "adapter_rejections": [],
            "alert_ids": sorted(set(created_alert_ids)),
        }

    approved_rule = repository.effective_safety_rule(now)
    legacy_rule_version: str | None = None
    if (
        approved_rule is not None
        and "main_fan" not in approved_rule["snapshot"]
    ):
        # Never mutate or silently reinterpret an already approved snapshot.
        # A pre-V2 rule remains auditable but must be explicitly retired and
        # replaced before new evaluations can be treated as approved.
        legacy_rule_version = approved_rule["rule_version"]
        approved_rule = None
    rules = (
        DEFAULT_RULE_SNAPSHOT
        if approved_rule is None
        else SafetyRuleSnapshot.model_validate_json(
            json.dumps(
                approved_rule["snapshot"],
                ensure_ascii=False,
                separators=(",", ":"),
            )
        )
    )
    operational = approved_rule is not None
    if approved_rule is None:
        repository.upsert_platform_alert(
            mine_id=batch.mine_id,
            category="data_quality",
            rule_code="safety_rule_approval_required",
            level="blue",
            title="安全规则尚未审批生效",
            summary=(
                "平台正在使用内置方案参数生成影子线索，但当前没有处于"
                "生效期的已审批规则版本，结果不得用于正式处置。"
            ),
            location_code="rule-governance",
            detected_at=now,
            observation_ids=sorted(
                {
                    item.observation_id for item in relevant
                }
                | {
                    item.observation_id for item in direct_observations
                }
                | {
                    item["observation_id"]
                    for item in adapter_rejections
                }
            ),
            details={
                "proposal_version": rules.version,
                "approval_required": True,
                "legacy_approved_rule_without_main_fan": (
                    legacy_rule_version
                ),
            },
            rule_profile={
                "version": rules.version,
                "fingerprint": rules.fingerprint,
                "approval_status": "not_approved",
            },
        )
    else:
        repository.auto_resolve_platform_alert(
            mine_id=batch.mine_id,
            category="data_quality",
            rule_code="safety_rule_approval_required",
            location_code="rule-governance",
            note=(
                f"规则 {rules.version} 已审批并处于生效期，"
                "后续批次已按该版本复算。"
            ),
        )
    for item in direct_observations:
        if item.metric_code == "personnel.unauthorized_entry_count":
            rule_code = "unauthorized_underground_entry"
            category = "personnel"
            title = "疑似未经授权入井"
            level = "red"
            active = item.value > 0
            summary = (
                f"监测到 {int(item.value)} 条未经授权入井记录，"
                "请立即核对人员定位、门禁和当班名单。"
            )
            details = {
                "latest_value": int(item.value),
                "advisory_only": True,
                "production_control_permitted": False,
            }
            rule_description = "count > 0"
        elif item.metric_code == "personnel.no_card_entry_count":
            rule_code = "personnel_no_card_entry"
            category = "personnel"
            title = "无卡入井核查预警"
            level = "orange"
            active = item.value > 0
            summary = (
                f"监测到 {int(item.value)} 条无卡入井聚合记录，"
                "请核对唯一性门禁、人员定位和当班名单；聚合计数"
                "本身不构成人员身份或违规认定。"
            )
            details = {
                "latest_value": int(item.value),
                "advisory_only": True,
                "production_control_permitted": False,
            }
            rule_description = "count > 0"
        elif item.metric_code == "personnel.person_card_mismatch_count":
            rule_code = "personnel_card_identity_mismatch"
            category = "personnel"
            title = "人卡不符核查预警"
            level = "orange"
            active = item.value > 0
            summary = (
                f"监测到 {int(item.value)} 条人卡不符聚合记录，"
                "请在授权系统内核对门禁、定位卡和人员身份；"
                "本平台不接收个人身份明细。"
            )
            details = {
                "latest_value": int(item.value),
                "advisory_only": True,
                "production_control_permitted": False,
            }
            rule_description = "count > 0"
        elif item.metric_code == "personnel.overtime_count":
            rule_code = "personnel_underground_overtime"
            category = "personnel"
            title = "井下超时人员核查提示"
            level = "yellow"
            active = item.value > 0
            summary = (
                f"监测到 {int(item.value)} 条井下超时聚合记录，"
                "请核对班次边界、定位数据和现场情况。"
            )
            details = {
                "latest_value": int(item.value),
                "advisory_only": True,
                "production_control_permitted": False,
            }
            rule_description = "count > 0"
        elif item.metric_code == "ventilation.main_fan_running":
            rule_code = "main_fan_stopped"
            category = "ventilation"
            title = "主通风机停机预警"
            level = rules.main_fan.stopped_level.value
            active = item.value == 0
            summary = (
                f"{item.location_code} 主通风机报告停机，"
                "请立即核对备用机、供电和实时风量。"
            )
            details = {
                "latest_running_state": int(item.value),
                "advisory_only": True,
                "production_control_permitted": False,
            }
            rule_description = "running == 0"
        elif item.metric_code == "ventilation.main_fan_fault":
            rule_code = "main_fan_fault"
            category = "ventilation"
            title = "主通风机故障预警"
            level = rules.main_fan.fault_level.value
            active = item.value == 1
            summary = (
                f"{item.location_code} 主通风机报告故障，"
                "请立即核对设备保护、备用机和实时风量。"
            )
            details = {
                "latest_fault_state": int(item.value),
                "advisory_only": True,
                "production_control_permitted": False,
            }
            rule_description = "fault == 1"
        else:
            rule_code = "main_fan_changeover"
            category = "ventilation"
            title = "主通风机倒机提示"
            level = rules.main_fan.changeover_level.value
            active = item.value == 1
            summary = (
                f"{item.location_code} 主通风机报告倒机，"
                "请核对备用机启停及风量恢复情况。"
            )
            details = {
                "latest_changeover_state": int(item.value),
                "advisory_only": True,
                "production_control_permitted": False,
            }
            rule_description = "changeover == 1"
        if (
            item.quality.valid
            and item.quality.clock_synchronized
            and active
        ):
            alert = repository.upsert_platform_alert(
                mine_id=batch.mine_id,
                category=category,
                rule_code=rule_code,
                level=level,
                title=title,
                summary=summary,
                location_code=item.location_code,
                detected_at=item.observed_at,
                observation_ids=[item.observation_id],
                details=details,
                rule_profile={
                    "version": rules.version,
                    "fingerprint": rules.fingerprint,
                    "rule": rule_description,
                    "approval_status": (
                        "approved"
                        if approved_rule is not None
                        else "not_approved"
                    ),
                },
                operational=operational,
            )
            created_alert_ids.append(alert["alert_id"])
        elif (
            item.quality.valid
            and item.quality.clock_synchronized
            and not active
        ):
            repository.auto_resolve_platform_alert(
                mine_id=batch.mine_id,
                category=category,
                rule_code=rule_code,
                location_code=item.location_code,
                operational=operational,
            )
    if adapter_rejections:
        repository.upsert_platform_alert(
            mine_id=batch.mine_id,
            category="data_quality",
            rule_code="safety_location_mapping_required",
            level="blue",
            title="安全监测点位待映射",
            summary=(
                "部分安全观测点位尚未映射到已审批规则口径，"
                "原始数据已保留但未参与阈值判断。"
            ),
            location_code="mapping-registry",
            detected_at=now,
            observation_ids=[
                item["observation_id"] for item in adapter_rejections
            ],
            details={"rejections": adapter_rejections},
            rule_profile={
                "version": rules.version,
                "fingerprint": rules.fingerprint,
            },
        )
    if not relevant:
        return {
            "status": (
                "evaluated_direct_signals"
                if direct_observations
                else "mapping_required"
            ),
            "mine_id": batch.mine_id,
            "reason": (
                "direct safety signals were independently evaluated"
                if direct_observations
                else "safety observation locations require mapping"
            ),
            "adapter_rejections": adapter_rejections,
            "source_health": source_health["sources"],
            "alert_ids": sorted(set(created_alert_ids)),
        }
    profile = _profile_for(repository, batch.mine_id)
    if profile is None:
        repository.upsert_platform_alert(
            mine_id=batch.mine_id,
            category="data_quality",
            rule_code="mine_safety_profile_missing",
            level="blue",
            title="矿井安全参数待配置",
            summary=(
                "尚未配置瓦斯矿井类别或核定井下人数，原始数据已留存，"
                "平台未擅自套用阈值。请管理员补齐矿井档案后复算。"
            ),
            location_code="mine-profile",
            detected_at=now,
            observation_ids=[
                observation.observation_id for observation in relevant
            ],
            details={
                "missing_fields": [
                    "gas_category",
                    "approved_underground_personnel",
                ],
                "adapter_rejections": adapter_rejections,
            },
            rule_profile={
                "version": rules.version,
                "fingerprint": rules.fingerprint,
            },
        )
        return {
            "status": "configuration_required",
            "mine_id": batch.mine_id,
            "reason": (
                "gas_category and approved_underground_personnel are required"
            ),
            "adapter_rejections": adapter_rejections,
            "source_health": source_health["sources"],
            "alert_ids": sorted(set(created_alert_ids)),
        }
    repository.auto_resolve_platform_alert(
        mine_id=batch.mine_id,
        category="data_quality",
        rule_code="mine_safety_profile_missing",
        location_code="mine-profile",
        note="矿井安全档案已补齐，后续批次已按已配置参数复算。",
    )
    previous = [
        SafetySignalState.model_validate_json(
            json.dumps(
                state,
                ensure_ascii=False,
                separators=(",", ":"),
            )
        )
        for state in repository.load_safety_states(
            batch.mine_id,
            rule_version=rules.version,
            rule_fingerprint=rules.fingerprint,
        )
    ]
    result = evaluate_safety(
        SafetyEvaluationRequest(
            profile=profile,
            decision_time=now,
            rules=rules,
            observations=tuple(relevant),
            previous_states=tuple(previous),
        )
    )
    payload = result.model_dump(mode="json")
    payload["adapter_rejections"] = adapter_rejections
    payload["source_health"] = source_health["sources"]
    run_id = repository.save_safety_evaluation(
        batch_id=batch.batch_id,
        result=payload,
    )
    for state in result.states:
        if state.status.value == "normal":
            repository.auto_resolve_platform_alert(
                mine_id=batch.mine_id,
                category=state.scope.value,
                rule_code=state.state_key,
                location_code=state.point_id or "underground-total",
                operational=operational,
            )
    for lead in result.active_leads:
        state = next(
            state
            for state in result.states
            if state.state_key == lead.state_key
        )
        alert = repository.upsert_platform_alert(
            mine_id=batch.mine_id,
            category=lead.scope.value,
            rule_code=lead.state_key,
            level=lead.level.value,
            title=_SCOPE_TITLES[lead.scope.value],
            summary=lead.recommended_review,
            location_code=lead.point_id or "underground-total",
            detected_at=lead.observed_at,
            observation_ids=list(result.accepted_observation_ids),
            details={
                "trigger_codes": list(lead.trigger_codes),
                "latest_value": lead.latest_value,
                "state": state.model_dump(mode="json"),
                "advisory_only": True,
                "production_control_permitted": False,
            },
            rule_profile={
                "version": result.rule_version,
                "fingerprint": result.rule_fingerprint,
                "authority_reference": (
                    rules.authority_reference
                ),
                "approval_status": (
                    "approved"
                    if approved_rule is not None
                    else "not_approved"
                ),
            },
            operational=operational,
        )
        created_alert_ids.append(alert["alert_id"])
    payload.update(
        {
            "status": "evaluated",
            "run_id": run_id,
            "alert_ids": sorted(set(created_alert_ids)),
        }
    )
    return payload
