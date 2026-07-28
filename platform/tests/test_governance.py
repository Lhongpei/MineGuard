from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from mineguard.governance import (
    AnalysisProfile,
    ConfigurationConflictError,
    GovernanceRepository,
    GovernanceService,
    GovernedObservation,
    GovernedProductionRequest,
    ProfileNotApprovedError,
    ProfileNotEffectiveError,
    SourceDefinition,
    compute_observation_signature,
    compute_payload_sha256,
    observation_payload,
    sign_observation,
)
from mineguard.aggregation import MeasurementType
from mineguard.models import BalanceParameters, MetricCode
from mineguard.optimization import analyze_production
from mineguard.quality import evaluate_data_quality


WINDOW_START = datetime(2026, 7, 20, tzinfo=UTC)
WINDOW_END = WINDOW_START + timedelta(days=1)
SOURCE_EFFECTIVE_FROM = datetime(2026, 1, 1, tzinfo=UTC)
CALIBRATION_END = datetime(2026, 12, 31, tzinfo=UTC)

VALUES = {
    MetricCode.REPORTED_PRODUCTION: 1000.0,
    MetricCode.MAIN_TRANSPORT: 1000.0,
    MetricCode.WASH_FEED: 800.0,
    MetricCode.RAW_SALES: 100.0,
    MetricCode.RAW_INVENTORY_CHANGE: 100.0,
}


def make_profile(
    *,
    version: str = "2026.1",
    required_metrics: list[MetricCode] | None = None,
    approved: bool = True,
    effective_to: datetime | None = None,
) -> AnalysisProfile:
    return AnalysisProfile(
        profile_id="five-flow",
        version=version,
        effective_from=datetime(2026, 1, 1, tzinfo=UTC),
        effective_to=effective_to,
        parameters=BalanceParameters(
            transport_balance_tolerance=25.0,
            stock_balance_tolerance=30.0,
            transport_slack_penalty=80.0,
            stock_slack_penalty=90.0,
            max_mcs=4,
            max_relaxed_groups=2,
            quality_gate=60.0,
        ),
        required_metrics=(
            list(MetricCode)
            if required_metrics is None
            else required_metrics
        ),
        approved=approved,
    )


def make_source(
    metric: MetricCode,
    index: int,
    *,
    source_id: str | None = None,
    mine_id: str = "M001",
    unit: str = "t",
    active: bool = True,
    calibration_valid_until: datetime = CALIBRATION_END,
    max_delay_seconds: float = 60.0,
    tolerance_rel: float = 0.0,
    resolution: float = 0.0,
    dependency_domains: list[str] | None = None,
    measurement_type: MeasurementType = MeasurementType.WINDOW_TOTAL,
    expected_interval_seconds: float | None = None,
    min_coverage: float = 0.9,
    max_boundary_staleness_seconds: float = 0.0,
    register_modulus: float | None = None,
    device_health_score: float | None = None,
    clock_quality_score: float | None = None,
) -> SourceDefinition:
    return SourceDefinition(
        source_id=source_id or f"source-{index}",
        mine_id=mine_id,
        metric_code=metric,
        root_source_group=f"root-group-{index}",
        unit=unit,
        tolerance_abs=10.0 + index,
        tolerance_rel=tolerance_rel,
        resolution=resolution,
        reliability=0.95 - index * 0.05,
        dependency_domains=dependency_domains or [],
        measurement_type=measurement_type,
        expected_interval_seconds=expected_interval_seconds,
        min_coverage=min_coverage,
        max_boundary_staleness_seconds=max_boundary_staleness_seconds,
        register_modulus=register_modulus,
        max_delay_seconds=max_delay_seconds,
        device_health_score=device_health_score,
        clock_quality_score=clock_quality_score,
        calibration_valid_until=calibration_valid_until,
        active=active,
    )


def signed_observation(
    source: SourceDefinition,
    secret: bytes,
    index: int,
    *,
    value: float | None = None,
    sequence_no: int | None = None,
    revision: int = 0,
    observation_id: str | None = None,
    unit: str | None = None,
    observed_at: datetime | None = None,
    received_at: datetime | None = None,
    interval_start: datetime | None = None,
    interval_end: datetime | None = None,
    reset_before: bool = False,
) -> GovernedObservation:
    observed = observed_at or WINDOW_START + timedelta(minutes=10, seconds=index)
    received = received_at or observed + timedelta(seconds=10)
    return GovernedObservation.signed(
        secret=secret,
        source_id=source.source_id,
        observation_id=observation_id or f"observation-{index}",
        value=VALUES[source.metric_code] if value is None else value,
        unit=source.unit if unit is None else unit,
        observed_at=observed,
        received_at=received,
        interval_start=interval_start,
        interval_end=interval_end,
        reset_before=reset_before,
        sequence_no=index if sequence_no is None else sequence_no,
        revision=revision,
    )


def register_baseline(
    repository: GovernanceRepository,
) -> tuple[
    AnalysisProfile,
    list[SourceDefinition],
    dict[str, bytes],
]:
    profile = make_profile()
    assert repository.register_profile(profile)
    sources = [
        make_source(metric, index)
        for index, metric in enumerate(MetricCode, start=1)
    ]
    secrets = {
        source.source_id: f"secret-{source.source_id}".encode()
        for source in sources
    }
    for source in sources:
        assert repository.register_source(
            source,
            effective_from=SOURCE_EFFECTIVE_FROM,
        )
    return profile, sources, secrets


def governed_request(
    profile: AnalysisProfile,
    observations: list[GovernedObservation],
) -> GovernedProductionRequest:
    return GovernedProductionRequest(
        mine_id="M001",
        window_start=WINDOW_START,
        window_end=WINDOW_END,
        profile_id=profile.profile_id,
        profile_version=profile.version,
        observations=observations,
    )


def test_happy_path_uses_only_server_registered_configuration() -> None:
    repository = GovernanceRepository()
    try:
        profile, sources, secrets = register_baseline(repository)
        observations = [
            signed_observation(source, secrets[source.source_id], index)
            for index, source in enumerate(sources, start=1)
        ]
        prepared = GovernanceService(
            repository,
            secrets.get,
        ).prepare(governed_request(profile, observations))

        assert prepared.accepted_count == 5
        assert prepared.rejected_count == 0
        assert prepared.quality_issues == []
        assert len(prepared.registry_snapshot_hash) == 64
        assert prepared.profile_version == profile.version
        assert prepared.request is not None
        assert prepared.request.parameters == profile.parameters
        assert prepared.request.calibration_scores == []

        by_source = {
            source.source_id: source for source in sources
        }
        for governed, derived in zip(
            sorted(observations, key=lambda item: item.source_id),
            sorted(
                prepared.request.observations,
                key=lambda item: item.observation_id,
            ),
            strict=True,
        ):
            source = by_source[governed.source_id]
            assert derived.source_group == source.root_source_group
            assert derived.tolerance_abs == source.tolerance_abs
            assert derived.tolerance_rel == source.tolerance_rel
            assert derived.resolution == source.resolution
            assert derived.dependency_domains == source.dependency_domains
            assert derived.source_reliability == source.reliability
            assert derived.quality.signature_valid is True
            assert derived.quality.device_health == 0.5
            assert derived.quality.clock == 0.5
            assert derived.quality.unverified_dimensions == [
                "device_health",
                "clock",
            ]
            assert derived.quality.blocking_flags == []

        quality = evaluate_data_quality(prepared.request)
        assert quality.status == "degraded"
        assert 80 <= quality.score < 100
        assert len(quality.unverified_dimensions) == 10
        assert analyze_production(prepared.request).status == "consistent"
    finally:
        repository.close()


def test_registered_device_and_clock_scores_are_marked_verified() -> None:
    repository = GovernanceRepository()
    profile = make_profile(
        required_metrics=[MetricCode.REPORTED_PRODUCTION]
    )
    source = make_source(
        MetricCode.REPORTED_PRODUCTION,
        1,
        device_health_score=0.92,
        clock_quality_score=0.97,
    )
    try:
        repository.register_profile(profile)
        repository.register_source(
            source,
            effective_from=SOURCE_EFFECTIVE_FROM,
        )
        prepared = GovernanceService(
            repository,
            lambda _: b"secret",
        ).prepare(
            governed_request(
                profile,
                [signed_observation(source, b"secret", 1)],
            )
        )

        assert prepared.request is not None
        quality = prepared.request.observations[0].quality
        assert quality.device_health == 0.92
        assert quality.clock == 0.97
        assert quality.unverified_dimensions == []
    finally:
        repository.close()


def test_governed_models_reject_caller_supplied_trust_fields() -> None:
    source = make_source(MetricCode.REPORTED_PRODUCTION, 1)
    observation = signed_observation(source, b"secret", 1)

    forged_observation = observation.model_dump(mode="python")
    forged_observation.update(
        {
            "source_group": "fake-independent-root",
            "tolerance_abs": 1_000_000.0,
            "reliability": 0.01,
            "quality": {"signature_valid": True},
        }
    )
    with pytest.raises(ValidationError):
        GovernedObservation.model_validate(forged_observation)

    request = GovernedProductionRequest(
        mine_id="M001",
        window_start=WINDOW_START,
        window_end=WINDOW_END,
        profile_id="five-flow",
        profile_version="2026.1",
        observations=[observation],
    )
    forged_request = request.model_dump(mode="python")
    forged_request.update(
        {
            "parameters": {"quality_gate": 0},
            "calibration_scores": [0.0],
        }
    )
    with pytest.raises(ValidationError):
        GovernedProductionRequest.model_validate(forged_request)

    invalid_sequence = observation.model_dump(mode="python")
    invalid_sequence["sequence_no"] = "1"
    with pytest.raises(ValidationError):
        GovernedObservation.model_validate(invalid_sequence)


def test_signature_payload_and_lateness_become_derived_quality() -> None:
    repository = GovernanceRepository()
    try:
        profile, sources, secrets = register_baseline(repository)
        observations = [
            signed_observation(source, secrets[source.source_id], index)
            for index, source in enumerate(sources, start=1)
        ]

        observations[0] = observations[0].model_copy(
            update={"signature": "0" * 64}
        )
        observations[1] = observations[1].model_copy(
            update={"value": observations[1].value + 50.0}
        )
        late = observations[2].model_copy(
            update={
                "received_at": (
                    observations[2].observed_at
                    + timedelta(seconds=600)
                )
            }
        )
        observations[2] = sign_observation(
            late,
            secrets[late.source_id],
        )

        prepared = GovernanceService(
            repository,
            secrets.get,
        ).prepare(governed_request(profile, observations))
        codes = {issue.code for issue in prepared.quality_issues}

        assert "signature_invalid" in codes
        assert "payload_hash_mismatch" in codes
        assert "late_observation" in codes
        assert prepared.accepted_count == 3
        assert prepared.rejected_count == 2
        assert prepared.request is not None
        late_derived = next(
            item
            for item in prepared.request.observations
            if item.observation_id == observations[2].observation_id
        )
        assert late_derived.quality.timeliness == 0.0
        assert any(
            flag.startswith("governance:signature_invalid")
            for flag in late_derived.quality.blocking_flags
        )
        result = analyze_production(prepared.request)
        assert result.status == "inconclusive"
        assert result.data_quality.status == "blocked"
        assert result.data_quality.unverified_dimensions
    finally:
        repository.close()


def test_cross_mine_unit_inactive_calibration_and_metric_mismatch_block() -> None:
    repository = GovernanceRepository()
    profile = make_profile(
        required_metrics=[
            MetricCode.REPORTED_PRODUCTION,
            MetricCode.MAIN_TRANSPORT,
            MetricCode.WASH_FEED,
            MetricCode.RAW_SALES,
        ]
    )
    repository.register_profile(profile)
    sources = [
        make_source(
            MetricCode.REPORTED_PRODUCTION,
            1,
            source_id="cross-mine",
            mine_id="M999",
        ),
        make_source(
            MetricCode.MAIN_TRANSPORT,
            2,
            source_id="wrong-unit",
        ),
        make_source(
            MetricCode.WASH_FEED,
            3,
            source_id="inactive",
            active=False,
        ),
        make_source(
            MetricCode.RAW_SALES,
            4,
            source_id="expired",
            calibration_valid_until=WINDOW_START - timedelta(seconds=1),
        ),
        make_source(
            MetricCode.RAW_INVENTORY_CHANGE,
            5,
            source_id="wrong-metric",
        ),
    ]
    secrets = {source.source_id: b"secret" for source in sources}
    try:
        for source in sources:
            repository.register_source(
                source,
                effective_from=SOURCE_EFFECTIVE_FROM,
            )
        observations = [
            signed_observation(
                source,
                secrets[source.source_id],
                index,
                unit=("kg" if source.source_id == "wrong-unit" else None),
            )
            for index, source in enumerate(sources, start=1)
        ]

        prepared = GovernanceService(
            repository,
            secrets.get,
        ).prepare(governed_request(profile, observations))
        codes = {issue.code for issue in prepared.quality_issues}

        assert {
            "source_mine_mismatch",
            "unit_mismatch",
            "source_inactive",
            "calibration_expired",
            "metric_mismatch",
        } <= codes
        assert prepared.accepted_count == 0
        assert prepared.rejected_count == 5
        assert prepared.request is None
        assert all(issue.blocking for issue in prepared.quality_issues)
    finally:
        repository.close()


def test_observation_uniqueness_and_revisions_are_append_only() -> None:
    repository = GovernanceRepository()
    source = make_source(MetricCode.REPORTED_PRODUCTION, 1)
    revision_zero = signed_observation(
        source,
        b"secret",
        1,
        sequence_no=88,
        observation_id="record-88",
    )
    try:
        assert repository.ingest_observation(revision_zero) == "inserted"
        assert repository.ingest_observation(revision_zero) == "duplicate"

        conflicting = sign_observation(
            revision_zero.model_copy(
                update={"value": revision_zero.value + 1.0}
            ),
            b"secret",
        )
        assert repository.ingest_observation(conflicting) == "conflict"

        revision_one = sign_observation(
            revision_zero.model_copy(
                update={
                    "value": revision_zero.value + 20.0,
                    "revision": 1,
                    "received_at": (
                        revision_zero.received_at + timedelta(hours=1)
                    ),
                }
            ),
            b"secret",
        )
        assert repository.ingest_observation(revision_one) == "inserted"
        revisions = repository.list_observation_revisions(
            source.source_id,
            88,
        )
        assert [item.revision for item in revisions] == [0, 1]
        assert [item.value for item in revisions] == [1000.0, 1020.0]
    finally:
        repository.close()


def test_prepare_uses_latest_revision_and_blocks_exact_duplicates() -> None:
    repository = GovernanceRepository()
    source = make_source(
        MetricCode.REPORTED_PRODUCTION,
        1,
        max_delay_seconds=10_000.0,
    )
    profile = make_profile(
        required_metrics=[MetricCode.REPORTED_PRODUCTION]
    )
    repository.register_profile(profile)
    repository.register_source(
        source,
        effective_from=SOURCE_EFFECTIVE_FROM,
    )
    revision_zero = signed_observation(
        source,
        b"secret",
        1,
        sequence_no=7,
        observation_id="record-7",
    )
    revision_one = sign_observation(
        revision_zero.model_copy(
            update={
                "value": 1100.0,
                "revision": 1,
                "received_at": revision_zero.received_at
                + timedelta(minutes=2),
            }
        ),
        b"secret",
    )
    try:
        service = GovernanceService(
            repository,
            lambda _: b"secret",
        )
        prepared = service.prepare(
            governed_request(profile, [revision_one, revision_zero])
        )

        assert prepared.accepted_count == 1
        assert prepared.rejected_count == 1
        assert prepared.request is not None
        assert prepared.request.observations[0].value == 1100.0
        assert {
            issue.code for issue in prepared.quality_issues
        } == {"superseded_revision"}

        duplicate_repository = GovernanceRepository()
        try:
            duplicate_repository.register_profile(profile)
            duplicate_repository.register_source(
                source,
                effective_from=SOURCE_EFFECTIVE_FROM,
            )
            duplicate_service = GovernanceService(
                duplicate_repository,
                lambda _: b"secret",
            )
            duplicate = duplicate_service.prepare(
                governed_request(
                    profile,
                    [revision_zero, revision_zero],
                )
            )
            assert duplicate.accepted_count == 1
            assert duplicate.rejected_count == 1
            assert any(
                issue.code == "duplicate_sequence_revision"
                and issue.blocking
                for issue in duplicate.quality_issues
            )
            assert duplicate.request is not None
            assert duplicate.request.observations[
                0
            ].quality.blocking_flags
        finally:
            duplicate_repository.close()
    finally:
        repository.close()


def test_exact_observations_can_be_reused_by_a_corrected_bundle() -> None:
    repository = GovernanceRepository()
    try:
        profile, sources, secrets = register_baseline(repository)
        observations = [
            signed_observation(source, secrets[source.source_id], index)
            for index, source in enumerate(sources, start=1)
        ]
        service = GovernanceService(repository, secrets.get)

        first = service.prepare(governed_request(profile, observations))
        retried = service.prepare(governed_request(profile, observations))

        assert first.accepted_count == retried.accepted_count == 5
        assert retried.rejected_count == 0
        assert retried.request is not None
        assert {
            issue.code for issue in retried.quality_issues
        } == {"idempotent_observation_retry"}
        assert all(
            not issue.blocking for issue in retried.quality_issues
        )
    finally:
        repository.close()


def test_configuration_versions_are_immutable_and_effective_by_time() -> None:
    repository = GovernanceRepository()
    source_v1 = make_source(
        MetricCode.REPORTED_PRODUCTION,
        1,
        source_id="versioned-source",
    )
    source_v2 = source_v1.model_copy(
        update={"tolerance_abs": 25.0}
    )
    profile = make_profile()
    try:
        assert repository.register_source(
            source_v1,
            version=1,
            effective_from=datetime(2026, 1, 1, tzinfo=UTC),
        )
        assert not repository.register_source(
            source_v1,
            version=1,
            effective_from=datetime(2026, 1, 1, tzinfo=UTC),
        )
        with pytest.raises(ConfigurationConflictError):
            repository.register_source(
                source_v2,
                version=1,
                effective_from=datetime(2026, 1, 1, tzinfo=UTC),
            )
        assert repository.register_source(
            source_v2,
            version=2,
            effective_from=datetime(2026, 7, 1, tzinfo=UTC),
        )
        assert repository.get_source(
            source_v1.source_id,
            as_of=datetime(2026, 6, 1, tzinfo=UTC),
        ).tolerance_abs == 10.0 + 1
        assert repository.get_source(
            source_v1.source_id,
            as_of=datetime(2026, 8, 1, tzinfo=UTC),
        ).tolerance_abs == 25.0

        assert repository.register_profile(profile)
        assert not repository.register_profile(profile)
        changed_profile = profile.model_copy(
            update={
                "parameters": BalanceParameters(
                    transport_balance_tolerance=999.0
                )
            }
        )
        with pytest.raises(ConfigurationConflictError):
            repository.register_profile(changed_profile)
        assert repository.get_profile(
            profile.profile_id,
            version=profile.version,
            as_of=WINDOW_START,
        ) == profile
    finally:
        repository.close()


def test_interval_deltas_are_aggregated_once_with_coverage_proof() -> None:
    repository = GovernanceRepository()
    source = make_source(
        MetricCode.MAIN_TRANSPORT,
        1,
        source_id="belt-half-hour",
        measurement_type=MeasurementType.INTERVAL_DELTA,
        expected_interval_seconds=12 * 3600,
        tolerance_rel=0.002,
        resolution=0.5,
        dependency_domains=["plc-a", "network-a"],
    )
    profile = make_profile(required_metrics=[MetricCode.MAIN_TRANSPORT])
    secret = b"interval-secret"
    try:
        repository.register_profile(profile)
        repository.register_source(
            source,
            effective_from=SOURCE_EFFECTIVE_FROM,
        )
        middle = WINDOW_START + timedelta(hours=12)
        observations = [
            signed_observation(
                source,
                secret,
                1,
                value=410.0,
                observed_at=middle,
                interval_start=WINDOW_START,
                interval_end=middle,
            ),
            signed_observation(
                source,
                secret,
                2,
                value=590.0,
                observed_at=WINDOW_END,
                interval_start=middle,
                interval_end=WINDOW_END,
            ),
        ]

        prepared = GovernanceService(
            repository,
            lambda _: secret,
        ).prepare(governed_request(profile, observations))

        assert prepared.accepted_count == 2
        assert prepared.rejected_count == 0
        assert prepared.quality_issues == []
        assert prepared.request is not None
        assert len(prepared.request.observations) == 1
        derived = prepared.request.observations[0]
        assert derived.observation_id.startswith("aggregated-")
        assert derived.value == 1000.0
        assert derived.quality.completeness == 1.0
        assert derived.tolerance_rel == 0.002
        assert derived.resolution == 0.5
        assert derived.dependency_domains == ["plc-a", "network-a"]
    finally:
        repository.close()


def test_missing_interval_coverage_is_blocked_and_never_imputed_as_zero() -> None:
    repository = GovernanceRepository()
    source = make_source(
        MetricCode.MAIN_TRANSPORT,
        1,
        source_id="belt-partial",
        measurement_type=MeasurementType.INTERVAL_DELTA,
        expected_interval_seconds=12 * 3600,
        min_coverage=0.9,
    )
    profile = make_profile(required_metrics=[MetricCode.MAIN_TRANSPORT])
    secret = b"interval-secret"
    try:
        repository.register_profile(profile)
        repository.register_source(
            source,
            effective_from=SOURCE_EFFECTIVE_FROM,
        )
        middle = WINDOW_START + timedelta(hours=12)
        observation = signed_observation(
            source,
            secret,
            1,
            value=410.0,
            observed_at=middle,
            interval_start=WINDOW_START,
            interval_end=middle,
        )

        prepared = GovernanceService(
            repository,
            lambda _: secret,
        ).prepare(governed_request(profile, [observation]))

        assert prepared.accepted_count == 1
        assert prepared.rejected_count == 0
        assert prepared.request is None
        assert any(
            issue.code == "aggregation_insufficient_coverage"
            and issue.blocking
            and issue.details["coverage_ratio"] == 0.5
            for issue in prepared.quality_issues
        )
    finally:
        repository.close()


def test_interval_event_time_cannot_select_a_future_source_version() -> None:
    repository = GovernanceRepository()
    profile = make_profile(
        required_metrics=[MetricCode.REPORTED_PRODUCTION]
    )
    original = make_source(
        MetricCode.REPORTED_PRODUCTION,
        1,
        source_id="interval-source",
        measurement_type=MeasurementType.INTERVAL_DELTA,
        expected_interval_seconds=24 * 3600,
    )
    future = original.model_copy(
        update={"tolerance_abs": original.tolerance_abs * 100}
    )
    secret = b"interval-secret"
    try:
        repository.register_profile(profile)
        repository.register_source(
            original,
            version=1,
            effective_from=SOURCE_EFFECTIVE_FROM,
            effective_to=WINDOW_END + timedelta(days=1),
        )
        repository.register_source(
            future,
            version=2,
            effective_from=WINDOW_END + timedelta(days=1),
        )
        observation = signed_observation(
            original,
            secret,
            1,
            observed_at=WINDOW_END + timedelta(days=10),
            received_at=WINDOW_END + timedelta(days=10, seconds=10),
            interval_start=WINDOW_START,
            interval_end=WINDOW_END,
        )

        prepared = GovernanceService(
            repository,
            lambda _: secret,
        ).prepare(governed_request(profile, [observation]))

        assert prepared.accepted_count == 0
        assert prepared.request is None
        outside = next(
            issue
            for issue in prepared.quality_issues
            if issue.code == "outside_analysis_window"
        )
        assert outside.blocking
        assert outside.details["source_version"] == 1
    finally:
        repository.close()


def test_revision_chain_locks_business_identity_and_interval() -> None:
    repository = GovernanceRepository()
    profile = make_profile(
        required_metrics=[MetricCode.REPORTED_PRODUCTION]
    )
    source = make_source(MetricCode.REPORTED_PRODUCTION, 1)
    revision_zero = signed_observation(
        source,
        b"secret",
        1,
        sequence_no=91,
        observation_id="logical-A",
    )
    revision_one = sign_observation(
        revision_zero.model_copy(
            update={
                "observation_id": "entirely-B",
                "revision": 1,
                "value": revision_zero.value + 99,
                "received_at": revision_zero.received_at
                + timedelta(minutes=1),
            }
        ),
        b"secret",
    )
    try:
        repository.register_profile(profile)
        repository.register_source(
            source,
            effective_from=SOURCE_EFFECTIVE_FROM,
        )
        prepared = GovernanceService(
            repository,
            lambda _: b"secret",
        ).prepare(
            governed_request(profile, [revision_zero, revision_one])
        )

        assert prepared.accepted_count == 1
        assert prepared.request is not None
        assert prepared.request.observations[0].observation_id == "logical-A"
        assert any(
            issue.code == "revision_identity_mismatch" and issue.blocking
            for issue in prepared.quality_issues
        )
        assert [
            item.observation_id
            for item in repository.list_observation_revisions(
                source.source_id,
                91,
            )
        ] == ["logical-A"]
    finally:
        repository.close()


def test_cumulative_register_requires_and_honours_explicit_reset() -> None:
    repository = GovernanceRepository()
    source = make_source(
        MetricCode.RAW_SALES,
        1,
        source_id="sales-register",
        measurement_type=MeasurementType.CUMULATIVE_REGISTER,
    )
    profile = make_profile(required_metrics=[MetricCode.RAW_SALES])
    secret = b"register-secret"
    try:
        repository.register_profile(profile)
        repository.register_source(
            source,
            effective_from=SOURCE_EFFECTIVE_FROM,
        )
        observations = [
            signed_observation(
                source,
                secret,
                1,
                value=90.0,
                observed_at=WINDOW_START,
            ),
            signed_observation(
                source,
                secret,
                2,
                value=10.0,
                observed_at=WINDOW_START + timedelta(hours=12),
                reset_before=True,
            ),
            signed_observation(
                source,
                secret,
                3,
                value=50.0,
                observed_at=WINDOW_END,
            ),
        ]

        prepared = GovernanceService(
            repository,
            lambda _: secret,
        ).prepare(governed_request(profile, observations))

        assert prepared.request is not None
        assert prepared.request.observations[0].value == 50.0
        assert not any(issue.blocking for issue in prepared.quality_issues)
    finally:
        repository.close()


def test_v1_signature_payload_stays_compatible_and_new_fields_are_signed() -> None:
    source = make_source(MetricCode.REPORTED_PRODUCTION, 1)
    legacy = signed_observation(source, b"secret", 1)

    payload = observation_payload(legacy)
    assert "interval_start" not in payload
    assert "interval_end" not in payload
    assert "reset_before" not in payload

    enhanced = signed_observation(
        source,
        b"secret",
        2,
        interval_start=WINDOW_START,
        interval_end=WINDOW_END,
        reset_before=True,
    )
    enhanced_payload = observation_payload(enhanced)
    encoded = enhanced.model_dump(mode="json")
    assert enhanced_payload["interval_start"] == encoded["interval_start"]
    assert enhanced_payload["interval_end"] == encoded["interval_end"]
    assert enhanced_payload["reset_before"] is True

    tampered = enhanced.model_copy(update={"reset_before": False})
    assert tampered.payload_sha256 != compute_payload_sha256(tampered)
    assert tampered.signature != compute_observation_signature(
        tampered,
        b"secret",
    )
    assert observation_payload(tampered) != enhanced_payload


def test_unapproved_and_out_of_period_profiles_cannot_run() -> None:
    source = make_source(MetricCode.REPORTED_PRODUCTION, 1)
    observation = signed_observation(source, b"secret", 1)

    unapproved_repository = GovernanceRepository()
    unapproved = make_profile(
        required_metrics=[MetricCode.REPORTED_PRODUCTION],
        approved=False,
    )
    unapproved_repository.register_profile(unapproved)
    unapproved_repository.register_source(
        source,
        effective_from=SOURCE_EFFECTIVE_FROM,
    )
    try:
        with pytest.raises(ProfileNotApprovedError):
            GovernanceService(
                unapproved_repository,
                lambda _: b"secret",
            ).prepare(governed_request(unapproved, [observation]))
    finally:
        unapproved_repository.close()

    expiring_repository = GovernanceRepository()
    expiring = make_profile(
        required_metrics=[MetricCode.REPORTED_PRODUCTION],
        effective_to=WINDOW_START + timedelta(hours=12),
    )
    expiring_repository.register_profile(expiring)
    expiring_repository.register_source(
        source,
        effective_from=SOURCE_EFFECTIVE_FROM,
    )
    try:
        with pytest.raises(ProfileNotEffectiveError):
            GovernanceService(
                expiring_repository,
                lambda _: b"secret",
            ).prepare(governed_request(expiring, [observation]))
    finally:
        expiring_repository.close()


def test_registry_snapshot_and_derived_request_are_deterministic(
    tmp_path: Path,
) -> None:
    outputs = []
    for index in range(2):
        database = tmp_path / f"governance-{index}.sqlite3"
        repository = GovernanceRepository(database)
        try:
            profile, sources, secrets = register_baseline(repository)
            observations = [
                signed_observation(
                    source,
                    secrets[source.source_id],
                    item_index,
                )
                for item_index, source in enumerate(sources, start=1)
            ]
            if index:
                observations.reverse()
            prepared = GovernanceService(
                repository,
                secrets.get,
            ).prepare(governed_request(profile, observations))
            outputs.append(
                (
                    prepared.registry_snapshot_hash,
                    prepared.request.model_dump(mode="json")
                    if prepared.request is not None
                    else None,
                )
            )
        finally:
            repository.close()

    assert outputs[0] == outputs[1]

    connection = sqlite3.connect(tmp_path / "governance-0.sqlite3")
    try:
        schema = " ".join(
            row[0] or ""
            for row in connection.execute(
                "SELECT sql FROM sqlite_master WHERE sql IS NOT NULL"
            )
        ).lower()
    finally:
        connection.close()
    assert "secret" not in schema
