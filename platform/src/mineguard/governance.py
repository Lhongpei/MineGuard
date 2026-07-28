"""可信来源注册、签名观测接入和服务端分析请求构造。

受治理入口只接受原始观测信封。来源组、容差、可靠性、质量信号和分析参数
全部由服务端注册表与已审批配置派生，调用方无法通过请求覆盖这些字段。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Annotated, Any, Literal, Self

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    model_validator,
)

from .aggregation import (
    AggregationRequest,
    AggregationResult,
    MAX_ABSOLUTE_MEASUREMENT_VALUE,
    MAX_TIME_SCALE_SECONDS,
    MIN_TIME_SCALE_SECONDS,
    MeasurementType,
    SeriesObservation,
    aggregate_measurements,
)
from .models import (
    BalanceParameters,
    MAX_ABSOLUTE_METRIC_VALUE,
    MAX_RELATIVE_TOLERANCE,
    MIN_EFFECTIVE_TOLERANCE,
    MetricCode,
    MetricObservation,
    ProductionAnalysisRequest,
    QualitySignals,
    StrictModel,
)
from .historical import OperationalContext


_SIGNING_CONTEXT = b"MINEGUARD-GOVERNED-OBSERVATION-V1\x00"
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


class GovernanceModel(StrictModel):
    """Immutable, non-coercing base model for the governance boundary."""

    model_config = ConfigDict(
        extra="forbid",
        allow_inf_nan=False,
        str_strip_whitespace=True,
        strict=True,
        frozen=True,
    )


class SourceDefinition(GovernanceModel):
    source_id: Annotated[str, Field(min_length=1, max_length=128)]
    mine_id: Annotated[str, Field(min_length=1, max_length=128)]
    metric_code: MetricCode
    root_source_group: Annotated[str, Field(min_length=1, max_length=128)]
    unit: Annotated[str, Field(min_length=1, max_length=32)] = "t"
    tolerance_abs: Annotated[
        float,
        Field(
            ge=MIN_EFFECTIVE_TOLERANCE,
            le=MAX_ABSOLUTE_METRIC_VALUE,
        ),
    ]
    tolerance_rel: Annotated[
        float,
        Field(ge=0, le=MAX_RELATIVE_TOLERANCE),
    ] = 0.0
    resolution: Annotated[
        float,
        Field(ge=0, le=MAX_ABSOLUTE_METRIC_VALUE),
    ] = 0.0
    reliability: Annotated[float, Field(gt=0, le=1)]
    dependency_domains: list[
        Annotated[str, Field(min_length=1, max_length=128)]
    ] = Field(default_factory=list)
    physical_node_id: Annotated[
        str,
        Field(min_length=1, max_length=128),
    ] | None = None
    physical_edge_id: Annotated[
        str,
        Field(min_length=1, max_length=128),
    ] | None = None
    material_type: Annotated[
        str,
        Field(min_length=1, max_length=128),
    ] = "raw_coal"
    measurement_type: MeasurementType = MeasurementType.WINDOW_TOTAL
    expected_interval_seconds: Annotated[
        float,
        Field(
            ge=MIN_TIME_SCALE_SECONDS,
            le=MAX_TIME_SCALE_SECONDS,
        ),
    ] | None = None
    min_coverage: Annotated[float, Field(gt=0, le=1)] = 0.9
    max_boundary_staleness_seconds: Annotated[
        float,
        Field(ge=0, le=MAX_TIME_SCALE_SECONDS),
    ] = 0.0
    register_modulus: Annotated[
        float,
        Field(gt=0, le=MAX_ABSOLUTE_MEASUREMENT_VALUE),
    ] | None = None
    rate_time_unit_seconds: Annotated[
        float,
        Field(
            ge=MIN_TIME_SCALE_SECONDS,
            le=MAX_TIME_SCALE_SECONDS,
        ),
    ] = 3600.0
    max_delay_seconds: Annotated[
        float,
        Field(ge=0, le=MAX_TIME_SCALE_SECONDS),
    ]
    device_health_score: Annotated[
        float,
        Field(ge=0, le=1),
    ] | None = None
    clock_quality_score: Annotated[
        float,
        Field(ge=0, le=1),
    ] | None = None
    calibration_valid_until: AwareDatetime
    active: bool = True

    @model_validator(mode="after")
    def validate_measurement_governance(self) -> "SourceDefinition":
        if len(self.dependency_domains) != len(
            set(self.dependency_domains)
        ):
            raise ValueError("dependency_domains values must be unique")
        if (
            self.physical_node_id is not None
            and self.physical_edge_id is not None
        ):
            raise ValueError(
                "a source cannot map to both a physical node and edge"
            )
        if (
            self.measurement_type
            is not MeasurementType.CUMULATIVE_REGISTER
            and self.register_modulus is not None
        ):
            raise ValueError(
                "register_modulus is only valid for cumulative_register"
            )
        return self


class AnalysisProfile(GovernanceModel):
    profile_id: Annotated[str, Field(min_length=1, max_length=128)]
    version: Annotated[str, Field(min_length=1, max_length=64)]
    effective_from: AwareDatetime
    effective_to: AwareDatetime | None = None
    parameters: BalanceParameters
    required_metrics: list[MetricCode]
    approved: bool

    @model_validator(mode="after")
    def validate_profile(self) -> "AnalysisProfile":
        if (
            self.effective_to is not None
            and self.effective_to <= self.effective_from
        ):
            raise ValueError("effective_to must be later than effective_from")
        if not self.required_metrics:
            raise ValueError("required_metrics must not be empty")
        if len(self.required_metrics) != len(set(self.required_metrics)):
            raise ValueError("required_metrics values must be unique")
        return self


class GovernedObservation(GovernanceModel):
    source_id: Annotated[str, Field(min_length=1, max_length=128)]
    observation_id: Annotated[str, Field(min_length=1, max_length=256)]
    value: Annotated[
        float,
        Field(
            ge=-MAX_ABSOLUTE_MEASUREMENT_VALUE,
            le=MAX_ABSOLUTE_MEASUREMENT_VALUE,
        ),
    ]
    unit: Annotated[str, Field(min_length=1, max_length=32)]
    observed_at: AwareDatetime
    received_at: AwareDatetime
    interval_start: AwareDatetime | None = None
    interval_end: AwareDatetime | None = None
    reset_before: bool = False
    sequence_no: Annotated[int, Field(ge=0)]
    revision: Annotated[int, Field(ge=0)]
    payload_sha256: Annotated[str, Field(min_length=64, max_length=64)]
    signature: Annotated[str, Field(min_length=1, max_length=256)]

    @model_validator(mode="after")
    def validate_interval(self) -> "GovernedObservation":
        if (self.interval_start is None) != (self.interval_end is None):
            raise ValueError(
                "interval_start and interval_end must be supplied together"
            )
        if (
            self.interval_start is not None
            and self.interval_end is not None
            and self.interval_end <= self.interval_start
        ):
            raise ValueError("interval_end must be later than interval_start")
        return self

    @classmethod
    def signed(
        cls,
        *,
        secret: bytes | str,
        **data: Any,
    ) -> Self:
        """Construct a correctly hashed and HMAC-authenticated observation."""

        draft = cls(
            **data,
            payload_sha256="0" * 64,
            signature="pending",
        )
        return sign_observation(draft, secret)


class GovernedProductionRequest(GovernanceModel):
    mine_id: Annotated[str, Field(min_length=1, max_length=128)]
    window_start: AwareDatetime
    window_end: AwareDatetime
    profile_id: Annotated[str, Field(min_length=1, max_length=128)]
    profile_version: Annotated[str, Field(min_length=1, max_length=64)]
    operational_context: OperationalContext = Field(
        default_factory=OperationalContext
    )
    observations: list[GovernedObservation]

    @model_validator(mode="after")
    def validate_window(self) -> "GovernedProductionRequest":
        if self.window_end <= self.window_start:
            raise ValueError("window_end must be later than window_start")
        if not self.observations:
            raise ValueError("observations must not be empty")
        return self


class QualityIssue(GovernanceModel):
    code: Annotated[str, Field(min_length=1, max_length=128)]
    severity: Literal["blocking", "warning"]
    message: Annotated[str, Field(min_length=1, max_length=1000)]
    source_id: str | None = None
    observation_id: str | None = None
    details: dict[str, str | int | float | bool | None] = Field(
        default_factory=dict
    )

    @property
    def blocking(self) -> bool:
        return self.severity == "blocking"


class PreparedAnalysis(GovernanceModel):
    request: ProductionAnalysisRequest | None
    profile_version: str
    registry_snapshot_hash: Annotated[
        str,
        Field(min_length=64, max_length=64),
    ]
    quality_issues: list[QualityIssue] = Field(default_factory=list)
    accepted_count: Annotated[int, Field(ge=0)]
    rejected_count: Annotated[int, Field(ge=0)]


class GovernanceError(RuntimeError):
    """Base error for trusted configuration and persistence operations."""


class ConfigurationConflictError(GovernanceError):
    """An immutable configuration key was reused with different content."""


class SourceNotFoundError(GovernanceError):
    """No source definition is effective for the requested instant."""


class ProfileNotFoundError(GovernanceError):
    """No requested analysis profile exists."""


class ProfileNotEffectiveError(GovernanceError):
    """The requested profile does not cover the analysis window."""


class ProfileNotApprovedError(GovernanceError):
    """An unapproved profile cannot construct an analysis request."""


def _json_default(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    item = getattr(value, "item", None)
    if callable(item):
        return item()
    raise TypeError(f"{type(value).__name__} is not JSON serializable")


def canonical_json(value: Any) -> str:
    """Return the deterministic JSON representation used by every digest."""

    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=_json_default,
    )


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def observation_payload(observation: GovernedObservation) -> dict[str, Any]:
    """Return exactly the business fields covered by the payload digest."""

    return observation.model_dump(
        mode="json",
        exclude={"payload_sha256", "signature"},
        # Newly introduced optional measurement fields must not invalidate
        # signatures created by the V1 envelope when they retain defaults.
        exclude_defaults=True,
    )


def compute_payload_sha256(observation: GovernedObservation) -> str:
    return sha256_json(observation_payload(observation))


def _secret_bytes(secret: bytes | str) -> bytes:
    if isinstance(secret, str):
        encoded = secret.encode("utf-8")
    elif isinstance(secret, bytes):
        encoded = secret
    else:
        raise TypeError("HMAC secret must be bytes or str")
    if not encoded:
        raise ValueError("HMAC secret must not be empty")
    return encoded


def compute_observation_signature(
    observation: GovernedObservation,
    secret: bytes | str,
) -> str:
    """Calculate HMAC over the payload plus its declared SHA-256 digest."""

    envelope = {
        "payload": observation_payload(observation),
        "payload_sha256": observation.payload_sha256,
    }
    material = _SIGNING_CONTEXT + canonical_json(envelope).encode("utf-8")
    return hmac.new(
        _secret_bytes(secret),
        material,
        hashlib.sha256,
    ).hexdigest()


def sign_observation(
    observation: GovernedObservation,
    secret: bytes | str,
) -> GovernedObservation:
    payload_hash = compute_payload_sha256(observation)
    with_hash = observation.model_copy(
        update={"payload_sha256": payload_hash}
    )
    return with_hash.model_copy(
        update={
            "signature": compute_observation_signature(with_hash, secret)
        }
    )


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("datetime must include timezone information")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _now_text() -> str:
    return _utc_text(datetime.now(UTC))


@dataclass(frozen=True)
class _SourceSnapshot:
    definition: SourceDefinition
    version: int
    effective_from: str
    effective_to: str | None
    definition_sha256: str

    def manifest(self) -> dict[str, Any]:
        return {
            "source_id": self.definition.source_id,
            "version": self.version,
            "effective_from": self.effective_from,
            "effective_to": self.effective_to,
            "definition_sha256": self.definition_sha256,
        }


@dataclass(frozen=True)
class _ProfileSnapshot:
    profile: AnalysisProfile
    definition_sha256: str

    def manifest(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile.profile_id,
            "version": self.profile.version,
            "definition_sha256": self.definition_sha256,
        }


ObservationWriteStatus = Literal["inserted", "duplicate", "conflict"]


class GovernanceRepository:
    """Thread-safe, append-only SQLite store for trusted local configuration."""

    def __init__(self, database_path: str | Path = ":memory:") -> None:
        self.database_path = str(database_path)
        if self.database_path != ":memory:":
            database_file = Path(self.database_path).expanduser().resolve()
            database_file.parent.mkdir(
                parents=True,
                exist_ok=True,
                mode=0o700,
            )
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(
            self.database_path,
            check_same_thread=False,
            timeout=10,
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        if self.database_path != ":memory:":
            self._connection.execute("PRAGMA journal_mode = WAL")
        self._initialize_schema()
        if self.database_path != ":memory:":
            try:
                Path(self.database_path).chmod(0o600)
            except OSError:
                pass

    def _initialize_schema(self) -> None:
        schema = """
        CREATE TABLE IF NOT EXISTS source_definitions (
            source_id TEXT NOT NULL,
            version INTEGER NOT NULL,
            effective_from TEXT NOT NULL,
            effective_to TEXT,
            definition_sha256 TEXT NOT NULL,
            definition_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY(source_id, version)
        );

        CREATE INDEX IF NOT EXISTS idx_source_effective
            ON source_definitions(source_id, effective_from, effective_to);

        CREATE TABLE IF NOT EXISTS analysis_profiles (
            profile_id TEXT NOT NULL,
            version TEXT NOT NULL,
            effective_from TEXT NOT NULL,
            effective_to TEXT,
            approved INTEGER NOT NULL,
            definition_sha256 TEXT NOT NULL,
            definition_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY(profile_id, version)
        );

        CREATE INDEX IF NOT EXISTS idx_profile_effective
            ON analysis_profiles(profile_id, effective_from, effective_to);

        CREATE TABLE IF NOT EXISTS governed_observations (
            source_id TEXT NOT NULL,
            sequence_no INTEGER NOT NULL,
            revision INTEGER NOT NULL,
            observation_id TEXT NOT NULL,
            observed_at TEXT NOT NULL,
            received_at TEXT NOT NULL,
            envelope_sha256 TEXT NOT NULL,
            envelope_json TEXT NOT NULL,
            ingested_at TEXT NOT NULL,
            PRIMARY KEY(source_id, sequence_no, revision)
        );

        CREATE INDEX IF NOT EXISTS idx_observation_record
            ON governed_observations(source_id, sequence_no, revision);
        """
        with self._lock, self._connection:
            self._connection.executescript(schema)

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def register_source(
        self,
        definition: SourceDefinition,
        *,
        version: int = 1,
        effective_from: datetime = _EPOCH,
        effective_to: datetime | None = None,
    ) -> bool:
        """Insert an immutable source version; return False for exact retry."""

        if not isinstance(definition, SourceDefinition):
            raise TypeError("definition must be a SourceDefinition")
        if type(version) is not int or version < 1:
            raise ValueError("source version must be a positive integer")
        start = _utc_text(effective_from)
        end = _utc_text(effective_to) if effective_to is not None else None
        if end is not None and end <= start:
            raise ValueError("effective_to must be later than effective_from")
        record = {
            "definition": definition,
            "version": version,
            "effective_from": start,
            "effective_to": end,
        }
        digest = sha256_json(record)
        encoded = canonical_json(definition)

        with self._lock, self._connection:
            existing = self._connection.execute(
                "SELECT definition_sha256 FROM source_definitions "
                "WHERE source_id = ? AND version = ?",
                (definition.source_id, version),
            ).fetchone()
            if existing is not None:
                if existing["definition_sha256"] == digest:
                    return False
                raise ConfigurationConflictError(
                    "source_id and version already exist with different content"
                )
            self._connection.execute(
                """
                INSERT INTO source_definitions (
                    source_id, version, effective_from, effective_to,
                    definition_sha256, definition_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    definition.source_id,
                    version,
                    start,
                    end,
                    digest,
                    encoded,
                    _now_text(),
                ),
            )
        return True

    def _source_snapshot(
        self,
        source_id: str,
        *,
        as_of: datetime,
        version: int | None = None,
    ) -> _SourceSnapshot:
        instant = _utc_text(as_of)
        if version is None:
            sql = (
                "SELECT * FROM source_definitions "
                "WHERE source_id = ? AND effective_from <= ? "
                "AND (effective_to IS NULL OR ? < effective_to) "
                "ORDER BY effective_from DESC, version DESC LIMIT 1"
            )
            parameters: tuple[Any, ...] = (source_id, instant, instant)
        else:
            sql = (
                "SELECT * FROM source_definitions "
                "WHERE source_id = ? AND version = ? "
                "AND effective_from <= ? "
                "AND (effective_to IS NULL OR ? < effective_to)"
            )
            parameters = (source_id, version, instant, instant)
        with self._lock:
            row = self._connection.execute(sql, parameters).fetchone()
        if row is None:
            raise SourceNotFoundError(
                f"no effective source definition for {source_id}"
            )
        return _SourceSnapshot(
            definition=SourceDefinition.model_validate_json(
                row["definition_json"]
            ),
            version=int(row["version"]),
            effective_from=str(row["effective_from"]),
            effective_to=(
                str(row["effective_to"])
                if row["effective_to"] is not None
                else None
            ),
            definition_sha256=str(row["definition_sha256"]),
        )

    def get_source(
        self,
        source_id: str,
        *,
        as_of: datetime,
        version: int | None = None,
    ) -> SourceDefinition:
        return self._source_snapshot(
            source_id,
            as_of=as_of,
            version=version,
        ).definition

    def list_source_versions(
        self,
        source_id: str,
    ) -> list[tuple[int, SourceDefinition]]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT version, definition_json FROM source_definitions "
                "WHERE source_id = ? ORDER BY version",
                (source_id,),
            ).fetchall()
        return [
            (
                int(row["version"]),
                SourceDefinition.model_validate_json(row["definition_json"]),
            )
            for row in rows
        ]

    def list_sources(self) -> list[dict[str, Any]]:
        """Return every immutable source version without any signing key."""

        with self._lock:
            rows = self._connection.execute(
                "SELECT version, effective_from, effective_to, "
                "definition_sha256, definition_json "
                "FROM source_definitions "
                "ORDER BY source_id, version"
            ).fetchall()
        return [
            {
                "version": int(row["version"]),
                "effective_from": str(row["effective_from"]),
                "effective_to": (
                    str(row["effective_to"])
                    if row["effective_to"] is not None
                    else None
                ),
                "definition_sha256": str(row["definition_sha256"]),
                "definition": SourceDefinition.model_validate_json(
                    row["definition_json"]
                ),
            }
            for row in rows
        ]

    def register_profile(self, profile: AnalysisProfile) -> bool:
        """Insert an immutable profile version; return False for exact retry."""

        if not isinstance(profile, AnalysisProfile):
            raise TypeError("profile must be an AnalysisProfile")
        digest = sha256_json(profile)
        encoded = canonical_json(profile)
        with self._lock, self._connection:
            existing = self._connection.execute(
                "SELECT definition_sha256 FROM analysis_profiles "
                "WHERE profile_id = ? AND version = ?",
                (profile.profile_id, profile.version),
            ).fetchone()
            if existing is not None:
                if existing["definition_sha256"] == digest:
                    return False
                raise ConfigurationConflictError(
                    "profile_id and version already exist with different content"
                )
            self._connection.execute(
                """
                INSERT INTO analysis_profiles (
                    profile_id, version, effective_from, effective_to,
                    approved, definition_sha256, definition_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    profile.profile_id,
                    profile.version,
                    _utc_text(profile.effective_from),
                    (
                        _utc_text(profile.effective_to)
                        if profile.effective_to is not None
                        else None
                    ),
                    int(profile.approved),
                    digest,
                    encoded,
                    _now_text(),
                ),
            )
        return True

    def _profile_snapshot(
        self,
        profile_id: str,
        *,
        version: str | None = None,
        as_of: datetime,
    ) -> _ProfileSnapshot:
        instant = _utc_text(as_of)
        if version is None:
            sql = (
                "SELECT * FROM analysis_profiles "
                "WHERE profile_id = ? AND effective_from <= ? "
                "AND (effective_to IS NULL OR ? < effective_to) "
                "ORDER BY effective_from DESC, rowid DESC LIMIT 1"
            )
            parameters: tuple[Any, ...] = (profile_id, instant, instant)
        else:
            sql = (
                "SELECT * FROM analysis_profiles "
                "WHERE profile_id = ? AND version = ? "
                "AND effective_from <= ? "
                "AND (effective_to IS NULL OR ? < effective_to)"
            )
            parameters = (profile_id, version, instant, instant)
        with self._lock:
            row = self._connection.execute(sql, parameters).fetchone()
        if row is None:
            raise ProfileNotFoundError(
                f"no effective profile for {profile_id}"
            )
        return _ProfileSnapshot(
            profile=AnalysisProfile.model_validate_json(
                row["definition_json"]
            ),
            definition_sha256=str(row["definition_sha256"]),
        )

    def get_profile(
        self,
        profile_id: str,
        *,
        version: str | None = None,
        as_of: datetime,
    ) -> AnalysisProfile:
        return self._profile_snapshot(
            profile_id,
            version=version,
            as_of=as_of,
        ).profile

    def list_profiles(self) -> list[dict[str, Any]]:
        """Return every immutable analysis-profile version."""

        with self._lock:
            rows = self._connection.execute(
                "SELECT definition_sha256, definition_json "
                "FROM analysis_profiles "
                "ORDER BY profile_id, effective_from, version"
            ).fetchall()
        return [
            {
                "definition_sha256": str(row["definition_sha256"]),
                "profile": AnalysisProfile.model_validate_json(
                    row["definition_json"]
                ),
            }
            for row in rows
        ]

    def ingest_observation(
        self,
        observation: GovernedObservation,
    ) -> ObservationWriteStatus:
        """Persist every unique revision without updating earlier revisions."""

        if not isinstance(observation, GovernedObservation):
            raise TypeError("observation must be a GovernedObservation")
        envelope_hash = sha256_json(observation)
        encoded = canonical_json(observation)
        key = (
            observation.source_id,
            observation.sequence_no,
            observation.revision,
        )
        with self._lock, self._connection:
            existing = self._connection.execute(
                "SELECT envelope_sha256 FROM governed_observations "
                "WHERE source_id = ? AND sequence_no = ? AND revision = ?",
                key,
            ).fetchone()
            if existing is not None:
                return (
                    "duplicate"
                    if existing["envelope_sha256"] == envelope_hash
                    else "conflict"
                )
            self._connection.execute(
                """
                INSERT INTO governed_observations (
                    source_id, sequence_no, revision, observation_id,
                    observed_at, received_at, envelope_sha256,
                    envelope_json, ingested_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    *key,
                    observation.observation_id,
                    _utc_text(observation.observed_at),
                    _utc_text(observation.received_at),
                    envelope_hash,
                    encoded,
                    _now_text(),
                ),
            )
        return "inserted"

    def has_observation_revision(
        self,
        source_id: str,
        sequence_no: int,
        revision: int,
    ) -> bool:
        with self._lock:
            row = self._connection.execute(
                "SELECT 1 FROM governed_observations "
                "WHERE source_id = ? AND sequence_no = ? AND revision = ?",
                (source_id, sequence_no, revision),
            ).fetchone()
        return row is not None

    def latest_observation_revision(
        self,
        source_id: str,
        sequence_no: int,
    ) -> int | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT MAX(revision) AS revision FROM governed_observations "
                "WHERE source_id = ? AND sequence_no = ?",
                (source_id, sequence_no),
            ).fetchone()
        if row is None or row["revision"] is None:
            return None
        return int(row["revision"])

    def list_observation_revisions(
        self,
        source_id: str,
        sequence_no: int,
    ) -> list[GovernedObservation]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT envelope_json FROM governed_observations "
                "WHERE source_id = ? AND sequence_no = ? ORDER BY revision",
                (source_id, sequence_no),
            ).fetchall()
        return [
            GovernedObservation.model_validate_json(row["envelope_json"])
            for row in rows
        ]


SecretResolver = Callable[[str], bytes | str | None]


@dataclass(frozen=True)
class _Candidate:
    input_index: int
    observation: GovernedObservation
    source: _SourceSnapshot
    late: bool


def _issue(
    code: str,
    severity: Literal["blocking", "warning"],
    message: str,
    observation: GovernedObservation | None = None,
    **details: str | int | float | bool | None,
) -> QualityIssue:
    return QualityIssue(
        code=code,
        severity=severity,
        message=message,
        source_id=(
            observation.source_id if observation is not None else None
        ),
        observation_id=(
            observation.observation_id if observation is not None else None
        ),
        details=details,
    )


def _issue_key(issue: QualityIssue) -> tuple[str, str, str, str]:
    return (
        issue.observation_id or "",
        issue.source_id or "",
        issue.code,
        canonical_json(issue.details),
    )


def _observation_matches_window(
    observation: GovernedObservation,
    source: SourceDefinition,
    request: GovernedProductionRequest,
) -> bool:
    """Apply measurement-type-specific event-time boundary rules."""

    if source.measurement_type is MeasurementType.INTERVAL_DELTA:
        return bool(
            observation.interval_start is not None
            and observation.interval_end is not None
            and observation.interval_start >= request.window_start
            and observation.interval_end <= request.window_end
            and observation.interval_start
            <= observation.observed_at
            <= observation.interval_end
        )
    if source.measurement_type in {
        MeasurementType.CUMULATIVE_REGISTER,
        MeasurementType.SNAPSHOT,
        MeasurementType.INSTANTANEOUS_RATE,
    }:
        grace = timedelta(
            seconds=source.max_boundary_staleness_seconds
        )
        return (
            request.window_start - grace
            <= observation.observed_at
            <= request.window_end + grace
        )
    return (
        request.window_start
        <= observation.observed_at
        < request.window_end
    )


def _source_reference_time(
    observation: GovernedObservation,
) -> datetime:
    """Choose a source-version instant that cannot be moved into the future.

    Interval readings describe the signed business interval, so their source
    definition is resolved at the beginning of that interval.  The separately
    signed ``observed_at`` still has to fall inside the interval below.
    """

    return observation.interval_start or observation.observed_at


def _aggregate_candidates(
    request: GovernedProductionRequest,
    candidates: list[_Candidate],
) -> tuple[
    list[tuple[_SourceSnapshot, list[_Candidate], AggregationResult]],
    list[QualityIssue],
]:
    grouped: dict[
        tuple[str, int, str],
        list[_Candidate],
    ] = {}
    for candidate in candidates:
        snapshot = candidate.source
        key = (
            snapshot.definition.source_id,
            snapshot.version,
            snapshot.definition_sha256,
        )
        grouped.setdefault(key, []).append(candidate)

    aggregates: list[
        tuple[_SourceSnapshot, list[_Candidate], AggregationResult]
    ] = []
    issues: list[QualityIssue] = []
    for key in sorted(grouped):
        source_candidates = sorted(
            grouped[key],
            key=lambda item: (
                item.observation.observed_at,
                item.observation.sequence_no,
                item.observation.revision,
                item.observation.observation_id,
            ),
        )
        snapshot = source_candidates[0].source
        source = snapshot.definition
        aggregation = aggregate_measurements(
            AggregationRequest(
                measurement_type=source.measurement_type,
                window_start=request.window_start,
                window_end=request.window_end,
                observations=[
                    SeriesObservation(
                        observation_id=item.observation.observation_id,
                        value=item.observation.value,
                        observed_at=item.observation.observed_at,
                        interval_start=item.observation.interval_start,
                        interval_end=item.observation.interval_end,
                        sequence_no=item.observation.sequence_no,
                        reset_before=item.observation.reset_before,
                    )
                    for item in source_candidates
                ],
                min_coverage=source.min_coverage,
                expected_interval_seconds=(
                    source.expected_interval_seconds
                ),
                max_boundary_staleness_seconds=(
                    source.max_boundary_staleness_seconds
                ),
                register_modulus=source.register_modulus,
                rate_time_unit_seconds=source.rate_time_unit_seconds,
            )
        )
        aggregates.append((snapshot, source_candidates, aggregation))
        representative = source_candidates[0].observation
        for aggregation_issue in aggregation.issues:
            issues.append(
                _issue(
                    f"aggregation_{aggregation_issue.code}",
                    aggregation_issue.severity,
                    aggregation_issue.message,
                    representative,
                    measurement_type=source.measurement_type.value,
                    coverage_ratio=aggregation.coverage_ratio,
                    contributing_count=len(source_candidates),
                )
            )
    return aggregates, issues


class GovernanceService:
    """Validate governed envelopes and construct the internal analysis request."""

    def __init__(
        self,
        repository: GovernanceRepository,
        secret_resolver: SecretResolver,
    ) -> None:
        self.repository = repository
        self.secret_resolver = secret_resolver

    def prepare(
        self,
        request: GovernedProductionRequest,
    ) -> PreparedAnalysis:
        if not isinstance(request, GovernedProductionRequest):
            raise TypeError("request must be a GovernedProductionRequest")

        profile_snapshot = self.repository._profile_snapshot(
            request.profile_id,
            version=request.profile_version,
            as_of=request.window_start,
        )
        profile = profile_snapshot.profile
        if not profile.approved:
            raise ProfileNotApprovedError(
                "analysis profile must be approved before use"
            )
        if (
            profile.effective_to is not None
            and request.window_end > profile.effective_to
        ):
            raise ProfileNotEffectiveError(
                "analysis window extends beyond profile effective_to"
            )

        issues: list[QualityIssue] = []
        candidates: list[_Candidate] = []
        source_snapshots: dict[
            tuple[str, int, str],
            _SourceSnapshot,
        ] = {}
        unknown_sources: set[str] = set()
        logical_ids: dict[str, tuple[str, int]] = {}
        seen_revision_keys: set[tuple[str, int, int]] = set()

        indexed = sorted(
            enumerate(request.observations),
            key=lambda pair: (
                pair[1].source_id,
                pair[1].sequence_no,
                pair[1].revision,
                pair[1].observation_id,
                sha256_json(pair[1]),
            ),
        )
        for input_index, observation in indexed:
            blocking_before = len(
                [issue for issue in issues if issue.blocking]
            )

            try:
                source_snapshot = self.repository._source_snapshot(
                    observation.source_id,
                    as_of=_source_reference_time(observation),
                )
            except SourceNotFoundError:
                unknown_sources.add(observation.source_id)
                issues.append(
                    _issue(
                        "unknown_source",
                        "blocking",
                        "观测来源未注册或在观测时刻未生效",
                        observation,
                    )
                )
                source_snapshot = None
            if source_snapshot is not None:
                source = source_snapshot.definition
                source_snapshots[
                    (
                        source.source_id,
                        source_snapshot.version,
                        source_snapshot.definition_sha256,
                    )
                ] = source_snapshot
                if source.mine_id != request.mine_id:
                    issues.append(
                        _issue(
                            "source_mine_mismatch",
                            "blocking",
                            "来源注册矿井与分析矿井不一致",
                            observation,
                            registered_mine_id=source.mine_id,
                            requested_mine_id=request.mine_id,
                        )
                    )
                if (
                    observation.interval_end is not None
                    and source_snapshot.effective_to is not None
                    and _utc_text(observation.interval_end)
                    > source_snapshot.effective_to
                ):
                    issues.append(
                        _issue(
                            "source_version_changes_within_interval",
                            "blocking",
                            "计量区间跨越来源定义版本边界，不能套用单一容差",
                            observation,
                            source_version=source_snapshot.version,
                            source_effective_to=(
                                source_snapshot.effective_to
                            ),
                        )
                    )
                if source.metric_code not in set(profile.required_metrics):
                    issues.append(
                        _issue(
                            "metric_mismatch",
                            "blocking",
                            "来源指标不属于该分析配置的必需指标",
                            observation,
                            metric_code=source.metric_code.value,
                        )
                    )
                if observation.unit != source.unit:
                    issues.append(
                        _issue(
                            "unit_mismatch",
                            "blocking",
                            "观测单位与来源注册单位不一致",
                            observation,
                            expected_unit=source.unit,
                            actual_unit=observation.unit,
                        )
                    )
                if not source.active:
                    issues.append(
                        _issue(
                            "source_inactive",
                            "blocking",
                            "观测来源已停用",
                            observation,
                        )
                    )
                if observation.observed_at > source.calibration_valid_until:
                    issues.append(
                        _issue(
                            "calibration_expired",
                            "blocking",
                            "观测发生时来源校准已过期",
                            observation,
                            calibration_valid_until=(
                                source.calibration_valid_until.isoformat()
                            ),
                        )
                    )
                if (
                    source.metric_code is not MetricCode.RAW_INVENTORY_CHANGE
                    and observation.value < 0
                ):
                    issues.append(
                        _issue(
                            "invalid_metric_value",
                            "blocking",
                            "非库存变化流量不得为负数",
                            observation,
                            metric_code=source.metric_code.value,
                        )
                    )

            computed_hash = compute_payload_sha256(observation)
            if not hmac.compare_digest(
                computed_hash,
                observation.payload_sha256,
            ):
                issues.append(
                    _issue(
                        "payload_hash_mismatch",
                        "blocking",
                        "载荷SHA-256与规范化观测内容不一致",
                        observation,
                    )
                )

            try:
                secret = self.secret_resolver(observation.source_id)
                if secret is None:
                    raise KeyError("secret unavailable")
                expected_signature = compute_observation_signature(
                    observation,
                    secret,
                )
                signature_valid = hmac.compare_digest(
                    expected_signature,
                    observation.signature,
                )
            except (KeyError, TypeError, ValueError):
                signature_valid = False
                issues.append(
                    _issue(
                        "signature_secret_unavailable",
                        "blocking",
                        "来源验签密钥不可用",
                        observation,
                    )
                )
            if not signature_valid:
                issues.append(
                    _issue(
                        "signature_invalid",
                        "blocking",
                        "HMAC-SHA256信封签名校验失败",
                        observation,
                    )
                )

            within_window = (
                request.window_start
                <= observation.observed_at
                < request.window_end
                if source_snapshot is None
                else _observation_matches_window(
                    observation,
                    source_snapshot.definition,
                    request,
                )
            )
            if not within_window:
                issues.append(
                    _issue(
                        "outside_analysis_window",
                        "blocking",
                        "观测时间或计量区间不符合该来源的分析窗口规则",
                        observation,
                        source_version=(
                            source_snapshot.version
                            if source_snapshot is not None
                            else None
                        ),
                    )
                )

            delay_seconds = (
                observation.received_at - observation.observed_at
            ).total_seconds()
            if delay_seconds < 0:
                issues.append(
                    _issue(
                        "received_before_observed",
                        "blocking",
                        "接收时间早于观测时间",
                        observation,
                        delay_seconds=delay_seconds,
                    )
                )
            late = bool(
                source_snapshot is not None
                and delay_seconds
                > source_snapshot.definition.max_delay_seconds
            )
            if late:
                issues.append(
                    _issue(
                        "late_observation",
                        "warning",
                        "观测超过来源允许的最大接收延迟",
                        observation,
                        delay_seconds=delay_seconds,
                        max_delay_seconds=(
                            source_snapshot.definition.max_delay_seconds
                        ),
                    )
                )

            logical_key = (
                observation.source_id,
                observation.sequence_no,
            )
            prior_logical_key = logical_ids.get(observation.observation_id)
            if (
                prior_logical_key is not None
                and prior_logical_key != logical_key
            ):
                issues.append(
                    _issue(
                        "duplicate_observation_id",
                        "blocking",
                        "同一observation_id用于不同逻辑记录",
                        observation,
                    )
                )
            else:
                logical_ids[observation.observation_id] = logical_key

            if (
                observation.revision > 0
                and not self.repository.has_observation_revision(
                    observation.source_id,
                    observation.sequence_no,
                    observation.revision - 1,
                )
            ):
                issues.append(
                    _issue(
                        "revision_gap",
                        "blocking",
                        "修订号缺少直接前序版本",
                        observation,
                        revision=observation.revision,
                    )
                )

            prior_revisions = self.repository.list_observation_revisions(
                observation.source_id,
                observation.sequence_no,
            )
            if any(
                prior.observation_id != observation.observation_id
                or prior.observed_at != observation.observed_at
                or prior.interval_start != observation.interval_start
                or prior.interval_end != observation.interval_end
                for prior in prior_revisions
            ):
                issues.append(
                    _issue(
                        "revision_identity_mismatch",
                        "blocking",
                        "同一来源序号的修订必须保持业务标识和计量区间不变",
                        observation,
                        sequence_no=observation.sequence_no,
                        revision=observation.revision,
                    )
                )

            blocking_after = len(
                [issue for issue in issues if issue.blocking]
            )
            if (
                source_snapshot is not None
                and blocking_after == blocking_before
            ):
                # Only trusted envelopes enter the accepted-observation
                # ledger.  Persisting before signature/source validation would
                # let a forged request permanently occupy a sequence/revision
                # and prevent the real device from retrying it.
                write_status = self.repository.ingest_observation(
                    observation
                )
                revision_key = (
                    observation.source_id,
                    observation.sequence_no,
                    observation.revision,
                )
                if write_status == "duplicate":
                    if revision_key in seen_revision_keys:
                        issues.append(
                            _issue(
                                "duplicate_sequence_revision",
                                "blocking",
                                "同一请求重复提交了相同来源、序号和修订号",
                                observation,
                                sequence_no=observation.sequence_no,
                                revision=observation.revision,
                            )
                        )
                    else:
                        # Network retries and corrected bundles commonly
                        # repeat already accepted observations.  Exact content
                        # is idempotent; a different envelope still returns
                        # ``conflict`` below.
                        issues.append(
                            _issue(
                                "idempotent_observation_retry",
                                "warning",
                                "观测已可信接收，本次按幂等重试复用",
                                observation,
                                sequence_no=observation.sequence_no,
                                revision=observation.revision,
                            )
                        )
                        seen_revision_keys.add(revision_key)
                        candidates.append(
                            _Candidate(
                                input_index=input_index,
                                observation=observation,
                                source=source_snapshot,
                                late=late,
                            )
                        )
                elif write_status == "conflict":
                    issues.append(
                        _issue(
                            "sequence_revision_conflict",
                            "blocking",
                            "相同来源、序号和修订号对应不同载荷",
                            observation,
                            sequence_no=observation.sequence_no,
                            revision=observation.revision,
                        )
                    )
                else:
                    seen_revision_keys.add(revision_key)
                    candidates.append(
                        _Candidate(
                            input_index=input_index,
                            observation=observation,
                            source=source_snapshot,
                            late=late,
                        )
                    )

        accepted: list[_Candidate] = []
        for candidate in candidates:
            observation = candidate.observation
            latest_revision = self.repository.latest_observation_revision(
                observation.source_id,
                observation.sequence_no,
            )
            if (
                latest_revision is not None
                and observation.revision < latest_revision
            ):
                issues.append(
                    _issue(
                        "superseded_revision",
                        "warning",
                        "该观测已有更高修订版本，本版本仅保留追溯",
                        observation,
                        revision=observation.revision,
                        latest_revision=latest_revision,
                    )
                )
                continue
            accepted.append(candidate)

        aggregates, aggregation_issues = _aggregate_candidates(
            request,
            accepted,
        )
        issues.extend(aggregation_issues)
        issues = sorted(
            {_issue_key(issue): issue for issue in issues}.values(),
            key=_issue_key,
        )
        blocking_flags = sorted(
            {f"governance:{issue.code}" for issue in issues if issue.blocking}
        )

        metric_observations: list[MetricObservation] = []
        for snapshot, source_candidates, aggregation in sorted(
            aggregates,
            key=lambda item: (
                item[0].definition.metric_code.value,
                item[0].definition.source_id,
                item[0].version,
            ),
        ):
            if aggregation.aggregate_value is None:
                continue
            source = snapshot.definition
            observation_ids = sorted(
                aggregation.contributing_observation_ids
            )
            observation_id = (
                observation_ids[0]
                if len(observation_ids) == 1
                else "aggregated-"
                + sha256_json(
                    {
                        "source_id": source.source_id,
                        "source_version": snapshot.version,
                        "window_start": request.window_start,
                        "window_end": request.window_end,
                        "observation_ids": observation_ids,
                    }
                )[:32]
            )
            metric_observations.append(
                MetricObservation(
                    observation_id=observation_id,
                    metric_code=source.metric_code,
                    value=aggregation.aggregate_value,
                    tolerance_abs=source.tolerance_abs,
                    tolerance_rel=source.tolerance_rel,
                    resolution=source.resolution,
                    source_group=source.root_source_group,
                    dependency_domains=source.dependency_domains,
                    source_reliability=source.reliability,
                    quality=QualitySignals(
                        completeness=aggregation.coverage_ratio,
                        timeliness=(
                            0.0
                            if any(
                                candidate.late
                                for candidate in source_candidates
                            )
                            else 1.0
                        ),
                        # Unknown dimensions retain a neutral numeric score
                        # for continuity, but are marked so they cannot
                        # support the strongest evidence grade.
                        device_health=(
                            source.device_health_score
                            if source.device_health_score is not None
                            else 0.5
                        ),
                        calibration=1.0,
                        clock=(
                            source.clock_quality_score
                            if source.clock_quality_score is not None
                            else 0.5
                        ),
                        lineage=1.0,
                        uniqueness=1.0,
                        signature_valid=True,
                        blocking_flags=blocking_flags,
                        unverified_dimensions=[
                            dimension
                            for dimension, verified_score in (
                                (
                                    "device_health",
                                    source.device_health_score,
                                ),
                                ("clock", source.clock_quality_score),
                            )
                            if verified_score is None
                        ],
                    ),
                )
            )

        analysis_request = (
            ProductionAnalysisRequest(
                mine_id=request.mine_id,
                window_start=request.window_start,
                window_end=request.window_end,
                observations=metric_observations,
                parameters=profile.parameters.model_copy(deep=True),
                calibration_scores=[],
            )
            if metric_observations
            else None
        )

        source_manifest = [
            snapshot.manifest()
            for snapshot in sorted(
                source_snapshots.values(),
                key=lambda item: (
                    item.definition.source_id,
                    item.version,
                    item.definition_sha256,
                ),
            )
        ]
        source_manifest.extend(
            {"source_id": source_id, "definition": None}
            for source_id in sorted(unknown_sources)
        )
        registry_snapshot_hash = sha256_json(
            {
                "profile": profile_snapshot.manifest(),
                "sources": source_manifest,
            }
        )
        return PreparedAnalysis(
            request=analysis_request,
            profile_version=profile.version,
            registry_snapshot_hash=registry_snapshot_hash,
            quality_issues=issues,
            accepted_count=len(accepted),
            rejected_count=len(request.observations) - len(accepted),
        )


__all__ = [
    "AnalysisProfile",
    "ConfigurationConflictError",
    "GovernanceError",
    "GovernanceRepository",
    "GovernanceService",
    "GovernedObservation",
    "GovernedProductionRequest",
    "PreparedAnalysis",
    "ProfileNotApprovedError",
    "ProfileNotEffectiveError",
    "ProfileNotFoundError",
    "QualityIssue",
    "SourceDefinition",
    "SourceNotFoundError",
    "canonical_json",
    "compute_observation_signature",
    "compute_payload_sha256",
    "observation_payload",
    "sha256_json",
    "sign_observation",
]
