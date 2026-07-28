"""无额外 Web 框架依赖的 JSON HTTP API。"""

from __future__ import annotations

import json
import hmac
import os
import secrets
import sys
import tempfile
import threading
import time
from uuid import UUID, uuid4
from copy import deepcopy
from datetime import UTC, date, datetime, timedelta
from enum import Enum
from http import HTTPStatus
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Annotated, Any, Callable, Literal
from urllib.parse import parse_qs, unquote, urlsplit

from pydantic import (
    AwareDatetime,
    BaseModel,
    Field,
    ValidationError,
    model_validator,
)

from . import __version__
from .aggregation import AggregationRequest, aggregate_measurements
from .analytics import calculate_leadership_analytics
from .auth import (
    CsrfValidationError,
    InvalidCredentialsError,
    InvalidSessionError,
    LastActiveAdminError,
    LocalAuthStore,
    LoginRateLimitedError,
    Permission,
    PermissionDeniedError,
    Principal,
    Role,
    UserConflictError,
    UserNotFoundError,
    authorize,
    clear_session_cookie_header,
    session_cookie_header,
)
from .calibration import apply_historical_calibration
from .casework import (
    ALGORITHM_FEATURE_VERSION,
    RUN_REFERENCE_LABELS,
    AlgorithmRecordIntegrityError,
    BatchConflictError,
    BatchNotFoundError,
    CaseNotFoundError,
    ExternalConfirmerRegistrationConflictError,
    ExternalEventSnapshotConflictError,
    ExternalSubmissionConflictError,
    InvalidCaseActionError,
    LegitimateScenarioConflictError,
    LocalRepository,
    RunNotFoundError,
    VersionConflictError,
    select_authoritative_algorithm_feature,
    sha256_json,
)
from .external_submission import (
    EXTERNAL_AUTH_WINDOW_SECONDS,
    EXTERNAL_CAPABILITIES_CONTRACT_VERSION,
    EXTERNAL_NONCE_RETENTION_SECONDS,
    EXTERNAL_RECEIPT_CONTRACT_VERSION,
    EXTERNAL_SIGNATURE_VERSION,
    EXTERNAL_SUBMISSION_CONTRACT_VERSION,
    SIGNED_HEADERS,
    EnterpriseSubmission,
    ExternalAuthenticationError,
    ExternalClient,
    authenticate_external_request,
    parse_external_clients,
    sha256_bytes,
    to_governed_production_request,
    validate_enterprise_submission_json,
)
from .evidence import (
    EvidenceBundleService,
    EvidenceError,
    EvidenceNotFoundError,
    EvidenceRepository,
)
from .flow import FlowAnalysisRequest, analyze_material_flow
from .jobs import (
    AnalysisJobRequest,
    AnalysisWindow,
    JobCapacityError,
    JobConflictError,
    JobManager,
    JobNotFoundError,
    JobStateError,
    JobRepository,
    PublicJobError,
)
from .governance import (
    AnalysisProfile,
    ConfigurationConflictError,
    GovernanceError,
    GovernanceRepository,
    GovernanceService,
    GovernedProductionRequest,
    ProfileNotApprovedError,
    ProfileNotEffectiveError,
    ProfileNotFoundError,
    SourceDefinition,
    sha256_json as governance_sha256_json,
)
from .historical_pipeline import enrich_portfolio_historical_evidence
from .historical import extract_historical_features
from .historical_pipeline import operational_context_from_batch
from .models import (
    PersonnelMatchRequest,
    ProductionAnalysisRequest,
    ProductionAnalysisResult,
    StrictModel,
)
from .monitoring import (
    initialize_temporal_model_snapshot,
    refresh_temporal_audit,
)
from .optimization import analyze_production
from .operations import (
    BackupExistsError,
    BackupManager,
    BackupNotFoundError,
    BackupVerificationError,
    OperationsError,
    ReadinessCheckResult,
    ReadinessChecker,
)
from .personnel import match_personnel
from .portfolio import (
    PortfolioAnalysisRequest,
    analyze_production_portfolio,
)
from .source_keys import SourceKeyConflictError, SourceKeyStore
from .runtime_manifest import build_runtime_manifest
from .temporal import (
    TemporalDetectionParameters,
    TemporalDetectionRequest,
    TemporalObservation,
    detect_temporal_anomalies,
)


MAX_REQUEST_BYTES = 10 * 1024 * 1024
WEB_ROOT = Path(__file__).resolve().with_name("web")

# Deliberately use an allowlist instead of translating arbitrary URL paths
# into filesystem paths.  Besides keeping the public surface small, this
# makes path traversal unable to escape the web resource directory.
STATIC_ROUTES: dict[str, tuple[str, str]] = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/assets/styles.css": ("styles.css", "text/css; charset=utf-8"),
    "/assets/app.js": ("app.js", "application/javascript; charset=utf-8"),
}
STATIC_CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "frame-ancestors 'none'"
)
COMPUTE_ONLY_POST_ROUTES = frozenset(
    {
        "/v1/analyze/production",
        "/v1/analyze/personnel",
        "/v1/analyze/flow",
        "/v1/analyze/aggregation",
        "/v1/analyze/temporal",
    }
)


class _GovernedInputRejected(ValueError):
    def __init__(self, details: list[dict[str, Any]]) -> None:
        self.details = details
        super().__init__("trusted observations failed governance checks")


def _json_default(value: Any) -> Any:
    """Convert the few non-native values an analysis result may contain."""

    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value

    # NumPy scalar values occasionally escape numerical code.  Keeping this
    # duck-typed avoids making the HTTP layer depend directly on NumPy.
    item = getattr(value, "item", None)
    if callable(item):
        return item()
    raise TypeError(f"{type(value).__name__} is not JSON serializable")


def _validation_details(error: ValidationError) -> list[dict[str, Any]]:
    """Return useful validation details without non-JSON exception objects."""

    return error.errors(
        include_url=False,
        include_context=False,
        include_input=False,
    )


class CaseActionRequest(StrictModel):
    action: Literal[
        "assign",
        "add_note",
        "start_review",
        "request_data",
        "submit_conclusion",
        "withdraw_conclusion",
        "approve",
        "reject",
        "close",
        "reopen",
        "archive_case",
        "restore_case",
    ]
    expected_version: Annotated[int, Field(ge=1)]
    note: Annotated[str, Field(min_length=1)] | None = None
    disposition: Literal[
        "confirmed",
        "confirmed_technical_issue",
        "excluded",
        "data_insufficient",
        "partially_supported",
    ] | None = None
    assignee: Annotated[str, Field(min_length=1)] | None = None


class LoginRequest(StrictModel):
    username: Annotated[str, Field(min_length=1, max_length=100)]
    password: Annotated[str, Field(min_length=1, max_length=500)]


class UserCreateRequest(StrictModel):
    username: Annotated[str, Field(min_length=1, max_length=100)]
    password: Annotated[str, Field(min_length=8, max_length=500)]
    role: Role
    mine_scopes: list[Annotated[str, Field(min_length=1)]] = Field(
        default_factory=list
    )


class UserStatusRequest(StrictModel):
    active: bool
    reason: Annotated[str, Field(min_length=1, max_length=1000)] | None = None


class BatchStatusRequest(StrictModel):
    active: bool
    reason: Annotated[str, Field(min_length=1, max_length=1000)]
    expected_version: Annotated[int, Field(ge=1)]


class PilotIsolationRequest(StrictModel):
    reason: Annotated[str, Field(min_length=1, max_length=1000)]


class UserAccessRequest(StrictModel):
    role: Role
    mine_scopes: Annotated[
        list[Annotated[str, Field(min_length=1, max_length=128)]],
        Field(max_length=5000),
    ] = Field(default_factory=list)
    reason: Annotated[str, Field(min_length=1, max_length=1000)] | None = None

    @model_validator(mode="after")
    def validate_mine_scopes(self) -> "UserAccessRequest":
        if len(self.mine_scopes) != len(set(self.mine_scopes)):
            raise ValueError("mine_scopes values must be unique")
        return self


class ChangePasswordRequest(StrictModel):
    current_password: Annotated[str, Field(min_length=1, max_length=500)]
    new_password: Annotated[str, Field(min_length=12, max_length=500)]


class ResetPasswordRequest(StrictModel):
    new_password: Annotated[str, Field(min_length=12, max_length=500)]


class JobSubmitRequest(StrictModel):
    idempotency_key: Annotated[str, Field(min_length=1, max_length=200)]
    windows: Annotated[list[AnalysisWindow], Field(min_length=1, max_length=5000)]


class JobReplayRequest(StrictModel):
    idempotency_key: Annotated[str, Field(min_length=1, max_length=200)]


class JobArchiveRequest(StrictModel):
    archived: bool
    reason: Annotated[str, Field(min_length=1, max_length=500)]


class GovernedJobWindow(StrictModel):
    window_id: Annotated[str, Field(min_length=1, max_length=200)]
    request: GovernedProductionRequest


class GovernedJobSubmitRequest(StrictModel):
    idempotency_key: Annotated[str, Field(min_length=1, max_length=200)]
    windows: Annotated[
        list[GovernedJobWindow],
        Field(min_length=1, max_length=5000),
    ]

    @model_validator(mode="after")
    def validate_window_ids(self) -> "GovernedJobSubmitRequest":
        identifiers = [window.window_id for window in self.windows]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("window_id values must be unique")
        return self


class EvidenceCreateRequest(StrictModel):
    expected_version: Annotated[int, Field(ge=1)]


class RunReferenceLabelRequest(StrictModel):
    label: Literal[
        "verified_normal",
        "legitimate_exception",
        "confirmed_data_error",
        "confirmed_technical_anomaly",
        "adjudicated_violation",
        "unresolved",
    ]
    expected_sequence: Annotated[int, Field(ge=0)]
    note: Annotated[str, Field(min_length=10, max_length=4000)]
    scenario_id: Annotated[
        str,
        Field(min_length=1, max_length=128),
    ] | None = None

    @model_validator(mode="after")
    def validate_scenario_reference(self) -> "RunReferenceLabelRequest":
        if (
            self.label == "legitimate_exception"
            and self.scenario_id is None
        ):
            raise ValueError(
                "legitimate_exception requires an approved scenario_id"
            )
        if (
            self.label != "legitimate_exception"
            and self.scenario_id is not None
        ):
            raise ValueError(
                "scenario_id is only valid for legitimate_exception"
            )
        return self


class LegitimateScenarioRequest(StrictModel):
    scenario_id: Annotated[str, Field(min_length=1, max_length=128)]
    version: Annotated[int, Field(ge=1)]
    name: Annotated[str, Field(min_length=1, max_length=160)]
    description: Annotated[str, Field(min_length=1, max_length=8000)]
    mine_ids: Annotated[
        list[Annotated[str, Field(min_length=1, max_length=128)]],
        Field(max_length=128),
    ] | None = None
    regime: Annotated[str, Field(min_length=1, max_length=128)] | None = None
    shift: Annotated[str, Field(min_length=1, max_length=128)] | None = None
    season: Annotated[str, Field(min_length=1, max_length=128)] | None = None
    maintenance: bool | None = None
    required_event_codes: Annotated[
        list[Annotated[str, Field(min_length=1, max_length=128)]],
        Field(max_length=128),
    ] = Field(default_factory=list)
    required_tags: Annotated[
        list[Annotated[str, Field(min_length=1, max_length=128)]],
        Field(max_length=128),
    ] = Field(default_factory=list)
    feature_bounds: Annotated[
        dict[
            Annotated[str, Field(min_length=1, max_length=128)],
            dict[str, float | None],
        ],
        Field(max_length=256),
    ] = Field(default_factory=dict)
    active: bool = True

    @model_validator(mode="after")
    def validate_unique_lists(self) -> "LegitimateScenarioRequest":
        for field_name in (
            "mine_ids",
            "required_event_codes",
            "required_tags",
        ):
            values = getattr(self, field_name)
            if values is not None and len(values) != len(set(values)):
                raise ValueError(f"{field_name} values must be unique")
        return self


class LegitimateScenarioCreateRequest(StrictModel):
    scenario: LegitimateScenarioRequest


class ExternalEventSnapshotRequest(StrictModel):
    snapshot_id: Annotated[str, Field(min_length=1, max_length=128)]
    mine_id: Annotated[str, Field(min_length=1, max_length=128)]
    window_start: AwareDatetime
    window_end: AwareDatetime
    event_codes: Annotated[
        list[Annotated[str, Field(min_length=1, max_length=64)]],
        Field(max_length=32),
    ] = Field(default_factory=list)
    evidence_sha256: Annotated[
        str,
        Field(pattern=r"^[0-9a-f]{64}$"),
    ]
    source_system: Annotated[str, Field(min_length=1, max_length=128)]
    record_id: Annotated[str, Field(min_length=1, max_length=256)]

    @model_validator(mode="after")
    def validate_snapshot(self) -> "ExternalEventSnapshotRequest":
        if self.window_start >= self.window_end:
            raise ValueError("window_start must be earlier than window_end")
        if len(self.event_codes) != len(set(self.event_codes)):
            raise ValueError("event_codes values must be unique")
        self.event_codes = sorted(self.event_codes)
        return self


class ExternalConfirmerRegistrationRequest(StrictModel):
    registration_id: Annotated[
        str,
        Field(
            min_length=1,
            max_length=128,
            pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
        ),
    ]
    client_id: Annotated[
        str,
        Field(
            min_length=1,
            max_length=128,
            pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
        ),
    ]
    enterprise_id: Annotated[
        str,
        Field(
            min_length=1,
            max_length=128,
            pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
        ),
    ]
    confirmer_id: Annotated[
        str,
        Field(
            min_length=1,
            max_length=128,
            pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
        ),
    ]
    version: Annotated[int, Field(ge=1)]
    confirmer_name: Annotated[str, Field(min_length=1, max_length=128)]
    confirmer_roles: Annotated[
        list[Annotated[str, Field(min_length=1, max_length=128)]],
        Field(min_length=1, max_length=128),
    ]
    confirmation_methods: Annotated[
        list[Literal["authenticated_click"]],
        Field(min_length=1, max_length=1),
    ] = Field(default_factory=lambda: ["authenticated_click"])
    active: bool = True
    source_system: Annotated[str, Field(min_length=1, max_length=128)]
    record_id: Annotated[str, Field(min_length=1, max_length=256)]

    @model_validator(mode="after")
    def validate_registration(
        self,
    ) -> "ExternalConfirmerRegistrationRequest":
        if len(self.confirmer_roles) != len(set(self.confirmer_roles)):
            raise ValueError("confirmer_roles values must be unique")
        self.confirmer_roles = sorted(self.confirmer_roles)
        return self


class SourceRegistrationRequest(StrictModel):
    definition: SourceDefinition
    version: Annotated[int, Field(ge=1)] = 1
    effective_from: AwareDatetime
    effective_to: AwareDatetime | None = None
    hmac_secret: Annotated[str, Field(min_length=16, max_length=4096)]


class ProfileRegistrationRequest(StrictModel):
    profile: AnalysisProfile


class BackupCreateRequest(StrictModel):
    backup_id: Annotated[
        str,
        Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$"),
    ]


class GovernedPortfolioIngestRequest(StrictModel):
    batch_id: Annotated[str, Field(min_length=1, max_length=200)]
    portfolio_name: Annotated[str, Field(min_length=1, max_length=200)]
    expected_mine_ids: Annotated[
        list[Annotated[str, Field(min_length=1, max_length=128)]],
        Field(min_length=1, max_length=5000),
    ]
    analyses: Annotated[
        list[GovernedProductionRequest],
        Field(max_length=5000),
    ] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_roster(self) -> "GovernedPortfolioIngestRequest":
        if len(self.expected_mine_ids) != len(set(self.expected_mine_ids)):
            raise ValueError("expected_mine_ids values must be unique")
        actual = [analysis.mine_id for analysis in self.analyses]
        if len(actual) != len(set(actual)):
            raise ValueError("analysis mine_id values must be unique")
        unexpected = sorted(set(actual) - set(self.expected_mine_ids))
        if unexpected:
            raise ValueError(
                "analysis mine_id values must belong to expected_mine_ids"
            )
        return self


class MineGuardRequestHandler(BaseHTTPRequestHandler):
    """HTTP transport for analysis, jurisdiction overview and casework."""

    protocol_version = "HTTP/1.1"
    server_version = f"MineGuard/{__version__}"

    _post_routes: dict[
        str,
        tuple[type[BaseModel], Callable[[Any], Any]],
    ] = {
        "/v1/analyze/production": (
            ProductionAnalysisRequest,
            lambda request: analyze_production(request),
        ),
        "/v1/analyze/personnel": (
            PersonnelMatchRequest,
            lambda request: match_personnel(request),
        ),
        "/v1/analyze/temporal": (
            TemporalDetectionRequest,
            lambda request: detect_temporal_anomalies(request),
        ),
        "/v1/analyze/flow": (
            FlowAnalysisRequest,
            lambda request: analyze_material_flow(request),
        ),
        "/v1/analyze/aggregation": (
            AggregationRequest,
            lambda request: aggregate_measurements(request),
        ),
    }

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        self._start_request_log()
        parsed = urlsplit(self.path)
        path = parsed.path
        static_resource = STATIC_ROUTES.get(path)
        if static_resource is not None:
            filename, content_type = static_resource
            self._send_static(filename, content_type)
            return
        if path == "/health":
            self._send_json(HTTPStatus.OK, {"status": "ok"})
            return
        if path == "/v1/enterprise-submission-capabilities":
            if parsed.query:
                self._send_external_error(
                    HTTPStatus.BAD_REQUEST,
                    "QUERY_NOT_SUPPORTED",
                    "This endpoint does not accept query parameters.",
                    retryable=False,
                )
            else:
                self._handle_external_capabilities()
            return
        external_receipt_id = self._external_receipt_id(path)
        if external_receipt_id is not None:
            if parsed.query:
                self._send_external_error(
                    HTTPStatus.BAD_REQUEST,
                    "QUERY_NOT_SUPPORTED",
                    "This endpoint does not accept query parameters.",
                    retryable=False,
                )
            else:
                self._handle_external_receipt_get(
                    external_receipt_id,
                    path,
                )
            return
        if path == "/live":
            self._send_json(HTTPStatus.OK, self._readiness.liveness())
            return
        if path == "/ready":
            readiness = self._readiness.readiness()
            status = (
                HTTPStatus.SERVICE_UNAVAILABLE
                if readiness["status"] == "not_ready"
                else HTTPStatus.OK
            )
            self._send_json(status, readiness)
            return
        if path == "/v1/auth/me":
            principal = self._require_authenticated()
            if principal is not None:
                self._send_json(
                    HTTPStatus.OK,
                    {"principal": self._principal_payload(principal)},
                )
            return
        if path == "/v1/auth/csrf":
            self._handle_csrf()
            return
        if path == "/v1/admin/users":
            principal = self._require_authenticated()
            if (
                principal is not None
                and self._require_permission(
                    principal,
                    Permission.USER_MANAGE,
                )
            ):
                self._send_json(
                    HTTPStatus.OK,
                    {"items": self._auth_store.list_users()},
                )
            return
        if path == "/v1/admin/audit":
            principal = self._require_authenticated()
            if (
                principal is not None
                and self._require_permission(
                    principal,
                    Permission.AUDIT_READ,
                )
            ):
                self._send_json(
                    HTTPStatus.OK,
                    {"items": self._auth_store.list_audit_events()},
                )
            return
        if path == "/v1/admin/readiness":
            principal = self._require_authenticated()
            if (
                principal is not None
                and self._require_permission(
                    principal,
                    Permission.AUDIT_READ,
                )
            ):
                self._send_json(
                    HTTPStatus.OK,
                    self._readiness.readiness(),
                )
            return
        if path == "/v1/admin/backups":
            principal = self._require_authenticated()
            if (
                principal is not None
                and self._require_permission(
                    principal,
                    Permission.CONFIG_MANAGE,
                )
            ):
                self._handle_backup_list()
            return
        if path == "/v1/admin/legitimate-scenarios":
            principal = self._require_authenticated()
            if (
                principal is not None
                and self._require_permission(
                    principal,
                    Permission.CONFIG_MANAGE,
                )
            ):
                self._handle_legitimate_scenario_list()
            return
        if path == "/v1/admin/external-event-snapshots":
            principal = self._require_authenticated()
            if (
                principal is not None
                and self._require_permission(
                    principal,
                    Permission.CONFIG_MANAGE,
                )
            ):
                self._handle_external_event_snapshot_list()
            return
        if path == "/v1/admin/external-confirmers":
            principal = self._require_authenticated()
            if (
                principal is not None
                and self._require_permission(
                    principal,
                    Permission.CONFIG_MANAGE,
                )
            ):
                self._handle_external_confirmer_list()
            return
        backup_id = self._backup_verify_route(path)
        if backup_id is not None:
            principal = self._require_authenticated()
            if (
                principal is not None
                and self._require_permission(
                    principal,
                    Permission.CONFIG_MANAGE,
                )
            ):
                self._handle_backup_verify(backup_id)
            return
        if path == "/v1/governance/sources":
            principal = self._require_authenticated()
            if (
                principal is not None
                and self._require_permission(
                    principal,
                    Permission.CONFIG_MANAGE,
                )
            ):
                self._handle_source_list()
            return
        if path == "/v1/governance/profiles":
            principal = self._require_authenticated()
            if (
                principal is not None
                and self._require_permission(
                    principal,
                    Permission.CONFIG_MANAGE,
                )
            ):
                self._handle_profile_list()
            return
        if path == "/v1/analysis-jobs":
            principal = self._require_authenticated()
            if principal is not None:
                self._handle_job_list(parsed.query, principal)
            return
        if path == "/v1/analysis-batches":
            principal = self._require_authenticated()
            if (
                principal is not None
                and self._require_permission(
                    principal,
                    Permission.AUDIT_READ,
                )
            ):
                self._handle_analysis_batch_list(parsed.query)
            return
        job_id = self._resource_id(path, "/v1/analysis-jobs/")
        if job_id is not None:
            principal = self._require_authenticated()
            if principal is not None:
                self._handle_job_detail(job_id, principal)
            return
        if path == "/v1/dashboard/overview":
            principal = self._require_authenticated()
            if principal is not None:
                self._handle_overview(principal)
            return
        if path == "/v1/dashboard/trends":
            principal = self._require_authenticated()
            if principal is not None:
                self._handle_trends(parsed.query, principal)
            return
        if path == "/v1/dashboard/temporal":
            principal = self._require_authenticated()
            if principal is not None:
                self._handle_temporal_dashboard(parsed.query, principal)
            return
        if path == "/v1/cases":
            principal = self._require_authenticated()
            if principal is not None:
                self._handle_case_list(parsed.query, principal)
            return

        batch_route = self._analysis_batch_route(path)
        if batch_route is not None:
            batch_id, suffix = batch_route
            if suffix in {"", "/audit"}:
                principal = self._require_authenticated()
                if (
                    principal is not None
                    and self._require_permission(
                        principal,
                        (
                            Permission.CONFIG_MANAGE
                            if suffix == ""
                            else Permission.AUDIT_READ
                        ),
                    )
                ):
                    self._handle_analysis_batch_detail(
                        batch_id,
                        audit_only=suffix == "/audit",
                    )
            elif suffix == "/status":
                self._send_method_not_allowed("POST")
            else:
                self._send_not_found()
            return

        case_route = self._case_route(path)
        if case_route is not None:
            case_id, suffix = case_route
            if suffix == "":
                principal = self._require_authenticated()
                if principal is not None:
                    self._handle_case_detail(case_id, principal)
            elif suffix == "/audit":
                principal = self._require_authenticated()
                if principal is not None:
                    self._handle_case_audit(case_id, principal)
            elif suffix in {"/actions", "/evidence"}:
                self._send_method_not_allowed("POST")
            else:
                self._send_not_found()
            return

        run_route = self._analysis_run_route(path)
        if run_route is not None:
            run_id, suffix = run_route
            principal = self._require_authenticated()
            if principal is not None:
                if suffix == "":
                    self._handle_analysis_run(run_id, principal)
                elif suffix == "/reference-labels":
                    self._handle_run_reference_labels_get(
                        run_id,
                        principal,
                    )
                else:
                    self._send_not_found()
            return
        evidence_route = self._evidence_route(path)
        if evidence_route is not None:
            bundle_id, verify_only = evidence_route
            principal = self._require_authenticated()
            if principal is not None:
                self._handle_evidence_get(
                    bundle_id,
                    principal,
                    verify_only=verify_only,
                )
            return
        if path == "/v1/analyze/production/batch":
            self._send_method_not_allowed("POST")
            return
        if path in self._post_routes:
            self._send_method_not_allowed("POST")
            return
        self._send_not_found()

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        self._start_request_log()
        # The single-node edition uses a short global write gate.  Besides
        # preventing conflicting cross-database mutations, this gives the
        # online backup endpoint a coherent business-state boundary. Pure
        # calculations are deliberately kept outside that gate so a bounded
        # solver run cannot block login, casework or trusted ingestion.
        path = urlsplit(self.path).path
        if path in COMPUTE_ONLY_POST_ROUTES:
            self._dispatch_POST()
            return
        with self.server.mutation_lock:  # type: ignore[attr-defined]
            self._dispatch_POST()

    def _dispatch_POST(self) -> None:
        parsed = urlsplit(self.path)
        path = parsed.path
        if path == "/v1/enterprise-submissions":
            if parsed.query:
                self._send_external_error(
                    HTTPStatus.BAD_REQUEST,
                    "QUERY_NOT_SUPPORTED",
                    "This endpoint does not accept query parameters.",
                    retryable=False,
                )
            else:
                self._handle_external_submission(path)
            return
        if path == "/v1/auth/login":
            self._handle_login()
            return
        if path == "/v1/auth/logout":
            principal = self._require_authenticated(require_csrf=True)
            if principal is not None:
                self._handle_logout()
            return
        if path == "/v1/auth/change-password":
            principal = self._require_authenticated(require_csrf=True)
            if principal is not None:
                self._handle_change_password(principal)
            return
        if path == "/v1/admin/users":
            principal = self._require_authenticated(require_csrf=True)
            if (
                principal is not None
                and self._require_permission(
                    principal,
                    Permission.USER_MANAGE,
                )
            ):
                self._handle_user_create(principal)
            return
        if path == "/v1/admin/backups":
            principal = self._require_authenticated(require_csrf=True)
            if (
                principal is not None
                and self._require_permission(
                    principal,
                    Permission.CONFIG_MANAGE,
                )
            ):
                self._handle_backup_create(principal)
            return
        if path == "/v1/admin/legitimate-scenarios":
            principal = self._require_authenticated(require_csrf=True)
            if (
                principal is not None
                and self._require_permission(
                    principal,
                    Permission.CONFIG_MANAGE,
                )
            ):
                self._handle_legitimate_scenario_create(principal)
            return
        if path == "/v1/admin/external-event-snapshots":
            principal = self._require_authenticated(require_csrf=True)
            if (
                principal is not None
                and self._require_permission(
                    principal,
                    Permission.CONFIG_MANAGE,
                )
            ):
                self._handle_external_event_snapshot_create(principal)
            return
        if path == "/v1/admin/external-confirmers":
            principal = self._require_authenticated(require_csrf=True)
            if (
                principal is not None
                and self._require_permission(
                    principal,
                    Permission.CONFIG_MANAGE,
                )
            ):
                self._handle_external_confirmer_create(principal)
            return
        if path == "/v1/governance/sources":
            principal = self._require_authenticated(require_csrf=True)
            if (
                principal is not None
                and self._require_permission(
                    principal,
                    Permission.CONFIG_MANAGE,
                )
            ):
                self._handle_source_register(principal)
            return
        if path == "/v1/governance/profiles":
            principal = self._require_authenticated(require_csrf=True)
            if (
                principal is not None
                and self._require_permission(
                    principal,
                    Permission.CONFIG_MANAGE,
                )
            ):
                self._handle_profile_register(principal)
            return
        if path == "/v1/ingest/production/batch":
            principal = self._require_authenticated(require_csrf=True)
            if principal is not None:
                self._handle_governed_portfolio_ingest(principal)
            return
        if path == "/v1/ingest/production":
            principal = self._require_authenticated(require_csrf=True)
            if principal is not None:
                self._handle_governed_ingest(principal)
            return
        user_status = self._admin_user_status_route(path)
        if user_status is not None:
            principal = self._require_authenticated(require_csrf=True)
            if (
                principal is not None
                and self._require_permission(
                    principal,
                    Permission.USER_MANAGE,
                )
            ):
                self._handle_user_status(user_status, principal)
            return
        user_password = self._admin_user_password_route(path)
        if user_password is not None:
            principal = self._require_authenticated(require_csrf=True)
            if (
                principal is not None
                and self._require_permission(
                    principal,
                    Permission.USER_MANAGE,
                )
            ):
                self._handle_password_reset(user_password, principal)
            return
        user_access = self._admin_user_access_route(path)
        if user_access is not None:
            principal = self._require_authenticated(require_csrf=True)
            if (
                principal is not None
                and self._require_permission(
                    principal,
                    Permission.USER_MANAGE,
                )
            ):
                self._handle_user_access(user_access, principal)
            return
        if path == "/v1/analysis-jobs":
            principal = self._require_authenticated(require_csrf=True)
            if principal is not None:
                self._handle_job_submit(principal)
            return
        if path == "/v1/ingest/production/jobs":
            principal = self._require_authenticated(require_csrf=True)
            if principal is not None:
                self._handle_governed_job_submit(principal)
            return
        job_action = self._job_action_route(path)
        if job_action is not None:
            job_id, action = job_action
            principal = self._require_authenticated(require_csrf=True)
            if principal is not None:
                self._handle_job_action(job_id, action, principal)
            return
        if path == "/v1/analyze/production/batch":
            principal = self._require_authenticated(require_csrf=True)
            if principal is not None:
                self._handle_portfolio_batch(principal, parsed.query)
            return
        if path == "/v1/admin/analysis-batches/isolate-pilots":
            principal = self._require_authenticated(require_csrf=True)
            if (
                principal is not None
                and self._require_permission(
                    principal,
                    Permission.CONFIG_MANAGE,
                )
            ):
                self._handle_pilot_batch_isolation(principal)
            return
        if path == "/v1/analysis-batches":
            self._send_method_not_allowed("GET")
            return

        batch_route = self._analysis_batch_route(path)
        if batch_route is not None:
            batch_id, suffix = batch_route
            if suffix == "/status":
                principal = self._require_authenticated(require_csrf=True)
                if (
                    principal is not None
                    and self._require_permission(
                        principal,
                        Permission.CONFIG_MANAGE,
                    )
                ):
                    self._handle_analysis_batch_status(
                        batch_id,
                        principal,
                    )
            elif suffix in {"", "/audit"}:
                self._send_method_not_allowed("GET")
            else:
                self._send_not_found()
            return

        case_route = self._case_route(path)
        if case_route is not None:
            case_id, suffix = case_route
            if suffix == "/actions":
                principal = self._require_authenticated(require_csrf=True)
                if principal is not None:
                    self._handle_case_action(case_id, principal)
            elif suffix == "/evidence":
                principal = self._require_authenticated(require_csrf=True)
                if principal is not None:
                    self._handle_evidence_create(case_id, principal)
            elif suffix in {"", "/audit"}:
                self._send_method_not_allowed("GET")
            else:
                self._send_not_found()
            return

        run_route = self._analysis_run_route(path)
        if run_route is not None:
            run_id, suffix = run_route
            if suffix == "/reference-labels":
                principal = self._require_authenticated(require_csrf=True)
                if principal is not None:
                    self._handle_run_reference_label_append(
                        run_id,
                        principal,
                    )
            elif suffix == "":
                self._send_method_not_allowed("GET")
            else:
                self._send_not_found()
            return

        route = self._post_routes.get(path)
        if route is None:
            if path == "/health":
                self._send_method_not_allowed("GET")
            elif path in STATIC_ROUTES or path in {
                "/v1/dashboard/overview",
                "/v1/dashboard/temporal",
                "/v1/cases",
            }:
                self._send_method_not_allowed("GET")
            else:
                self._send_not_found()
            return

        principal = self._require_authenticated(require_csrf=True)
        if principal is None:
            return
        model_type, operation = route
        try:
            body = self._read_request_body()
            request = model_type.model_validate_json(body)
        except _RequestTooLarge as error:
            self._send_error(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                "request_too_large",
                str(error),
            )
            return
        except _BadRequest as error:
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "bad_request",
                str(error),
            )
            return
        except ValidationError as error:
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "validation_error",
                "request validation failed",
                _validation_details(error),
            )
            return

        try:
            if self._auth_required and principal.role is not Role.ADMIN:
                self._send_error(
                    HTTPStatus.FORBIDDEN,
                    "trusted_ingest_required",
                    "direct caller-supplied analysis is restricted to "
                    "administrators; use trusted ingestion",
                )
                return
            mine_id = getattr(request, "mine_id", None)
            if not self._require_permission(
                principal,
                Permission.ANALYSIS_RUN,
                mine_id=mine_id,
            ):
                return
            result = operation(request)
            self._send_json(HTTPStatus.OK, result)
        except Exception:
            # Analysis exceptions may contain operational details and must not
            # be reflected to an HTTP caller.
            self.log_error("analysis operation failed")
            self._send_error(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "internal_error",
                "internal server error",
            )

    @property
    def _repository(self) -> LocalRepository:
        return self.server.repository  # type: ignore[attr-defined]

    @property
    def _external_clients(self) -> dict[str, ExternalClient]:
        return self.server.external_clients  # type: ignore[attr-defined]

    @property
    def _local_actor(self) -> str:
        return self.server.local_actor  # type: ignore[attr-defined]

    @property
    def _auth_store(self) -> LocalAuthStore:
        return self.server.auth_store  # type: ignore[attr-defined]

    @property
    def _job_manager(self) -> JobManager:
        return self.server.job_manager  # type: ignore[attr-defined]

    @property
    def _evidence_service(self) -> EvidenceBundleService:
        return self.server.evidence_service  # type: ignore[attr-defined]

    @property
    def _evidence_repository(self) -> EvidenceRepository:
        return self.server.evidence_repository  # type: ignore[attr-defined]

    @property
    def _governance_repository(self) -> GovernanceRepository:
        return self.server.governance_repository  # type: ignore[attr-defined]

    def _refresh_temporal_audit(
        self,
        mine_ids: set[str],
    ) -> dict[str, Any]:
        """Append detector audit records after the analysis commit succeeds."""

        try:
            return refresh_temporal_audit(
                self._repository,
                mine_ids=mine_ids,
            )
        except Exception:
            # The immutable analysis batch is already committed. A monitoring
            # refresh failure must be visible but must never roll it back.
            self.log_error(
                "temporal audit refresh failed for mines %s",
                ",".join(sorted(mine_ids)),
            )
            return {
                "status": "refresh_failed",
                "mine_ids": sorted(mine_ids),
            }

    @property
    def _governance_service(self) -> GovernanceService:
        return self.server.governance_service  # type: ignore[attr-defined]

    @property
    def _source_key_store(self) -> SourceKeyStore:
        return self.server.source_key_store  # type: ignore[attr-defined]

    @property
    def _readiness(self) -> ReadinessChecker:
        return self.server.readiness  # type: ignore[attr-defined]

    @property
    def _backup_manager(self) -> BackupManager | None:
        return self.server.backup_manager  # type: ignore[attr-defined]

    @property
    def _backup_databases(self) -> dict[str, Path]:
        return self.server.backup_databases  # type: ignore[attr-defined]

    @property
    def _auth_required(self) -> bool:
        return bool(self.server.auth_required)  # type: ignore[attr-defined]

    @property
    def _secure_cookie(self) -> bool:
        return bool(self.server.secure_cookie)  # type: ignore[attr-defined]

    def _session_token(self) -> str | None:
        raw_cookie = self.headers.get("Cookie")
        if not raw_cookie:
            return None
        cookies = SimpleCookie()
        try:
            cookies.load(raw_cookie)
        except CookieError:
            return None
        morsel = cookies.get("mineguard_session")
        return morsel.value if morsel is not None else None

    def _require_authenticated(
        self,
        *,
        require_csrf: bool = False,
    ) -> Principal | None:
        if not self._auth_required:
            return Principal(
                user_id="local",
                username=self._local_actor,
                role=Role.ADMIN,
                mine_scopes=(),
                session_id="local-auth-disabled",
            )
        session_token = self._session_token()
        if not session_token:
            self._send_error(
                HTTPStatus.UNAUTHORIZED,
                "authentication_required",
                "login is required",
            )
            return None
        try:
            if require_csrf:
                return self._auth_store.validate_csrf(
                    session_token,
                    self.headers.get("X-CSRF-Token"),
                    method=self.command,
                )
            return self._auth_store.authenticate(session_token)
        except CsrfValidationError:
            self._send_error(
                HTTPStatus.FORBIDDEN,
                "csrf_invalid",
                "request authenticity check failed",
            )
        except InvalidSessionError:
            self._send_error(
                HTTPStatus.UNAUTHORIZED,
                "session_invalid",
                "session is invalid or expired",
            )
        return None

    def _require_permission(
        self,
        principal: Principal,
        permission: Permission,
        *,
        mine_id: str | None = None,
    ) -> bool:
        try:
            authorize(principal, permission, mine_id)
            return True
        except PermissionDeniedError:
            self._record_audit(
                principal,
                "permission_denied",
                {
                    "permission": permission.value,
                    "mine_id": mine_id,
                },
            )
            self._send_error(
                HTTPStatus.FORBIDDEN,
                "permission_denied",
                "permission or mine scope denied",
            )
        return False

    def _record_audit(
        self,
        principal: Principal,
        action: str,
        detail: dict[str, Any],
    ) -> None:
        try:
            self._auth_store.record_audit_event(
                action,
                principal=principal,
                client_id=str(self.client_address[0]),
                detail=detail,
            )
        except Exception:
            self.log_error("audit event could not be persisted")

    @staticmethod
    def _principal_payload(principal: Principal) -> dict[str, Any]:
        return {
            "user_id": principal.user_id,
            "username": principal.username,
            "role": principal.role.value,
            "mine_scopes": list(principal.mine_scopes),
        }

    @staticmethod
    def _visible_mines(principal: Principal) -> tuple[str, ...] | None:
        return None if principal.role is Role.ADMIN else principal.mine_scopes

    @staticmethod
    def _resource_id(path: str, prefix: str) -> str | None:
        if not path.startswith(prefix):
            return None
        resource_id = path[len(prefix):]
        if not resource_id or "/" in resource_id:
            return None
        return resource_id

    @staticmethod
    def _case_route(path: str) -> tuple[str, str] | None:
        prefix = "/v1/cases/"
        if not path.startswith(prefix):
            return None
        remainder = path[len(prefix):]
        if not remainder:
            return None
        case_id, separator, suffix = remainder.partition("/")
        if not case_id:
            return None
        return case_id, (f"/{suffix}" if separator else "")

    @staticmethod
    def _analysis_run_route(path: str) -> tuple[str, str] | None:
        prefix = "/v1/analysis-runs/"
        if not path.startswith(prefix):
            return None
        remainder = path[len(prefix):]
        if not remainder:
            return None
        run_id, separator, suffix = remainder.partition("/")
        if not run_id:
            return None
        return run_id, (f"/{suffix}" if separator else "")

    @staticmethod
    def _analysis_batch_route(path: str) -> tuple[str, str] | None:
        prefix = "/v1/analysis-batches/"
        if not path.startswith(prefix):
            return None
        remainder = path[len(prefix):]
        if not remainder:
            return None
        encoded_id, separator, suffix = remainder.partition("/")
        batch_id = unquote(encoded_id)
        if (
            not batch_id
            or "/" in batch_id
            or "\x00" in batch_id
            or (separator and suffix not in {"status", "audit"})
        ):
            return None
        return batch_id, (f"/{suffix}" if separator else "")

    @staticmethod
    def _evidence_route(path: str) -> tuple[str, bool] | None:
        prefix = "/v1/evidence/"
        if not path.startswith(prefix):
            return None
        remainder = path[len(prefix):]
        if not remainder:
            return None
        if remainder.endswith("/verify"):
            bundle_id = remainder[: -len("/verify")]
            if bundle_id and "/" not in bundle_id:
                return bundle_id, True
            return None
        if "/" not in remainder:
            return remainder, False
        return None

    @staticmethod
    def _admin_user_status_route(path: str) -> str | None:
        prefix = "/v1/admin/users/"
        suffix = "/status"
        if not path.startswith(prefix) or not path.endswith(suffix):
            return None
        username = unquote(path[len(prefix): -len(suffix)])
        return (
            username
            if username and "/" not in username and "\x00" not in username
            else None
        )

    @staticmethod
    def _admin_user_password_route(path: str) -> str | None:
        prefix = "/v1/admin/users/"
        suffix = "/reset-password"
        if not path.startswith(prefix) or not path.endswith(suffix):
            return None
        username = unquote(path[len(prefix): -len(suffix)])
        return (
            username
            if username and "/" not in username and "\x00" not in username
            else None
        )

    @staticmethod
    def _admin_user_access_route(path: str) -> str | None:
        prefix = "/v1/admin/users/"
        suffix = "/access"
        if not path.startswith(prefix) or not path.endswith(suffix):
            return None
        username = unquote(path[len(prefix): -len(suffix)])
        return (
            username
            if username and "/" not in username and "\x00" not in username
            else None
        )

    @staticmethod
    def _job_action_route(path: str) -> tuple[str, str] | None:
        prefix = "/v1/analysis-jobs/"
        if not path.startswith(prefix):
            return None
        remainder = path[len(prefix):]
        job_id, separator, action = remainder.partition("/")
        if not separator or action not in {"archive", "cancel", "replay"}:
            return None
        return job_id, action

    @staticmethod
    def _backup_verify_route(path: str) -> str | None:
        prefix = "/v1/admin/backups/"
        suffix = "/verify"
        if not path.startswith(prefix) or not path.endswith(suffix):
            return None
        backup_id = path[len(prefix): -len(suffix)]
        return backup_id if backup_id and "/" not in backup_id else None

    def _read_model(self, model_type: type[BaseModel]) -> BaseModel | None:
        try:
            body = self._read_request_body()
            return model_type.model_validate_json(body)
        except _RequestTooLarge as error:
            self._send_error(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                "request_too_large",
                str(error),
            )
        except _BadRequest as error:
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "bad_request",
                str(error),
            )
        except ValidationError as error:
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "validation_error",
                "request validation failed",
                _validation_details(error),
            )
        return None

    def _handle_login(self) -> None:
        if not self._auth_required:
            self._send_error(
                HTTPStatus.CONFLICT,
                "authentication_disabled",
                "local authentication is disabled",
            )
            return
        validated = self._read_model(LoginRequest)
        if validated is None:
            return
        request = validated
        assert isinstance(request, LoginRequest)
        try:
            result = self._auth_store.login(
                request.username,
                request.password,
                client_id=str(self.client_address[0]),
            )
            self._send_json(
                HTTPStatus.OK,
                {
                    "principal": self._principal_payload(
                        result.principal
                    ),
                    "csrf_token": result.csrf_token,
                    "absolute_expires_at": result.absolute_expires_at,
                    "idle_expires_at": result.idle_expires_at,
                },
                headers={
                    "Set-Cookie": session_cookie_header(
                        result.session_token,
                        max_age_seconds=(
                            self._auth_store.absolute_timeout_seconds
                        ),
                        secure=self._secure_cookie,
                    )
                },
            )
        except LoginRateLimitedError as error:
            self._send_error(
                HTTPStatus.TOO_MANY_REQUESTS,
                "login_rate_limited",
                "too many failed login attempts",
                headers={"Retry-After": str(error.retry_after_seconds)},
            )
        except InvalidCredentialsError:
            self._send_error(
                HTTPStatus.UNAUTHORIZED,
                "invalid_credentials",
                "invalid username or password",
            )

    def _handle_csrf(self) -> None:
        if not self._auth_required:
            self._send_json(
                HTTPStatus.OK,
                {
                    "principal": self._principal_payload(
                        self._require_authenticated()  # type: ignore[arg-type]
                    ),
                    "csrf_token": None,
                },
            )
            return
        session_token = self._session_token()
        if not session_token:
            self._send_error(
                HTTPStatus.UNAUTHORIZED,
                "authentication_required",
                "login is required",
            )
            return
        try:
            principal, csrf_token = self._auth_store.issue_csrf(
                session_token
            )
            self._send_json(
                HTTPStatus.OK,
                {
                    "principal": self._principal_payload(principal),
                    "csrf_token": csrf_token,
                },
            )
        except InvalidSessionError:
            self._send_error(
                HTTPStatus.UNAUTHORIZED,
                "session_invalid",
                "session is invalid or expired",
            )

    def _handle_logout(self) -> None:
        session_token = self._session_token()
        if session_token:
            self._auth_store.logout(session_token)
        self._send_json(
            HTTPStatus.OK,
            {"status": "logged_out"},
            headers={
                "Set-Cookie": clear_session_cookie_header(
                    secure=self._secure_cookie
                )
            },
        )

    def _handle_change_password(self, principal: Principal) -> None:
        validated = self._read_model(ChangePasswordRequest)
        if validated is None:
            return
        request = validated
        assert isinstance(request, ChangePasswordRequest)
        try:
            self._auth_store.change_password(
                principal.username,
                request.current_password,
                request.new_password,
            )
            self._send_json(
                HTTPStatus.OK,
                {
                    "status": "password_changed",
                    "reauthentication_required": True,
                },
                headers={
                    "Set-Cookie": clear_session_cookie_header(
                        secure=self._secure_cookie
                    )
                },
            )
        except InvalidCredentialsError:
            self._send_error(
                HTTPStatus.UNAUTHORIZED,
                "invalid_credentials",
                "current password is incorrect",
            )

    def _handle_user_create(self, principal: Principal) -> None:
        validated = self._read_model(UserCreateRequest)
        if validated is None:
            return
        request = validated
        assert isinstance(request, UserCreateRequest)
        try:
            user = self._auth_store.create_user(
                request.username,
                request.password,
                request.role,
                request.mine_scopes,
            )
            self._record_audit(
                principal,
                "admin_user_created",
                {
                    "target_username": user.username,
                    "role": user.role.value,
                    "mine_scopes": list(user.mine_scopes),
                },
            )
            self._send_json(
                HTTPStatus.CREATED,
                {"user": user.to_audit_dict()},
            )
        except (UserConflictError, ValueError) as error:
            self._send_error(
                HTTPStatus.CONFLICT,
                "user_conflict",
                str(error),
            )

    def _handle_user_status(
        self,
        username: str,
        principal: Principal,
    ) -> None:
        validated = self._read_model(UserStatusRequest)
        if validated is None:
            return
        request = validated
        assert isinstance(request, UserStatusRequest)
        try:
            target = self._auth_store.get_user(username)
            if target is None:
                raise UserNotFoundError(username)
            if not request.active and target.user_id == principal.user_id:
                self._record_audit(
                    principal,
                    "admin_self_disable_denied",
                    {"target_username": target.username},
                )
                self._send_error(
                    HTTPStatus.CONFLICT,
                    "cannot_disable_self",
                    "an administrator cannot disable their current account",
                )
                return
            user = self._auth_store.set_user_active(
                username,
                request.active,
            )
            self._record_audit(
                principal,
                "admin_user_status_changed",
                {
                    "target_username": user.username,
                    "active": user.active,
                    "reason": (
                        request.reason.strip()
                        if request.reason is not None
                        else None
                    ),
                },
            )
            self._send_json(
                HTTPStatus.OK,
                {"user": user.to_audit_dict()},
            )
        except LastActiveAdminError as error:
            self._record_audit(
                principal,
                "admin_last_active_admin_change_denied",
                {
                    "target_username": username,
                    "requested_active": request.active,
                    "reason": (
                        request.reason.strip()
                        if request.reason is not None
                        else None
                    ),
                },
            )
            self._send_error(
                HTTPStatus.CONFLICT,
                "last_active_admin",
                str(error),
            )
        except UserNotFoundError:
            self._send_error(
                HTTPStatus.NOT_FOUND,
                "user_not_found",
                "user not found",
            )
        except ValueError:
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "invalid_username",
                "username is invalid",
            )

    def _handle_user_access(
        self,
        username: str,
        principal: Principal,
    ) -> None:
        validated = self._read_model(UserAccessRequest)
        if validated is None:
            return
        request = validated
        assert isinstance(request, UserAccessRequest)
        try:
            previous = self._auth_store.get_user(username)
            if previous is None:
                raise UserNotFoundError(username)
            user = self._auth_store.update_user_access(
                username,
                request.role,
                request.mine_scopes,
            )
            reauthentication_required = user.user_id == principal.user_id
            self._record_audit(
                principal,
                "admin_user_access_changed",
                {
                    "target_username": user.username,
                    "previous_role": previous.role.value,
                    "role": user.role.value,
                    "previous_mine_scopes": list(previous.mine_scopes),
                    "mine_scopes": list(user.mine_scopes),
                    "sessions_revoked": True,
                    "reason": (
                        request.reason.strip()
                        if request.reason is not None
                        else None
                    ),
                },
            )
            headers = (
                {
                    "Set-Cookie": clear_session_cookie_header(
                        secure=self._secure_cookie
                    )
                }
                if reauthentication_required
                else None
            )
            self._send_json(
                HTTPStatus.OK,
                {
                    "user": user.to_audit_dict(),
                    "sessions_revoked": True,
                    "reauthentication_required": reauthentication_required,
                },
                headers=headers,
            )
        except LastActiveAdminError as error:
            self._record_audit(
                principal,
                "admin_last_active_admin_change_denied",
                {
                    "target_username": username,
                    "requested_role": request.role.value,
                    "requested_mine_scopes": list(request.mine_scopes),
                    "reason": (
                        request.reason.strip()
                        if request.reason is not None
                        else None
                    ),
                },
            )
            self._send_error(
                HTTPStatus.CONFLICT,
                "last_active_admin",
                str(error),
            )
        except UserNotFoundError:
            self._send_error(
                HTTPStatus.NOT_FOUND,
                "user_not_found",
                "user not found",
            )
        except ValueError as error:
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "invalid_user_access",
                str(error),
            )

    def _handle_password_reset(
        self,
        username: str,
        principal: Principal,
    ) -> None:
        validated = self._read_model(ResetPasswordRequest)
        if validated is None:
            return
        request = validated
        assert isinstance(request, ResetPasswordRequest)
        try:
            user = self._auth_store.get_user(username)
            if user is None:
                raise UserNotFoundError(username)
            reauthentication_required = user.user_id == principal.user_id
            self._auth_store.reset_password(
                username,
                request.new_password,
            )
            self._record_audit(
                principal,
                "admin_password_reset",
                {"target_username": username},
            )
            self._send_json(
                HTTPStatus.OK,
                {
                    "status": "password_reset",
                    "username": username,
                    "sessions_revoked": True,
                    "reauthentication_required": reauthentication_required,
                },
                headers=(
                    {
                        "Set-Cookie": clear_session_cookie_header(
                            secure=self._secure_cookie
                        )
                    }
                    if reauthentication_required
                    else None
                ),
            )
        except UserNotFoundError:
            self._send_error(
                HTTPStatus.NOT_FOUND,
                "user_not_found",
                "user not found",
            )

    def _handle_backup_list(self) -> None:
        manager = self._backup_manager
        if manager is None:
            self._send_error(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "backup_unavailable",
                "backups require persistent database paths",
            )
            return
        self._send_json(
            HTTPStatus.OK,
            {"items": manager.list_backups()},
        )

    def _handle_backup_create(self, principal: Principal) -> None:
        validated = self._read_model(BackupCreateRequest)
        if validated is None:
            return
        request = validated
        assert isinstance(request, BackupCreateRequest)
        manager = self._backup_manager
        if manager is None:
            self._send_error(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "backup_unavailable",
                "backups require persistent database paths",
            )
            return
        manifest: dict[str, Any]
        try:
            self._job_manager.stop()
            try:
                manifest = manager.create_backup(
                    request.backup_id,
                    self._backup_databases,
                )
            finally:
                # Do not acknowledge a successful backup while readiness is
                # still degraded by the intentionally paused worker.
                self._job_manager.start()
        except BackupExistsError as error:
            self._send_error(
                HTTPStatus.CONFLICT,
                "backup_exists",
                str(error),
            )
        except OperationsError:
            self._send_error(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "backup_failed",
                "backup could not be created",
            )
        else:
            self._record_audit(
                principal,
                "backup_created",
                {"backup_id": request.backup_id},
            )
            self._send_json(
                HTTPStatus.CREATED,
                {"manifest": manifest, "verification": "valid"},
            )

    def _handle_backup_verify(self, backup_id: str) -> None:
        manager = self._backup_manager
        if manager is None:
            self._send_error(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "backup_unavailable",
                "backups require persistent database paths",
            )
            return
        try:
            manifest = manager.verify(backup_id)
            self._send_json(
                HTTPStatus.OK,
                {"manifest": manifest, "verification": "valid"},
            )
        except BackupNotFoundError:
            self._send_error(
                HTTPStatus.NOT_FOUND,
                "backup_not_found",
                "backup not found",
            )
        except BackupVerificationError:
            self._send_error(
                HTTPStatus.CONFLICT,
                "backup_invalid",
                "backup verification failed",
            )

    def _handle_source_list(self) -> None:
        self._send_json(
            HTTPStatus.OK,
            {"items": self._governance_repository.list_sources()},
        )

    def _handle_profile_list(self) -> None:
        self._send_json(
            HTTPStatus.OK,
            {"items": self._governance_repository.list_profiles()},
        )

    def _handle_source_register(self, principal: Principal) -> None:
        validated = self._read_model(SourceRegistrationRequest)
        if validated is None:
            return
        request = validated
        assert isinstance(request, SourceRegistrationRequest)
        secret = request.hmac_secret.encode("utf-8")
        source_id = request.definition.source_id
        try:
            existing_secret = self._source_key_store.get(source_id)
            if (
                existing_secret is not None
                and not hmac.compare_digest(existing_secret, secret)
            ):
                raise SourceKeyConflictError(
                    "source already has a different key"
                )
            created = self._governance_repository.register_source(
                request.definition,
                version=request.version,
                effective_from=request.effective_from,
                effective_to=request.effective_to,
            )
            self._source_key_store.put(source_id, secret)
            self._send_json(
                HTTPStatus.CREATED if created else HTTPStatus.OK,
                {
                    "created": created,
                    "source_id": source_id,
                    "version": request.version,
                    "key_present": True,
                },
            )
            self._record_audit(
                principal,
                "source_registered",
                {
                    "source_id": source_id,
                    "version": request.version,
                    "created": created,
                },
            )
        except (
            ConfigurationConflictError,
            SourceKeyConflictError,
            ValueError,
        ) as error:
            self._send_error(
                HTTPStatus.CONFLICT,
                "source_registration_conflict",
                str(error),
            )

    def _handle_profile_register(self, principal: Principal) -> None:
        validated = self._read_model(ProfileRegistrationRequest)
        if validated is None:
            return
        request = validated
        assert isinstance(request, ProfileRegistrationRequest)
        try:
            created = self._governance_repository.register_profile(
                request.profile
            )
            self._send_json(
                HTTPStatus.CREATED if created else HTTPStatus.OK,
                {
                    "created": created,
                    "profile_id": request.profile.profile_id,
                    "version": request.profile.version,
                    "approved": request.profile.approved,
                },
            )
            self._record_audit(
                principal,
                "analysis_profile_registered",
                {
                    "profile_id": request.profile.profile_id,
                    "version": request.profile.version,
                    "approved": request.profile.approved,
                    "created": created,
                },
            )
        except (ConfigurationConflictError, ValueError) as error:
            self._send_error(
                HTTPStatus.CONFLICT,
                "profile_registration_conflict",
                str(error),
            )

    @staticmethod
    def _external_receipt_id(path: str) -> str | None:
        prefix = "/v1/enterprise-submissions/"
        suffix = "/receipt"
        if not path.startswith(prefix) or not path.endswith(suffix):
            return None
        submission_id = path[len(prefix):-len(suffix)]
        if not submission_id or "/" in submission_id:
            return None
        return submission_id

    def _handle_external_capabilities(self) -> None:
        self._send_json(
            HTTPStatus.OK,
            {
                "contract_version": (
                    EXTERNAL_CAPABILITIES_CONTRACT_VERSION
                ),
                "service_id": "mineguard-regulatory-intake",
                "server_time": self._utc_now_text(),
                "supported_submission_contracts": [
                    {
                        "version": (
                            EXTERNAL_SUBMISSION_CONTRACT_VERSION
                        ),
                        "status": "current",
                        "schema_uri": (
                            "urn:mineguard:contract:"
                            "enterprise-submission:v1"
                        ),
                        "submission_path": (
                            "/v1/enterprise-submissions"
                        ),
                    }
                ],
                "authentication": {
                    "scheme": "hmac-sha256",
                    "signature_version": EXTERNAL_SIGNATURE_VERSION,
                    "timestamp_tolerance_seconds": 300,
                    "nonce_retention_seconds": (
                        EXTERNAL_NONCE_RETENTION_SECONDS
                    ),
                },
                "limits": {
                    "max_body_bytes": MAX_REQUEST_BYTES,
                    "max_observations": 10_000,
                },
                "integrity_algorithms": {
                    "submission_payload": "sha-256+rfc8785-jcs",
                    "transport_body": "sha-256+raw-http-body",
                    "observation_signature": (
                        "mineguard-governed-observation-"
                        "hmac-sha256-v1"
                    ),
                },
                "features": {
                    "field_provenance_required": True,
                    "human_confirmation_required": True,
                    "llm_disclosure_required": True,
                    "regulatory_classification_at_intake": False,
                },
            },
        )

    @staticmethod
    def _utc_now_text() -> str:
        return (
            datetime.now(UTC)
            .isoformat()
            .replace("+00:00", "Z")
        )

    def _send_external_error(
        self,
        status: HTTPStatus,
        code: str,
        message: str,
        *,
        retryable: bool,
        submission: EnterpriseSubmission | None = None,
        violations: list[dict[str, str]] | None = None,
        include_server_time: bool = False,
    ) -> None:
        payload: dict[str, Any] = {
            "contract_version": "enterprise-submission-error-v1",
            "error_id": str(uuid4()),
            "occurred_at": self._utc_now_text(),
            "http_status": int(status),
            "code": code,
            "message": message[:1000],
            "retryable": retryable,
            "violations": (violations or [])[:500],
        }
        if submission is not None:
            payload["submission_id"] = submission.submission_id
            payload["idempotency_key"] = submission.idempotency_key
        if include_server_time:
            payload["server_time"] = self._utc_now_text()
        self._send_json(status, payload)

    @staticmethod
    def _external_validation_violations(
        error: ValidationError,
    ) -> list[dict[str, str]]:
        violations: list[dict[str, str]] = []
        for item in error.errors(
            include_url=False,
            include_context=False,
            include_input=False,
        )[:500]:
            location = item.get("loc") or ()
            pointer = "".join(
                "/"
                + str(part).replace("~", "~0").replace("/", "~1")
                for part in location
            )
            violations.append(
                {
                    "json_pointer": pointer,
                    "rule": str(item.get("type") or "validation")[:128],
                    "message": str(
                        item.get("msg") or "validation failed"
                    )[:1000],
                }
            )
        return violations

    def _authenticate_external_transport(
        self,
        *,
        body: bytes,
        method: str,
        path: str,
    ) -> tuple[ExternalClient, datetime] | None:
        if not self._external_clients:
            self._send_external_error(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "EXTERNAL_INTAKE_NOT_CONFIGURED",
                "Enterprise intake authentication is not configured.",
                retryable=False,
            )
            return None
        try:
            for header_name in SIGNED_HEADERS:
                values = self.headers.get_all(header_name, [])
                if len(values) != 1:
                    raise ExternalAuthenticationError(
                        "external request authentication failed"
                    )
            client, request_time, nonce = (
                authenticate_external_request(
                    self._external_clients,
                    self.headers,
                    body,
                    method=method,
                    path=path,
                )
            )
            now = datetime.now(UTC)
            claimed = self._repository.claim_external_request_nonce(
                client_id=client.client_id,
                nonce=nonce,
                request_timestamp=request_time.isoformat(),
                expires_at=(
                    now
                    + timedelta(
                        seconds=EXTERNAL_NONCE_RETENTION_SECONDS
                    )
                ).isoformat(),
            )
            if not claimed:
                raise ExternalAuthenticationError(
                    "external request authentication failed"
                )
            return client, request_time
        except ExternalAuthenticationError:
            self._send_external_error(
                HTTPStatus.UNAUTHORIZED,
                "AUTHENTICATION_FAILED",
                "External request authentication failed.",
                retryable=False,
                include_server_time=True,
            )
            return None

    @staticmethod
    def _external_principal(
        client: ExternalClient,
        mine_id: str,
    ) -> Principal:
        return Principal(
            user_id=f"external:{client.client_id}",
            username=f"external:{client.client_id}",
            role=Role.SUPERVISOR,
            mine_scopes=(mine_id,),
            session_id=f"external:{client.client_id}",
        )

    def _send_duplicate_external_receipt(
        self,
        stored: dict[str, Any],
    ) -> None:
        receipt = deepcopy(stored["receipt"])
        receipt["status"] = "duplicate"
        location = receipt["links"]["self"]
        self._send_json(
            HTTPStatus.OK,
            receipt,
            headers={"Location": location},
        )

    def _handle_external_submission(self, path: str) -> None:
        try:
            body = self._read_request_body()
        except _RequestTooLarge as error:
            self._send_external_error(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                "PAYLOAD_TOO_LARGE",
                str(error),
                retryable=False,
            )
            return
        except _BadRequest as error:
            self._send_external_error(
                HTTPStatus.BAD_REQUEST,
                "BAD_REQUEST",
                str(error),
                retryable=False,
            )
            return

        authenticated = self._authenticate_external_transport(
            body=body,
            method="POST",
            path=path,
        )
        if authenticated is None:
            return
        client, transport_time = authenticated

        try:
            submission = validate_enterprise_submission_json(body)
        except ValidationError as error:
            self._send_external_error(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "SUBMISSION_VALIDATION_FAILED",
                "The enterprise submission failed contract validation.",
                retryable=False,
                violations=self._external_validation_violations(error),
            )
            return
        except ValueError as error:
            is_json_error = "valid JSON" in str(error)
            self._send_external_error(
                (
                    HTTPStatus.BAD_REQUEST
                    if is_json_error
                    else HTTPStatus.UNPROCESSABLE_ENTITY
                ),
                (
                    "INVALID_JSON"
                    if is_json_error
                    else "PAYLOAD_INTEGRITY_FAILED"
                ),
                (
                    "The request body is not valid JSON."
                    if is_json_error
                    else "The payload integrity check failed."
                ),
                retryable=False,
                violations=(
                    []
                    if is_json_error
                    else [
                        {
                            "json_pointer": "/payload_sha256",
                            "rule": "rfc8785_sha256",
                            "message": str(error)[:1000],
                        }
                    ]
                ),
            )
            return

        enterprise_id = submission.payload.enterprise.enterprise_id
        mine_id = submission.payload.mine.mine_id
        if (
            enterprise_id != client.enterprise_id
            or not client.allows_mine(mine_id)
        ):
            self._send_external_error(
                HTTPStatus.FORBIDDEN,
                "SUBMISSION_SCOPE_DENIED",
                "The authenticated client cannot submit this enterprise or mine.",
                retryable=False,
                submission=submission,
            )
            return

        # Exact retries are lookups of an already accepted immutable receipt,
        # not fresh regulatory decisions. Resolve them before consulting the
        # current versioned registries so a later deactivation cannot rewrite
        # the historical outcome or break transport retries.
        body_sha256 = sha256_bytes(body)
        existing = self._repository.get_external_submission_receipt(
            client_id=client.client_id,
            idempotency_key=submission.idempotency_key,
        )
        if existing is not None:
            if (
                existing["submission_id"] == submission.submission_id
                and existing["payload_sha256"]
                == submission.payload_sha256
                and existing.get("body_sha256") == body_sha256
            ):
                self._send_duplicate_external_receipt(existing)
            else:
                self._send_external_error(
                    HTTPStatus.CONFLICT,
                    "IDEMPOTENCY_CONFLICT",
                    "The idempotency key is already bound to different content.",
                    retryable=False,
                    submission=submission,
                )
            return
        same_submission = (
            self._repository.get_external_submission_receipt_by_submission_id(
                client_id=client.client_id,
                submission_id=submission.submission_id,
            )
        )
        if same_submission is not None:
            self._send_external_error(
                HTTPStatus.CONFLICT,
                "SUBMISSION_ID_CONFLICT",
                "The submission identifier is already in use.",
                retryable=False,
                submission=submission,
            )
            return

        confirmation = submission.payload.human_confirmation
        try:
            confirmer_registration = (
                self._repository
                .find_current_external_confirmer_registration(
                    client_id=client.client_id,
                    enterprise_id=enterprise_id,
                    confirmer_id=confirmation.confirmer_id,
                    confirmer_name=confirmation.confirmer_name,
                    confirmer_role=confirmation.confirmer_role,
                    confirmation_method=(
                        confirmation.confirmation_method
                    ),
                )
            )
        except AlgorithmRecordIntegrityError:
            self._send_external_error(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "CONFIRMER_REGISTRY_INTEGRITY_ERROR",
                "The regulator confirmer registry failed integrity "
                "validation.",
                retryable=True,
                submission=submission,
            )
            return
        if confirmer_registration is None:
            self._send_external_error(
                HTTPStatus.FORBIDDEN,
                "CONFIRMER_NOT_AUTHORIZED",
                "The confirmer identity, role, or method is not authorized "
                "by the regulator's current registry version for this "
                "enterprise client.",
                retryable=False,
                submission=submission,
                violations=[
                    {
                        "json_pointer": (
                            "/payload/human_confirmation/confirmer_id"
                        ),
                        "rule": "authorized_confirmer",
                        "message": (
                            "No active regulator-owned confirmer registration "
                            "exactly matches this identity, role and method."
                        ),
                    }
                ],
            )
            return

        event_provenance = (
            submission.payload.operational_context.field_provenance
            .approved_event_codes
        )
        event_snapshot = self._repository.find_external_event_snapshot(
            event_codes=(
                submission.payload.operational_context.approved_event_codes
            ),
            mine_id=mine_id,
            window_start=submission.payload.window.window_start,
            window_end=submission.payload.window.window_end,
            evidence_sha256={
                record.evidence_sha256
                for record in event_provenance
            },
        )
        if event_snapshot is None:
            self._send_external_error(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "EVENT_SNAPSHOT_NOT_VERIFIED",
                "The exact approved-event query result is not present in the "
                "regulator-controlled snapshot registry for this mine, "
                "window, code set, and evidence digest.",
                retryable=False,
                submission=submission,
                violations=[
                    {
                        "json_pointer": (
                            "/payload/operational_context/"
                            "approved_event_codes"
                        ),
                        "rule": "regulator_verified_event_snapshot",
                        "message": (
                            "The complete event-code set, including an empty "
                            "set, must match a regulator-side query snapshot."
                        ),
                    }
                ],
            )
            return

        submission_future_seconds = (
            submission.submitted_at.astimezone(UTC)
            - transport_time
        ).total_seconds()
        if submission_future_seconds > EXTERNAL_AUTH_WINDOW_SECONDS:
            self._send_external_error(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "SUBMISSION_TIME_INVALID",
                "A submission timestamp cannot be later than its "
                "authenticated transport timestamp.",
                retryable=False,
                submission=submission,
                violations=[
                    {
                        "json_pointer": "/submitted_at",
                        "rule": "transport_time_binding",
                        "message": (
                            "submitted_at is later than the allowed "
                            "authenticated transport clock skew."
                        ),
                    }
                ],
            )
            return

        request = to_governed_production_request(submission)
        principal = self._external_principal(client, mine_id)
        try:
            _, analysis, batch_id = self._execute_governed_ingest(
                request,
                principal,
                context_additions={
                    "kind": "enterprise_agent_governed_ingest",
                    "external_submission": (
                        submission.model_dump(mode="json")
                    ),
                    "external_body_sha256": body_sha256,
                    "external_client_id": client.client_id,
                    "external_confirmer_registration": {
                        "registration_id": confirmer_registration[
                            "registration_id"
                        ],
                        "client_id": confirmer_registration["client_id"],
                        "enterprise_id": confirmer_registration[
                            "enterprise_id"
                        ],
                        "confirmer_id": confirmer_registration[
                            "confirmer_id"
                        ],
                        "version": confirmer_registration["version"],
                        "content_sha256": confirmer_registration[
                            "content_sha256"
                        ],
                    },
                    "external_event_snapshot": {
                        "snapshot_id": event_snapshot["snapshot_id"],
                        "content_sha256": event_snapshot[
                            "content_sha256"
                        ],
                        "evidence_sha256": event_snapshot[
                            "evidence_sha256"
                        ],
                    },
                },
                batch_discriminator=(
                    f"{client.client_id}:{submission.submission_id}:"
                    f"{submission.payload_sha256}"
                ),
            )
            warnings = [
                {
                    "code": str(issue.get("code") or "QUALITY_WARNING"),
                    "message": str(
                        issue.get("message") or "Quality warning"
                    ),
                }
                for issue in (
                    (analysis.get("governance") or {}).get(
                        "quality_issues",
                        [],
                    )
                )
                if issue.get("severity") == "warning"
            ][:100]
            receipt = {
                "contract_version": (
                    EXTERNAL_RECEIPT_CONTRACT_VERSION
                ),
                "submission_contract_version": (
                    EXTERNAL_SUBMISSION_CONTRACT_VERSION
                ),
                "receipt_id": str(uuid4()),
                "submission_id": submission.submission_id,
                "idempotency_key": submission.idempotency_key,
                "received_at": self._utc_now_text(),
                "status": "accepted",
                "payload_sha256": submission.payload_sha256,
                "intake_batch_id": batch_id,
                "regulatory_outcome": (
                    "not_determined_at_intake"
                ),
                "warnings": warnings,
                "links": {
                    "self": (
                        "/v1/enterprise-submissions/"
                        f"{submission.submission_id}/receipt"
                    ),
                },
            }
            stored = self._repository.save_external_submission_receipt(
                submission_id=submission.submission_id,
                client_id=client.client_id,
                enterprise_id=enterprise_id,
                mine_id=mine_id,
                idempotency_key=submission.idempotency_key,
                payload_sha256=submission.payload_sha256,
                receipt=receipt,
                submission_body=body,
            )
            if not stored["created"]:
                self._send_duplicate_external_receipt(stored)
                return
            self._record_audit(
                principal,
                "external_submission_received",
                {
                    "submission_id": submission.submission_id,
                    "idempotency_key": submission.idempotency_key,
                    "payload_sha256": submission.payload_sha256,
                    "body_sha256": body_sha256,
                    "batch_id": batch_id,
                    "enterprise_id": enterprise_id,
                    "mine_id": mine_id,
                    "llm_used": (
                        submission.payload.llm_assistance.used
                    ),
                },
            )
            self._send_json(
                HTTPStatus.ACCEPTED,
                receipt,
                headers={"Location": receipt["links"]["self"]},
            )
        except _GovernedInputRejected as error:
            violations = [
                {
                    "json_pointer": "/payload/observations",
                    "rule": str(
                        detail.get("code") or "governance"
                    )[:128],
                    "message": str(
                        detail.get("message") or str(error)
                    )[:1000],
                }
                for detail in error.details
            ]
            self._send_external_error(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "GOVERNANCE_REJECTED",
                str(error),
                retryable=False,
                submission=submission,
                violations=violations,
            )
        except (
            ProfileNotApprovedError,
            ProfileNotEffectiveError,
            ProfileNotFoundError,
        ):
            self._send_external_error(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "GOVERNANCE_CONFIGURATION_REJECTED",
                "The requested regulatory profile is unavailable or not effective.",
                retryable=False,
                submission=submission,
            )
        except (
            AlgorithmRecordIntegrityError,
            BatchConflictError,
            ExternalSubmissionConflictError,
            GovernanceError,
        ):
            self._send_external_error(
                HTTPStatus.CONFLICT,
                "REGULATORY_INTAKE_CONFLICT",
                "The submission conflicts with existing regulatory state.",
                retryable=False,
                submission=submission,
            )
        except Exception:
            self.log_error("external enterprise ingestion failed")
            self._send_external_error(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Internal server error.",
                retryable=True,
                submission=submission,
            )

    def _handle_external_receipt_get(
        self,
        submission_id: str,
        path: str,
    ) -> None:
        try:
            parsed = UUID(submission_id)
            if str(parsed) != submission_id.lower():
                raise ValueError("non-canonical UUID")
        except ValueError:
            self._send_external_error(
                HTTPStatus.BAD_REQUEST,
                "INVALID_SUBMISSION_ID",
                "The submission identifier is not a canonical UUID.",
                retryable=False,
            )
            return
        raw_length = self.headers.get("Content-Length")
        if raw_length not in {None, "0"}:
            self._send_external_error(
                HTTPStatus.BAD_REQUEST,
                "GET_BODY_NOT_ALLOWED",
                "Receipt requests cannot include a body.",
                retryable=False,
            )
            return
        authenticated = self._authenticate_external_transport(
            body=b"",
            method="GET",
            path=path,
        )
        if authenticated is None:
            return
        client, _transport_time = authenticated
        stored = (
            self._repository.get_external_submission_receipt_by_submission_id(
                client_id=client.client_id,
                submission_id=submission_id,
            )
        )
        if stored is None:
            self._send_external_error(
                HTTPStatus.NOT_FOUND,
                "RECEIPT_NOT_FOUND",
                "Submission receipt not found.",
                retryable=False,
            )
            return
        self._send_json(HTTPStatus.OK, stored["receipt"])

    def _execute_governed_ingest(
        self,
        request: GovernedProductionRequest,
        principal: Principal,
        *,
        context_additions: dict[str, Any] | None = None,
        batch_discriminator: str | None = None,
    ) -> tuple[HTTPStatus, dict[str, Any], str]:
        request_sha256 = governance_sha256_json(request)
        if batch_discriminator is None:
            # Preserve the established internal governed-ingestion identity.
            batch_id = f"trusted-{request_sha256[:32]}"
        else:
            batch_material_sha256 = governance_sha256_json(
                {
                    "governed_request_sha256": request_sha256,
                    "batch_discriminator": batch_discriminator,
                }
            )
            batch_id = f"trusted-{batch_material_sha256[:32]}"
        existing = self._repository.get_batch(batch_id)
        if existing is not None:
            if existing.get("integrity_valid") is not True:
                raise AlgorithmRecordIntegrityError(
                    "stored batch failed request, response or context "
                    "integrity verification"
                )
            temporal_audit = self._refresh_temporal_audit(
                {request.mine_id}
            )
            return (
                HTTPStatus.OK,
                {
                    "created": False,
                    "batch": existing["response"],
                    "governance": existing.get("context"),
                    "temporal_audit": temporal_audit,
                },
                batch_id,
            )

        prepared = self._governance_service.prepare(request)
        blocking = [
            issue.model_dump(mode="json")
            for issue in prepared.quality_issues
            if issue.blocking
        ]
        if blocking or prepared.request is None:
            raise _GovernedInputRejected(blocking)

        calibrated_request, calibration = apply_historical_calibration(
            self._repository,
            prepared.request,
            engine_version=__version__,
            trusted_mode="governed",
            profile_id=request.profile_id,
            profile_version=prepared.profile_version,
            registry_snapshot_hash=(
                prepared.registry_snapshot_hash
            ),
            operational_context=request.operational_context,
        )
        context = {
            "kind": "governed_production_ingest",
            "ingested_by": principal.username,
            "runtime_manifest": build_runtime_manifest(),
            "governed_request_sha256": request_sha256,
            "profile_id": request.profile_id,
            "profile_version": prepared.profile_version,
            "registry_snapshot_hash": (
                prepared.registry_snapshot_hash
            ),
            "accepted_count": prepared.accepted_count,
            "rejected_count": prepared.rejected_count,
            "quality_issues": [
                issue.model_dump(mode="json")
                for issue in prepared.quality_issues
            ],
            "calibration": calibration.model_dump(mode="json"),
            "operational_context": request.operational_context.model_dump(
                mode="json"
            ),
            "observation_envelopes": [
                observation.model_dump(mode="json")
                for observation in request.observations
            ],
        }
        if context_additions is not None:
            context.update(context_additions)
        portfolio_request = PortfolioAnalysisRequest(
            batch_id=batch_id,
            portfolio_name=f"{request.mine_id}可信数据接入",
            expected_mine_ids=[request.mine_id],
            analyses=[calibrated_request],
        )
        physical_result = analyze_production_portfolio(
            portfolio_request
        )
        result = enrich_portfolio_historical_evidence(
            self._repository,
            portfolio_request,
            physical_result,
            engine_version=__version__,
            context_obj=context,
        )
        stored = self._repository.save_portfolio_batch(
            portfolio_request,
            result,
            __version__,
            context_obj=context,
        )
        temporal_audit = self._refresh_temporal_audit(
            {request.mine_id}
        )
        self._record_audit(
            principal,
            "governed_ingest_accepted",
            {
                "batch_id": batch_id,
                "mine_id": request.mine_id,
                "profile_id": request.profile_id,
                "profile_version": request.profile_version,
                "registry_snapshot_hash": (
                    prepared.registry_snapshot_hash
                ),
            },
        )
        return (
            HTTPStatus.CREATED,
            {
                "created": stored["created"],
                "batch": stored["batch"],
                "governance": context,
                "temporal_audit": temporal_audit,
            },
            batch_id,
        )

    def _handle_governed_ingest(self, principal: Principal) -> None:
        validated = self._read_model(GovernedProductionRequest)
        if validated is None:
            return
        request = validated
        assert isinstance(request, GovernedProductionRequest)
        if not self._require_permission(
            principal,
            Permission.ANALYSIS_RUN,
            mine_id=request.mine_id,
        ):
            return

        try:
            status, payload, _ = self._execute_governed_ingest(
                request,
                principal,
            )
            self._send_json(status, payload)
        except _GovernedInputRejected as error:
            self._send_error(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "governance_rejected",
                str(error),
                error.details,
            )
        except (
            ProfileNotApprovedError,
            ProfileNotEffectiveError,
            ProfileNotFoundError,
        ) as error:
            self._send_error(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "governance_configuration_rejected",
                str(error),
            )
        except GovernanceError:
            self._send_error(
                HTTPStatus.CONFLICT,
                "governance_conflict",
                "governance persistence conflict",
            )
        except AlgorithmRecordIntegrityError as error:
            self._send_error(
                HTTPStatus.CONFLICT,
                "batch_integrity_error",
                str(error),
            )
        except BatchConflictError as error:
            self._send_error(
                HTTPStatus.CONFLICT,
                "batch_conflict",
                str(error),
            )
        except Exception:
            self.log_error("governed production ingestion failed")
            self._send_error(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "internal_error",
                "internal server error",
            )

    def _handle_governed_portfolio_ingest(
        self,
        principal: Principal,
    ) -> None:
        validated = self._read_model(GovernedPortfolioIngestRequest)
        if validated is None:
            return
        request = validated
        assert isinstance(request, GovernedPortfolioIngestRequest)
        for mine_id in request.expected_mine_ids:
            if not self._require_permission(
                principal,
                Permission.ANALYSIS_RUN,
                mine_id=mine_id,
            ):
                return

        request_sha256 = governance_sha256_json(request)
        existing = self._repository.get_batch(request.batch_id)
        if existing is not None:
            if existing.get("integrity_valid") is not True:
                self._send_error(
                    HTTPStatus.CONFLICT,
                    "batch_integrity_error",
                    "stored batch failed request, response or context "
                    "integrity verification",
                )
                return
            context = existing.get("context") or {}
            if context.get("governed_request_sha256") != request_sha256:
                self._send_error(
                    HTTPStatus.CONFLICT,
                    "batch_conflict",
                    "batch_id already exists with different trusted input",
                )
                return
            received_mines = {
                str(report["mine_id"])
                for report in context.get("mine_reports", [])
                if (
                    isinstance(report, dict)
                    and report.get("accepted") is True
                    and isinstance(report.get("mine_id"), str)
                )
            }
            temporal_audit = self._refresh_temporal_audit(
                received_mines
            )
            self._send_json(
                HTTPStatus.OK,
                {
                    "created": False,
                    "partial": bool(context.get("partial")),
                    "batch": existing["response"],
                    "governance": context,
                    "temporal_audit": temporal_audit,
                },
            )
            return

        derived_requests: list[ProductionAnalysisRequest] = []
        reports: list[dict[str, Any]] = []
        for governed in request.analyses:
            try:
                prepared = self._governance_service.prepare(governed)
                blocking = [
                    issue.model_dump(mode="json")
                    for issue in prepared.quality_issues
                    if issue.blocking
                ]
                accepted = not blocking and prepared.request is not None
                if accepted:
                    assert prepared.request is not None
                    calibrated_request, calibration = (
                        apply_historical_calibration(
                            self._repository,
                            prepared.request,
                            engine_version=__version__,
                            trusted_mode="governed",
                            profile_id=governed.profile_id,
                            profile_version=prepared.profile_version,
                            registry_snapshot_hash=(
                                prepared.registry_snapshot_hash
                            ),
                            operational_context=(
                                governed.operational_context
                            ),
                        )
                    )
                    derived_requests.append(calibrated_request)
                else:
                    calibration = None
                reports.append(
                    {
                        "mine_id": governed.mine_id,
                        "ingested_by": principal.username,
                        "accepted": accepted,
                        "profile_id": governed.profile_id,
                        "profile_version": governed.profile_version,
                        "registry_snapshot_hash": (
                            prepared.registry_snapshot_hash
                        ),
                        "accepted_count": prepared.accepted_count,
                        "rejected_count": prepared.rejected_count,
                        "quality_issues": [
                            issue.model_dump(mode="json")
                            for issue in prepared.quality_issues
                        ],
                        "calibration": (
                            calibration.model_dump(mode="json")
                            if calibration is not None
                            else None
                        ),
                        "operational_context": (
                            governed.operational_context.model_dump(
                                mode="json"
                            )
                        ),
                        "observation_envelopes": [
                            observation.model_dump(mode="json")
                            for observation in governed.observations
                        ],
                    }
                )
            except (
                ProfileNotApprovedError,
                ProfileNotEffectiveError,
                ProfileNotFoundError,
            ) as error:
                reports.append(
                    {
                        "mine_id": governed.mine_id,
                        "accepted": False,
                        "profile_id": governed.profile_id,
                        "profile_version": governed.profile_version,
                        "configuration_error": str(error),
                        "quality_issues": [],
                        "observation_envelopes": [
                            observation.model_dump(mode="json")
                            for observation in governed.observations
                        ],
                    }
                )
            except GovernanceError:
                self._send_error(
                    HTTPStatus.CONFLICT,
                    "governance_conflict",
                    "governance persistence conflict",
                )
                return

        received_mines = {
            derived.mine_id for derived in derived_requests
        }
        partial = (
            len(received_mines) != len(request.expected_mine_ids)
        )
        context = {
            "kind": "governed_portfolio_ingest",
            "ingested_by": principal.username,
            "runtime_manifest": build_runtime_manifest(),
            "governed_request_sha256": request_sha256,
            "partial": partial,
            "accepted_mine_count": len(received_mines),
            "rejected_submission_count": sum(
                not report["accepted"] for report in reports
            ),
            "mine_reports": reports,
        }
        portfolio_request = PortfolioAnalysisRequest(
            batch_id=request.batch_id,
            portfolio_name=request.portfolio_name,
            expected_mine_ids=request.expected_mine_ids,
            analyses=derived_requests,
        )
        try:
            physical_result = analyze_production_portfolio(
                portfolio_request
            )
            result = enrich_portfolio_historical_evidence(
                self._repository,
                portfolio_request,
                physical_result,
                engine_version=__version__,
                context_obj=context,
            )
            stored = self._repository.save_portfolio_batch(
                portfolio_request,
                result,
                __version__,
                context_obj=context,
            )
            temporal_audit = self._refresh_temporal_audit(
                received_mines
            )
            self._record_audit(
                principal,
                "governed_portfolio_ingest_accepted",
                {
                    "batch_id": request.batch_id,
                    "expected_mine_count": len(request.expected_mine_ids),
                    "accepted_mine_count": len(received_mines),
                    "partial": partial,
                },
            )
            self._send_json(
                HTTPStatus.CREATED,
                {
                    "created": stored["created"],
                    "partial": partial,
                    "batch": stored["batch"],
                    "governance": context,
                    "temporal_audit": temporal_audit,
                },
            )
        except BatchConflictError as error:
            self._send_error(
                HTTPStatus.CONFLICT,
                "batch_conflict",
                str(error),
            )
        except GovernanceError:
            self._send_error(
                HTTPStatus.CONFLICT,
                "governance_conflict",
                "governance persistence conflict",
            )
        except Exception:
            self.log_error("governed portfolio ingestion failed")
            self._send_error(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "internal_error",
                "internal server error",
            )

    def _handle_governed_job_submit(
        self,
        principal: Principal,
    ) -> None:
        validated = self._read_model(GovernedJobSubmitRequest)
        if validated is None:
            return
        request = validated
        assert isinstance(request, GovernedJobSubmitRequest)
        for window in request.windows:
            if not self._require_permission(
                principal,
                Permission.ANALYSIS_RUN,
                mine_id=window.request.mine_id,
            ):
                return
        try:
            record, created = self._job_manager.submit(
                AnalysisJobRequest(
                    idempotency_key=request.idempotency_key,
                    requested_by=principal.username,
                    windows=[
                        AnalysisWindow(
                            window_id=window.window_id,
                            mine_id=window.request.mine_id,
                            payload={
                                "_mineguard_kind": "governed_production",
                                "ingested_by": principal.username,
                                "request": window.request.model_dump(
                                    mode="json"
                                ),
                            },
                        )
                        for window in request.windows
                    ],
                )
            )
            self._record_audit(
                principal,
                "governed_analysis_job_submitted",
                {
                    "job_id": record.job_id,
                    "created": created,
                    "window_count": len(request.windows),
                },
            )
            self._send_json(
                HTTPStatus.ACCEPTED if created else HTTPStatus.OK,
                {"job": record},
            )
        except JobConflictError as error:
            self._send_error(
                HTTPStatus.CONFLICT,
                "job_conflict",
                str(error),
            )
        except JobCapacityError as error:
            self._send_error(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "job_capacity_full",
                str(error),
            )

    def _handle_job_submit(self, principal: Principal) -> None:
        validated = self._read_model(JobSubmitRequest)
        if validated is None:
            return
        request = validated
        assert isinstance(request, JobSubmitRequest)
        if self._auth_required and principal.role is not Role.ADMIN:
            self._send_error(
                HTTPStatus.FORBIDDEN,
                "trusted_ingest_required",
                "caller-supplied asynchronous analysis is restricted to "
                "administrators; use trusted ingestion",
            )
            return
        for window in request.windows:
            if not self._require_permission(
                principal,
                Permission.ANALYSIS_RUN,
                mine_id=window.mine_id,
            ):
                return
        try:
            record, created = self._job_manager.submit(
                AnalysisJobRequest(
                    idempotency_key=request.idempotency_key,
                    requested_by=principal.username,
                    windows=request.windows,
                )
            )
            self._record_audit(
                principal,
                "analysis_job_submitted",
                {
                    "job_id": record.job_id,
                    "created": created,
                    "window_count": len(request.windows),
                },
            )
            self._send_json(
                HTTPStatus.ACCEPTED if created else HTTPStatus.OK,
                {"job": record},
            )
        except JobConflictError as error:
            self._send_error(
                HTTPStatus.CONFLICT,
                "job_conflict",
                str(error),
            )
        except JobCapacityError as error:
            self._send_error(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "job_capacity_full",
                str(error),
            )

    def _visible_job(
        self,
        record: Any,
        principal: Principal,
    ) -> dict[str, Any] | None:
        payload = record.model_dump(mode="json")
        scopes = self._visible_mines(principal)
        if scopes is None:
            return payload
        visible = [
            outcome
            for outcome in payload["outcomes"]
            if outcome["mine_id"] in scopes
        ]
        if not visible:
            return None
        payload["outcomes"] = visible
        statuses = [str(outcome["status"]) for outcome in visible]
        succeeded = statuses.count("succeeded")
        failed = statuses.count("failed")
        cancelled = statuses.count("cancelled")
        completed = succeeded + failed + cancelled
        payload["total_windows"] = len(visible)
        payload["completed_windows"] = completed
        payload["succeeded_windows"] = succeeded
        payload["failed_windows"] = failed
        payload["cancelled_windows"] = cancelled
        if completed == len(visible):
            if cancelled == len(visible):
                payload["status"] = "cancelled"
            elif failed == len(visible):
                payload["status"] = "failed"
            elif succeeded == len(visible):
                payload["status"] = "succeeded"
            else:
                payload["status"] = "partial_failed"
        elif "running" in statuses or completed:
            payload["status"] = "running"
        else:
            payload["status"] = "queued"
        payload.pop("request_sha256", None)
        return payload

    @staticmethod
    def _job_list_query(query: str) -> bool | None:
        """Return archive visibility, rejecting every non-canonical query."""

        if not query:
            return False
        try:
            values = parse_qs(
                query,
                keep_blank_values=True,
                strict_parsing=True,
                max_num_fields=1,
                separator="&",
            )
        except ValueError:
            return None
        if set(values) != {"include_archived"}:
            return None
        if values["include_archived"] != ["1"]:
            return None
        return True

    def _handle_job_list(
        self,
        query: str,
        principal: Principal,
    ) -> None:
        include_archived = self._job_list_query(query)
        if include_archived is None:
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "invalid_query",
                "the only supported job query parameter is "
                "include_archived=1",
            )
            return
        items = [
            visible
            for record in self._job_manager.list(
                include_archived=include_archived
            )
            if (visible := self._visible_job(record, principal)) is not None
        ]
        self._send_json(
            HTTPStatus.OK,
            {"items": items, "total": len(items)},
        )

    def _handle_job_detail(
        self,
        job_id: str,
        principal: Principal,
    ) -> None:
        try:
            visible = self._visible_job(
                self._job_manager.get(job_id),
                principal,
            )
            if visible is None:
                raise PermissionDeniedError("job outside mine scope")
            self._send_json(HTTPStatus.OK, {"job": visible})
        except JobNotFoundError:
            self._send_error(
                HTTPStatus.NOT_FOUND,
                "job_not_found",
                "analysis job not found",
            )
        except PermissionDeniedError:
            self._send_error(
                HTTPStatus.FORBIDDEN,
                "permission_denied",
                "permission or mine scope denied",
            )

    def _handle_job_action(
        self,
        job_id: str,
        action: str,
        principal: Principal,
    ) -> None:
        try:
            existing = self._job_manager.get(job_id)
            for outcome in existing.outcomes:
                if not self._require_permission(
                    principal,
                    Permission.ANALYSIS_RUN,
                    mine_id=outcome.mine_id,
                ):
                    return
            if action == "cancel":
                result = self._job_manager.cancel(job_id)
                self._record_audit(
                    principal,
                    "analysis_job_cancelled",
                    {"job_id": job_id},
                )
                self._send_json(HTTPStatus.OK, {"job": result})
                return
            if action == "archive":
                validated = self._read_model(JobArchiveRequest)
                if validated is None:
                    return
                request = validated
                assert isinstance(request, JobArchiveRequest)
                result = self._job_manager.archive(
                    job_id,
                    archived=request.archived,
                    archived_by=principal.username,
                    reason=request.reason,
                )
                event = (
                    "analysis_job_archived"
                    if request.archived
                    else "analysis_job_restored"
                )
                self._record_audit(
                    principal,
                    event,
                    {
                        "job_id": job_id,
                        "reason": request.reason.strip(),
                    },
                )
                self._send_json(HTTPStatus.OK, {"job": result})
                return
            if self._auth_required and principal.role is not Role.ADMIN:
                self._send_error(
                    HTTPStatus.FORBIDDEN,
                    "trusted_ingest_required",
                    "replaying caller-supplied jobs is restricted to "
                    "administrators",
                )
                return
            validated = self._read_model(JobReplayRequest)
            if validated is None:
                return
            request = validated
            assert isinstance(request, JobReplayRequest)
            result, created = self._job_manager.replay(
                job_id,
                idempotency_key=request.idempotency_key,
                requested_by=principal.username,
            )
            self._record_audit(
                principal,
                "analysis_job_replayed",
                {
                    "job_id": result.job_id,
                    "parent_job_id": job_id,
                    "created": created,
                },
            )
            self._send_json(
                HTTPStatus.ACCEPTED if created else HTTPStatus.OK,
                {"job": result},
            )
        except JobNotFoundError:
            self._send_error(
                HTTPStatus.NOT_FOUND,
                "job_not_found",
                "analysis job not found",
            )
        except (JobConflictError, JobStateError) as error:
            self._send_error(
                HTTPStatus.CONFLICT,
                "job_action_conflict",
                str(error),
            )

    @staticmethod
    def _portfolio_preview_query(query: str) -> bool | None:
        """Return preview mode, or ``None`` for an invalid query string."""

        if not query:
            return False
        try:
            values = parse_qs(
                query,
                keep_blank_values=True,
                strict_parsing=True,
                max_num_fields=1,
                separator="&",
            )
        except ValueError:
            return None
        if set(values) != {"preview"} or values["preview"] != ["1"]:
            return None
        return True

    def _handle_portfolio_batch(
        self,
        principal: Principal,
        query: str,
    ) -> None:
        preview = self._portfolio_preview_query(query)
        if preview is None:
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "invalid_query",
                "the only supported batch query parameter is preview=1",
            )
            return
        validated = self._read_model(PortfolioAnalysisRequest)
        if validated is None:
            return
        request = validated
        assert isinstance(request, PortfolioAnalysisRequest)
        if self._auth_required and principal.role is not Role.ADMIN:
            self._send_error(
                HTTPStatus.FORBIDDEN,
                "trusted_ingest_required",
                "caller-supplied analysis parameters are restricted to "
                "administrators; use trusted ingestion",
            )
            return
        for mine_id in request.expected_mine_ids:
            if not self._require_permission(
                principal,
                Permission.ANALYSIS_RUN,
                mine_id=mine_id,
            ):
                return

        try:
            if preview:
                # A pilot preview is deliberately compute-only: it must not
                # create batches, runs, cases, algorithm features, monitoring
                # findings, or audit events.
                self._send_json(
                    HTTPStatus.OK,
                    analyze_production_portfolio(request),
                )
                return

            received_mines = {
                analysis.mine_id for analysis in request.analyses
            }
            existing = self._repository.get_batch(request.batch_id)
            if existing is not None:
                if existing.get("integrity_valid") is not True:
                    self._send_error(
                        HTTPStatus.CONFLICT,
                        "batch_integrity_error",
                        "stored batch failed request, response or context "
                        "integrity verification",
                    )
                    return
                if existing["request_sha256"] != sha256_json(request):
                    raise BatchConflictError(
                        "batch_id already exists with different input"
                    )
                temporal_audit = self._refresh_temporal_audit(
                    received_mines
                )
                self._send_json(
                    HTTPStatus.OK,
                    {
                        **existing["response"],
                        "temporal_audit": temporal_audit,
                    },
                )
                return

            result = analyze_production_portfolio(request)
            stored = self._repository.save_portfolio_batch(
                request,
                result,
                __version__,
                context_obj={
                    "kind": "direct_admin_sandbox",
                    "runtime_manifest": build_runtime_manifest(),
                },
            )
            temporal_audit = self._refresh_temporal_audit(
                received_mines
            )
            self._record_audit(
                principal,
                "direct_batch_analyzed",
                {
                    "batch_id": request.batch_id,
                    "mine_count": len(request.expected_mine_ids),
                    "created": stored["created"],
                },
            )
            self._send_json(
                HTTPStatus.OK,
                {
                    **stored["batch"],
                    "temporal_audit": temporal_audit,
                },
            )
        except BatchConflictError as error:
            self._send_error(
                HTTPStatus.CONFLICT,
                "batch_conflict",
                str(error),
            )
        except Exception:
            self.log_error("portfolio analysis operation failed")
            self._send_error(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "internal_error",
                "internal server error",
            )

    def _handle_analysis_batch_list(self, query: str) -> None:
        values = parse_qs(query, keep_blank_values=True)
        if set(values) - {"include_invalidated", "limit"} or any(
            len(entries) != 1 for entries in values.values()
        ):
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "invalid_query",
                "supported parameters are include_invalidated and limit",
            )
            return
        raw_include = values.get("include_invalidated", ["false"])[0]
        if raw_include not in {"true", "false", "1", "0"}:
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "invalid_query",
                "include_invalidated must be true, false, 1 or 0",
            )
            return
        try:
            limit = int(values.get("limit", ["100"])[0])
        except ValueError:
            limit = 0
        if not 1 <= limit <= 1000:
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "invalid_query",
                "limit must be an integer from 1 to 1000",
            )
            return
        batches = self._repository.list_batches(
            limit=limit,
            include_invalidated=raw_include in {"true", "1"},
        )
        items = []
        for batch in batches:
            response_items = batch["response"].get("items", [])
            context = batch.get("context")
            items.append(
                {
                    "batch_id": batch["batch_id"],
                    "portfolio_name": batch["portfolio_name"],
                    "created_at": batch["created_at"],
                    "request_sha256": batch["request_sha256"],
                    "data_mode": (
                        context.get("kind")
                        if isinstance(context, dict)
                        else None
                    ),
                    "mine_count": len(response_items),
                    "lifecycle": batch["lifecycle"],
                }
            )
        self._send_json(
            HTTPStatus.OK,
            {"items": items, "total": len(items)},
        )

    def _handle_analysis_batch_detail(
        self,
        batch_id: str,
        *,
        audit_only: bool,
    ) -> None:
        batch = self._repository.get_batch(batch_id)
        if batch is None:
            self._send_error(
                HTTPStatus.NOT_FOUND,
                "batch_not_found",
                "analysis batch not found",
            )
            return
        events = self._repository.get_batch_lifecycle_events(batch_id)
        payload: dict[str, Any] = {
            "batch_id": batch_id,
            "lifecycle": batch["lifecycle"],
            "lifecycle_events": events,
            "lifecycle_chain_valid": (
                self._repository.verify_batch_lifecycle_chain(batch_id)
            ),
        }
        if not audit_only:
            payload["batch"] = batch
        self._send_json(HTTPStatus.OK, payload)

    def _handle_analysis_batch_status(
        self,
        batch_id: str,
        principal: Principal,
    ) -> None:
        validated = self._read_model(BatchStatusRequest)
        if validated is None:
            return
        request = validated
        assert isinstance(request, BatchStatusRequest)
        try:
            result = self._repository.set_batch_active(
                batch_id,
                active=request.active,
                expected_version=request.expected_version,
                actor=principal.username,
                reason=request.reason,
            )
        except BatchNotFoundError:
            self._send_error(
                HTTPStatus.NOT_FOUND,
                "batch_not_found",
                "analysis batch not found",
            )
            return
        except VersionConflictError as error:
            self._send_error(
                HTTPStatus.CONFLICT,
                "version_conflict",
                str(error),
            )
            return
        except ValueError as error:
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "invalid_batch_status",
                str(error),
            )
            return
        audit_action = (
            "analysis_batch_status_unchanged"
            if not result["changed"]
            else (
                "analysis_batch_restored"
                if request.active
                else "analysis_batch_invalidated"
            )
        )
        self._record_audit(
            principal,
            audit_action,
            {
                "batch_id": batch_id,
                "reason": request.reason.strip(),
                "changed": result["changed"],
                "lifecycle_version": result["lifecycle"]["version"],
            },
        )
        self._send_json(
            HTTPStatus.OK,
            {
                "batch_id": batch_id,
                **result,
                "lifecycle_chain_valid": (
                    self._repository.verify_batch_lifecycle_chain(batch_id)
                ),
            },
        )

    def _handle_pilot_batch_isolation(
        self,
        principal: Principal,
    ) -> None:
        validated = self._read_model(PilotIsolationRequest)
        if validated is None:
            return
        request = validated
        assert isinstance(request, PilotIsolationRequest)
        try:
            isolated = self._repository.isolate_legacy_pilot_batches(
                actor=principal.username,
                reason=request.reason,
            )
        except ValueError as error:
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "invalid_batch_status",
                str(error),
            )
            return
        self._record_audit(
            principal,
            "legacy_pilot_batches_isolated",
            {
                "batch_ids": [item["batch_id"] for item in isolated],
                "count": len(isolated),
                "reason": request.reason.strip(),
            },
        )
        self._send_json(
            HTTPStatus.OK,
            {
                "isolated_count": len(isolated),
                "items": isolated,
            },
        )

    @staticmethod
    def _is_governed_batch(batch: dict[str, Any]) -> bool:
        context = batch.get("context")
        return bool(
            isinstance(context, dict)
            and str(context.get("kind", "")).startswith("governed_")
        )

    def _leadership_batches(
        self,
        *,
        visible_mines: tuple[str, ...] | None,
        limit: int,
    ) -> tuple[list[dict[str, Any]], bool]:
        """Prefer governed history once it exists for the caller's scope."""

        candidates = [
            batch
            for batch in self._repository.list_batches(limit=limit)
            if visible_mines is None
            or any(
                str(item.get("mine_id")) in visible_mines
                for item in batch["response"].get("items", [])
            )
        ]
        governed = [
            batch for batch in candidates if self._is_governed_batch(batch)
        ]
        return (governed, True) if governed else (candidates, False)

    def _handle_overview(self, principal: Principal) -> None:
        visible_mines = self._visible_mines(principal)
        if any(
            batch.get("integrity_valid") is not True
            for batch in self._repository.list_batches(limit=1000)
        ):
            self._send_error(
                HTTPStatus.CONFLICT,
                "batch_integrity_error",
                "at least one active batch failed request, response or "
                "context integrity verification; leadership results are "
                "withheld pending audit",
            )
            return
        leadership_batches, governed_mode = self._leadership_batches(
            visible_mines=visible_mines,
            limit=1000,
        )
        latest = leadership_batches[0] if leadership_batches else None
        if latest is None:
            trusted_service = self._auth_required
            self._send_json(
                HTTPStatus.OK,
                {
                    "batch": None,
                    "open_case_count": 0,
                    "local_trial": not trusted_service,
                    "operating_mode": (
                        "trusted_intranet_shadow"
                        if trusted_service
                        else "local_trial"
                    ),
                    "batch_data_mode": None,
                    "trust_notice": (
                        "内网影子运行：尚未接收可信治理批次。"
                        if trusted_service
                        else (
                            "本地影子试用：结果仅形成技术核查线索，"
                            "不作违法认定。"
                        )
                    ),
                    "generated_at": datetime.now().astimezone().isoformat(),
                },
            )
            return

        batch_id = str(latest["batch_id"])
        context = latest.get("context")
        trusted_shadow = bool(
            isinstance(context, dict)
            and str(context.get("kind", "")).startswith("governed_")
        )
        trusted_service = self._auth_required
        batch = self._decorate_batch(
            latest["response"],
            batch_id=batch_id,
            visible_mines=visible_mines,
        )
        self._send_json(
            HTTPStatus.OK,
            {
                "batch": batch,
                "batch_created_at": latest["created_at"],
                "request_sha256": latest["request_sha256"],
                "open_case_count": self._repository.count_open_cases(
                    batch_ids=(
                        tuple(
                            str(batch["batch_id"])
                            for batch in leadership_batches
                        )
                        if governed_mode
                        else None
                    ),
                    mine_ids=visible_mines,
                ),
                "current_batch_open_case_count": (
                    self._repository.count_open_cases(
                        batch_id=batch_id,
                        mine_ids=visible_mines,
                    )
                ),
                "local_trial": not trusted_shadow,
                "operating_mode": (
                    "trusted_intranet_shadow"
                    if trusted_service
                    else "local_trial"
                ),
                "batch_data_mode": (
                    "governed_trusted"
                    if trusted_shadow
                    else "legacy_or_direct_analysis"
                ),
                "trust_notice": (
                    (
                        "内网影子运行：技术状态、复核优先级与办理状态"
                        "相互独立，任何线索均需调阅原始证据人工复核。"
                    )
                    if trusted_shadow
                    else (
                        "当前服务为内网影子运行；最新批次来自历史或"
                        "管理员直接分析通道，未经过可信来源治理，只作"
                        "试算线索。"
                        if trusted_service
                        else (
                            "本地影子试用：结果仅形成技术核查线索，"
                            "不作违法认定。"
                        )
                    )
                ),
                "generated_at": datetime.now().astimezone().isoformat(),
            },
        )

    def _handle_trends(
        self,
        query: str,
        principal: Principal,
    ) -> None:
        visible_mines = self._visible_mines(principal)
        representative_mine = (
            None
            if visible_mines is None
            else (visible_mines[0] if visible_mines else "__no_scope__")
        )
        if not self._require_permission(
            principal,
            Permission.DATA_READ,
            mine_id=representative_mine,
        ):
            return
        values = parse_qs(query, keep_blank_values=True)
        allowed = {"days", "timezone"}
        if (
            set(values) - allowed
            or any(len(entries) != 1 for entries in values.values())
        ):
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "invalid_query",
                "supported parameters are days and timezone",
            )
            return
        try:
            days = int(values.get("days", ["30"])[0])
        except ValueError:
            days = 0
        if not 1 <= days <= 365:
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "invalid_query",
                "days must be an integer from 1 to 365",
            )
            return
        timezone = values.get("timezone", ["Asia/Shanghai"])[0]
        if not timezone:
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "invalid_query",
                "timezone must not be empty",
            )
            return

        leadership_batches, governed_mode = self._leadership_batches(
            visible_mines=visible_mines,
            limit=1000,
        )
        leadership_batch_ids = {
            str(batch["batch_id"]) for batch in leadership_batches
        }
        cases = [
            case
            for case in self._repository.list_cases()
            if (
                visible_mines is None
                or str(case["mine_id"]) in visible_mines
            )
            and (
                not governed_mode
                or str(case["batch_id"]) in leadership_batch_ids
            )
        ]
        events = {
            str(case["case_id"]): self._repository.get_case_events(
                str(case["case_id"])
            )
            for case in cases
        }
        now = datetime.now().astimezone()
        try:
            report = calculate_leadership_analytics(
                leadership_batches,
                cases,
                events,
                mine_ids=visible_mines,
                start_at=now - timedelta(days=days),
                end_at=now,
                as_of=now,
                timezone=timezone,
            )
        except ValueError as error:
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "invalid_query",
                str(error),
            )
            return
        self._send_json(HTTPStatus.OK, {"analytics": report})

    @staticmethod
    def _temporal_detector_thresholds(
        parameters: TemporalDetectionParameters,
    ) -> dict[str, Any]:
        return {
            "baseline": {
                "window": parameters.baseline_window,
                "minimum_history": parameters.min_history,
                "minimum_quality": parameters.min_baseline_quality,
                "minimum_scale": parameters.minimum_scale,
            },
            "rolling_mad": {
                "robust_z": parameters.mad_z_threshold,
            },
            "ewma": {
                "alpha": parameters.ewma_alpha,
                "standardized": parameters.ewma_z_threshold,
            },
            "cusum": {
                "drift": parameters.cusum_drift,
                "threshold": parameters.cusum_threshold,
            },
            "page_hinkley": {
                "delta": parameters.page_hinkley_delta,
                "threshold": parameters.page_hinkley_threshold,
            },
            "source_health": {
                "maximum_latency_seconds": (
                    parameters.max_latency_seconds
                ),
                "maximum_revision_count": (
                    parameters.max_revision_count
                ),
            },
        }

    @staticmethod
    def _feature_event_time(value: Any) -> datetime | None:
        if not isinstance(value, str) or not value.strip():
            return None
        try:
            parsed = datetime.fromisoformat(
                value.strip().replace("Z", "+00:00")
            )
        except ValueError:
            return None
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            return None
        return parsed.astimezone(UTC)

    @classmethod
    def _temporal_observations_from_features(
        cls,
        features: list[dict[str, Any]],
        *,
        visible_mines: tuple[str, ...] | None,
        start_at: datetime,
        end_at: datetime,
        history_start_at: datetime | None = None,
    ) -> tuple[list[TemporalObservation], dict[str, Any]]:
        scoped_mines = (
            None if visible_mines is None else set(visible_mines)
        )
        load_start = history_start_at or start_at
        point_candidates: dict[
            tuple[str, str, str, datetime],
            list[tuple[dict[str, Any], TemporalObservation, bool]],
        ] = {}
        rows_in_window = 0
        accepted_rows = 0
        rejected_rows = 0
        warmup_rows = 0
        ambiguous_rows = 0

        for feature in features:
            if not isinstance(feature, dict):
                continue
            raw_mine_id = feature.get("mine_id")
            if not isinstance(raw_mine_id, str):
                continue
            mine_id = raw_mine_id.strip()
            if not mine_id or (
                scoped_mines is not None and mine_id not in scoped_mines
            ):
                # Defence in depth: repository filtering must never become
                # the only protection against cross-mine disclosure.
                continue

            event_time = cls._feature_event_time(
                feature.get("observed_at")
            )
            if event_time is None:
                rejected_rows += 1
                continue
            if not load_start <= event_time < end_at:
                continue
            visible = start_at <= event_time < end_at
            if visible:
                rows_in_window += 1
            else:
                warmup_rows += 1
            if feature.get("hash_valid") is not True:
                rejected_rows += 1
                continue
            compatibility = feature.get("compatibility")
            if (
                not isinstance(compatibility, dict)
                or compatibility.get("trusted_mode") != "governed"
                or compatibility.get("governance_complete") is not True
            ):
                rejected_rows += 1
                continue

            feature_code = feature.get("feature_code")
            if not isinstance(feature_code, str):
                rejected_rows += 1
                continue
            metric_code = feature_code.strip()
            if not metric_code:
                rejected_rows += 1
                continue
            raw_source_key = feature.get("source_key")
            source_key = (
                raw_source_key.strip()
                if isinstance(raw_source_key, str)
                else ""
            )
            source_id = source_key or "analysis_engine"
            raw_value = feature.get("value")
            if (
                not isinstance(raw_value, (int, float))
                or isinstance(raw_value, bool)
            ):
                rejected_rows += 1
                continue
            raw_quality = feature.get("quality_score")
            if raw_quality is None:
                quality = 1.0
            elif (
                isinstance(raw_quality, (int, float))
                and not isinstance(raw_quality, bool)
            ):
                quality = float(raw_quality)
            else:
                rejected_rows += 1
                continue

            try:
                observation = TemporalObservation(
                    mine_id=mine_id,
                    source_id=source_id,
                    metric_code=metric_code,
                    timestamp=event_time,
                    signed_residual=float(raw_value),
                    quality=quality,
                )
            except ValidationError:
                rejected_rows += 1
                continue
            point_key = (
                mine_id,
                source_id,
                metric_code,
                event_time,
            )
            point_candidates.setdefault(point_key, []).append(
                (feature, observation, visible)
            )

        observations: list[TemporalObservation] = []
        revision_rows = 0
        for point_key in sorted(point_candidates):
            candidates = point_candidates[point_key]
            selection = select_authoritative_algorithm_feature(
                [candidate[0] for candidate in candidates]
            )
            if selection["status"] != "selected":
                ambiguous_rows += len(candidates)
                rejected_rows += len(candidates)
                continue
            selected_feature = selection["selected"]
            selected_feature_row, selected, visible = next(
                candidate
                for candidate in candidates
                if candidate[0] is selected_feature
            )
            authority = selected_feature_row.get("authority_order")
            revision_count = (
                int(authority.get("source_revision_no") or 0)
                if isinstance(authority, dict)
                else 0
            )
            if visible:
                accepted_rows += 1
                revision_rows += revision_count
            observations.append(
                TemporalObservation.model_validate(
                    {
                        **selected.model_dump(),
                        "revision_count": revision_count,
                    }
                )
            )

        return observations, {
            "feature_row_count": rows_in_window,
            "accepted_feature_row_count": accepted_rows,
            "observation_count": len(observations),
            "revision_row_count": revision_rows,
            "rejected_feature_row_count": rejected_rows,
            "ambiguous_feature_row_count": ambiguous_rows,
            "warmup_feature_row_count": warmup_rows,
        }

    def _handle_temporal_dashboard(
        self,
        query: str,
        principal: Principal,
    ) -> None:
        visible_mines = self._visible_mines(principal)
        representative_mine = (
            None
            if visible_mines is None
            else (visible_mines[0] if visible_mines else "__no_scope__")
        )
        if not self._require_permission(
            principal,
            Permission.DATA_READ,
            mine_id=representative_mine,
        ):
            return

        values = parse_qs(query, keep_blank_values=True)
        if set(values) - {"days"} or any(
            len(entries) != 1 for entries in values.values()
        ):
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "invalid_query",
                "supported parameter is days",
            )
            return
        try:
            days = int(values.get("days", ["30"])[0])
        except ValueError:
            days = 0
        if not 1 <= days <= 365:
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "invalid_query",
                "days must be an integer from 1 to 365",
            )
            return

        end_at = datetime.now(UTC)
        start_at = end_at - timedelta(days=days)
        parameters = TemporalDetectionParameters()
        warmup_days = max(90, parameters.baseline_window * 2)
        history_start_at = start_at - timedelta(days=warmup_days)
        feature_limit = 100_000
        # SQLite stores the original ISO-8601 representation.  A one-day
        # coarse range limits I/O, while the authoritative comparison below
        # parses offsets and compares actual instants.
        features = self._repository.list_algorithm_features(
            mine_ids=(
                None
                if visible_mines is None
                else set(visible_mines)
            ),
            feature_version=ALGORITHM_FEATURE_VERSION,
            start_at=(history_start_at - timedelta(days=1))
            .date()
            .isoformat(),
            end_at=(
                end_at + timedelta(days=1)
            ).date().isoformat(),
            limit=feature_limit,
            include_overflow_sentinel=True,
        )
        feature_limit_reached = len(features) > feature_limit
        common: dict[str, Any] = {
            "window": {
                "days": days,
                "start_at": start_at.isoformat(),
                "end_at": end_at.isoformat(),
                "end_exclusive": True,
                "warmup_start_at": history_start_at.isoformat(),
                "ordering": "event_time_ascending_per_series",
            },
            "detector_thresholds": (
                self._temporal_detector_thresholds(parameters)
            ),
            "feature_version": ALGORITHM_FEATURE_VERSION,
            "generated_at": end_at.isoformat(),
        }
        if feature_limit_reached:
            self._send_json(
                HTTPStatus.OK,
                {
                    **common,
                    "status": "insufficient_history",
                    "reason": "data_truncated",
                    "series": [],
                    "series_count": 0,
                    "anomalous_series_count": 0,
                    "insufficient_history_series_count": 0,
                    "episodes": [],
                    "health": {
                        "feature_row_count": feature_limit + 1,
                        "accepted_feature_row_count": 0,
                        "observation_count": 0,
                        "revision_row_count": 0,
                        "rejected_feature_row_count": 0,
                        "ambiguous_feature_row_count": 0,
                        "warmup_feature_row_count": 0,
                        "series_count": 0,
                        "point_count": 0,
                        "missing_count": 0,
                        "late_count": 0,
                        "revised_count": 0,
                        "low_quality_count": 0,
                        "baseline_accepted_count": 0,
                        "feature_limit_reached": True,
                        "status": "degraded",
                    },
                },
            )
            return
        observations, feature_health = (
            self._temporal_observations_from_features(
                features,
                visible_mines=visible_mines,
                start_at=start_at,
                end_at=end_at,
                history_start_at=history_start_at,
            )
        )

        if not any(
            start_at <= item.timestamp < end_at for item in observations
        ):
            self._send_json(
                HTTPStatus.OK,
                {
                    **common,
                    "status": "insufficient_history",
                    "reason": "no_usable_history",
                    "series": [],
                    "series_count": 0,
                    "anomalous_series_count": 0,
                    "insufficient_history_series_count": 0,
                    "episodes": [],
                    "health": {
                        **feature_health,
                        "series_count": 0,
                        "point_count": 0,
                        "missing_count": 0,
                        "late_count": 0,
                        "revised_count": 0,
                        "low_quality_count": 0,
                        "baseline_accepted_count": 0,
                        "feature_limit_reached": (
                            feature_limit_reached
                        ),
                        "status": (
                            "degraded"
                            if (
                                feature_health[
                                    "rejected_feature_row_count"
                                ]
                                or feature_limit_reached
                            )
                            else "insufficient_history"
                        ),
                    },
                },
            )
            return

        result = detect_temporal_anomalies(
            TemporalDetectionRequest(
                observations=observations,
                parameters=parameters,
                report_start=start_at,
                report_end=end_at,
            )
        )
        flattened_episodes = [
            {
                "mine_id": series.mine_id,
                "source_id": series.source_id,
                "metric_code": series.metric_code,
                **episode.model_dump(mode="json"),
            }
            for series in result.series
            for episode in series.episodes
        ]
        source_health = [
            series.source_health for series in result.series
        ]
        has_anomaly = any(
            series.anomaly_point_count > 0 for series in result.series
        )
        if has_anomaly:
            status = "anomalous"
            reason = "detector_signal"
        elif result.insufficient_history_series_count:
            status = "insufficient_history"
            reason = "cold_start"
        else:
            status = "normal"
            reason = "sufficient_history"
        result_payload = result.model_dump(mode="json")
        self._send_json(
            HTTPStatus.OK,
            {
                **common,
                **result_payload,
                "status": status,
                "reason": reason,
                "episodes": flattened_episodes,
                "health": {
                    **feature_health,
                    "series_count": result.series_count,
                    "point_count": sum(
                        item.point_count for item in source_health
                    ),
                    "missing_count": sum(
                        item.missing_count for item in source_health
                    ),
                    "late_count": sum(
                        item.late_count for item in source_health
                    ),
                    "revised_count": sum(
                        item.revised_count for item in source_health
                    ),
                    "low_quality_count": sum(
                        item.low_quality_count for item in source_health
                    ),
                    "baseline_accepted_count": sum(
                        item.baseline_accepted_count
                        for item in source_health
                    ),
                    "feature_limit_reached": feature_limit_reached,
                    "status": (
                        "degraded"
                        if (
                            feature_health[
                                "rejected_feature_row_count"
                            ]
                            or feature_limit_reached
                        )
                        else "ok"
                    ),
                },
            },
        )

    def _decorate_batch(
        self,
        response: dict[str, Any],
        *,
        batch_id: str,
        visible_mines: tuple[str, ...] | None = None,
    ) -> dict[str, Any]:
        batch = deepcopy(response)
        cases_by_mine = {
            str(case["mine_id"]): case
            for case in self._repository.list_cases(batch_id=batch_id)
        }
        runs_by_mine = {
            str(run["mine_id"]): run
            for run in self._repository.list_runs(batch_id)
        }
        items = [
            item
            for item in batch.get("items", [])
            if (
                visible_mines is None
                or str(item.get("mine_id")) in visible_mines
            )
        ]
        batch["items"] = items
        for item in items:
            mine_id = str(item["mine_id"])
            case = cases_by_mine.get(mine_id)
            run = runs_by_mine.get(mine_id)
            item["case_id"] = case["case_id"] if case else None
            item["workflow_status"] = (
                case["workflow_status"] if case else None
            )
            item["assignee"] = case["assignee"] if case else None
            item["case_version"] = case["version"] if case else None
            item["analysis_run_id"] = run["run_id"] if run else None
        batch["expected_mine_count"] = len(items)
        batch["received_mine_count"] = sum(
            item.get("technical_status") != "not_received"
            for item in items
        )
        batch["coverage_rate"] = (
            batch["received_mine_count"] / len(items) if items else 0
        )
        technical_keys = (
            "not_received",
            "consistent",
            "inconsistent",
            "inconclusive",
            "solver_error",
        )
        priority_keys = ("P1", "P2", "DATA", "NONE")
        batch["technical_status_counts"] = {
            key: sum(
                item.get("technical_status") == key for item in items
            )
            for key in technical_keys
        }
        batch["review_priority_counts"] = {
            key: sum(item.get("review_priority") == key for item in items)
            for key in priority_keys
        }
        return batch

    def _handle_case_list(
        self,
        query: str,
        principal: Principal,
    ) -> None:
        values = parse_qs(query, keep_blank_values=True)
        allowed = {
            "status",
            "priority",
            "mine_id",
            "batch_id",
            "include_archived",
        }
        unknown = sorted(set(values) - allowed)
        if unknown or any(len(entries) != 1 for entries in values.values()):
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "invalid_query",
                "unsupported or repeated case query parameter",
            )
            return
        include_archived_values = values.pop("include_archived", None)
        if (
            include_archived_values is not None
            and include_archived_values != ["1"]
        ):
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "invalid_query",
                "include_archived must be exactly 1 when supplied",
            )
            return
        filters = {
            name: entries[0] or None
            for name, entries in values.items()
        }
        visible_mines = self._visible_mines(principal)
        requested_mine = filters.get("mine_id")
        if (
            visible_mines is not None
            and requested_mine is not None
            and requested_mine not in visible_mines
        ):
            self._send_error(
                HTTPStatus.FORBIDDEN,
                "permission_denied",
                "permission or mine scope denied",
            )
            return
        cases = [
            self._decorate_case(case)
            for case in self._repository.list_cases(
                status=filters.get("status"),
                priority=filters.get("priority"),
                mine_id=requested_mine,
                batch_id=filters.get("batch_id"),
                include_archived=include_archived_values == ["1"],
            )
            if (
                visible_mines is None
                or str(case["mine_id"]) in visible_mines
            )
        ]
        self._send_json(
            HTTPStatus.OK,
            {"items": cases, "total": len(cases)},
        )

    @staticmethod
    def _decorate_case(case: dict[str, Any]) -> dict[str, Any]:
        decorated = dict(case)
        decorated["analysis_run_id"] = decorated.pop("run_id", None)
        return decorated

    def _case_detail_payload(self, case_id: str) -> dict[str, Any]:
        case = self._repository.get_case(case_id)
        decorated_case = self._decorate_case(case)
        batch = self._repository.get_batch(str(case["batch_id"]))
        batch_integrity_valid = bool(
            batch is not None and batch.get("integrity_valid") is True
        )
        if batch_integrity_valid and batch is not None:
            item = next(
                (
                    candidate
                    for candidate in batch["response"].get("items", [])
                    if isinstance(candidate, dict)
                    and str(candidate.get("mine_id") or "")
                    == str(case["mine_id"])
                ),
                None,
            )
            if item is not None:
                for key in (
                    "historical_evidence",
                    "temporal_evidence",
                    "legitimate_scenario_matches",
                    "evidence_fusion",
                ):
                    if key in item:
                        decorated_case[key] = item[key]
        run_id = case.get("run_id")
        run_hashes_valid = (
            self._repository.verify_run_hashes(str(run_id))
            if run_id
            else None
        )
        audit_chain_valid = self._repository.verify_case_chain(case_id)
        return {
            "case": decorated_case,
            "events": self._repository.get_case_events(case_id),
            "audit_chain_valid": audit_chain_valid,
            "run_hashes_valid": run_hashes_valid,
            "batch_integrity_valid": batch_integrity_valid,
            "integrity_valid": (
                audit_chain_valid
                and (run_hashes_valid is not False)
                and batch_integrity_valid
            ),
            "audit_scope": (
                "本地哈希链完整性校验，不等同于数字签名或不可篡改存储。"
            ),
        }

    def _authorized_case(
        self,
        case_id: str,
        principal: Principal,
        permission: Permission,
    ) -> dict[str, Any] | None:
        case = self._repository.get_case(case_id)
        if not self._require_permission(
            principal,
            permission,
            mine_id=str(case["mine_id"]),
        ):
            return None
        return case

    def _handle_case_detail(
        self,
        case_id: str,
        principal: Principal,
    ) -> None:
        try:
            if self._authorized_case(
                case_id,
                principal,
                Permission.CASE_READ,
            ) is None:
                return
            self._send_json(
                HTTPStatus.OK,
                self._case_detail_payload(case_id),
            )
        except CaseNotFoundError as error:
            self._send_error(
                HTTPStatus.NOT_FOUND,
                "case_not_found",
                str(error),
            )

    def _handle_case_audit(
        self,
        case_id: str,
        principal: Principal,
    ) -> None:
        try:
            case = self._authorized_case(
                case_id,
                principal,
                Permission.AUDIT_READ,
            )
            if case is None:
                return
            run_id = case.get("run_id")
            run_hashes_valid = (
                self._repository.verify_run_hashes(str(run_id))
                if run_id
                else None
            )
            audit_chain_valid = self._repository.verify_case_chain(case_id)
            self._send_json(
                HTTPStatus.OK,
                {
                    "case_id": case_id,
                    "events": self._repository.get_case_events(case_id),
                    "audit_chain_valid": audit_chain_valid,
                    "run_hashes_valid": run_hashes_valid,
                    "integrity_valid": (
                        audit_chain_valid
                        and (run_hashes_valid is not False)
                    ),
                    "audit_scope": (
                        "本地哈希链完整性校验，不等同于数字签名"
                        "或不可篡改存储。"
                    ),
                },
            )
        except CaseNotFoundError as error:
            self._send_error(
                HTTPStatus.NOT_FOUND,
                "case_not_found",
                str(error),
            )

    def _handle_case_action(
        self,
        case_id: str,
        principal: Principal,
    ) -> None:
        validated = self._read_model(CaseActionRequest)
        if validated is None:
            return
        request = validated
        assert isinstance(request, CaseActionRequest)
        disposition = request.disposition
        if disposition == "confirmed":
            disposition = "confirmed_technical_issue"
        try:
            if request.action == "assign":
                permission = Permission.CASE_ASSIGN
            elif request.action in {
                "approve",
                "reject",
                "reopen",
                "archive_case",
                "restore_case",
            }:
                permission = Permission.CASE_APPROVE
            else:
                permission = Permission.CASE_REVIEW
            if self._authorized_case(
                case_id,
                principal,
                permission,
            ) is None:
                return
            if self._auth_required and request.action == "close":
                self._record_audit(
                    principal,
                    "case_action_denied",
                    {
                        "case_id": case_id,
                        "action": request.action,
                        "reason": "double_review_required",
                    },
                )
                self._send_error(
                    HTTPStatus.CONFLICT,
                    "double_review_required",
                    "submit_conclusion and approval by a different user "
                    "are required",
                )
                return
            self._repository.apply_case_action(
                case_id,
                action=request.action,
                expected_version=request.expected_version,
                actor=principal.username,
                note=request.note,
                disposition=disposition,
                assignee=request.assignee,
            )
            self._record_audit(
                principal,
                "case_action_applied",
                {
                    "case_id": case_id,
                    "action": request.action,
                    "expected_version": request.expected_version,
                },
            )
            self._send_json(
                HTTPStatus.OK,
                self._case_detail_payload(case_id),
            )
        except CaseNotFoundError as error:
            self._send_error(
                HTTPStatus.NOT_FOUND,
                "case_not_found",
                str(error),
            )
        except VersionConflictError as error:
            self._record_audit(
                principal,
                "case_action_denied",
                {
                    "case_id": case_id,
                    "action": request.action,
                    "reason": "version_conflict",
                    "expected_version": request.expected_version,
                },
            )
            self._send_error(
                HTTPStatus.CONFLICT,
                "version_conflict",
                str(error),
            )
        except InvalidCaseActionError as error:
            self._record_audit(
                principal,
                "case_action_denied",
                {
                    "case_id": case_id,
                    "action": request.action,
                    "reason": "invalid_case_action",
                },
            )
            self._send_error(
                HTTPStatus.CONFLICT,
                "invalid_case_action",
                str(error),
            )

    def _run_reference_label_payload(
        self,
        run_id: str,
    ) -> dict[str, Any]:
        current = self._repository.get_run_reference_label(run_id)
        history = self._repository.get_run_reference_label_history(run_id)
        return {
            "run_id": run_id,
            "current": current,
            "history": history,
            "chain_valid": (
                self._repository.verify_run_reference_label_chain(run_id)
                if history
                else None
            ),
            "supported_labels": sorted(RUN_REFERENCE_LABELS),
            "baseline_eligible_labels": [
                "verified_normal",
            ],
            "scenario_explanation_labels": [
                "legitimate_exception",
            ],
        }

    def _handle_run_reference_labels_get(
        self,
        run_id: str,
        principal: Principal,
    ) -> None:
        try:
            run = self._repository.get_run(run_id)
            if run.get("batch_integrity_valid") is not True:
                self._send_error(
                    HTTPStatus.CONFLICT,
                    "batch_integrity_error",
                    "analysis run belongs to a batch that failed "
                    "integrity verification",
                )
                return
            if not self._require_permission(
                principal,
                Permission.ANALYSIS_READ,
                mine_id=str(run["mine_id"]),
            ):
                return
            self._send_json(
                HTTPStatus.OK,
                self._run_reference_label_payload(run_id),
            )
        except RunNotFoundError as error:
            self._send_error(
                HTTPStatus.NOT_FOUND,
                "analysis_run_not_found",
                str(error),
            )

    def _matched_legitimate_scenario(
        self,
        run: dict[str, Any],
        scenario_id: str,
    ) -> dict[str, Any] | None:
        request = ProductionAnalysisRequest.model_validate(run["input"])
        result = ProductionAnalysisResult.model_validate(run["result"])
        features = extract_historical_features(request, result)
        context = operational_context_from_batch(
            run.get("batch_context"),
            str(run["mine_id"]),
        )
        matches = self._repository.match_legitimate_scenarios(
            mine_id=str(run["mine_id"]),
            operational_context=context.model_dump(mode="json"),
            features=features,
        )
        return next(
            (
                scenario
                for scenario in matches.get("matched_scenarios", [])
                if isinstance(scenario, dict)
                and scenario.get("scenario_id") == scenario_id
            ),
            None,
        )

    @staticmethod
    def _run_ingested_by(run: dict[str, Any]) -> str | None:
        context = run.get("batch_context")
        if not isinstance(context, dict):
            return None
        mine_id = str(run.get("mine_id") or "")
        reports = context.get("mine_reports")
        if isinstance(reports, list):
            report = next(
                (
                    candidate
                    for candidate in reports
                    if isinstance(candidate, dict)
                    and str(candidate.get("mine_id") or "") == mine_id
                ),
                None,
            )
            if report is not None and report.get("ingested_by"):
                return str(report["ingested_by"])
        return (
            str(context["ingested_by"])
            if context.get("ingested_by")
            else None
        )

    def _handle_run_reference_label_append(
        self,
        run_id: str,
        principal: Principal,
    ) -> None:
        validated = self._read_model(RunReferenceLabelRequest)
        if validated is None:
            return
        request = validated
        assert isinstance(request, RunReferenceLabelRequest)
        try:
            run = self._repository.get_run(run_id)
            if run.get("batch_integrity_valid") is not True:
                self._send_error(
                    HTTPStatus.CONFLICT,
                    "batch_integrity_error",
                    "analysis run belongs to a batch that failed "
                    "integrity verification",
                )
                return
            if not self._require_permission(
                principal,
                Permission.CASE_APPROVE,
                mine_id=str(run["mine_id"]),
            ):
                return
            trusted_reference_label = request.label in {
                "verified_normal",
                "legitimate_exception",
            }
            ingested_by = self._run_ingested_by(run)
            label_history = (
                self._repository.get_run_reference_label_history(run_id)
            )
            if (
                trusted_reference_label
                and ingested_by == principal.username
            ):
                self._send_error(
                    HTTPStatus.CONFLICT,
                    "separation_of_duties_required",
                    "the user who accepted this governed data cannot "
                    "approve it as trusted historical evidence",
                )
                return
            if (
                trusted_reference_label
                and any(
                    event.get("actor") == principal.username
                    and event.get("label")
                    in {
                        "confirmed_data_error",
                        "confirmed_technical_anomaly",
                        "adjudicated_violation",
                    }
                    for event in label_history
                )
            ):
                self._send_error(
                    HTTPStatus.CONFLICT,
                    "second_reviewer_required",
                    "reclassifying an adverse label into baseline evidence "
                    "requires a different approver",
                )
                return
            scenario_reference: str | None = None
            if request.scenario_id is not None:
                matched = self._matched_legitimate_scenario(
                    run,
                    request.scenario_id,
                )
                if matched is None:
                    self._send_error(
                        HTTPStatus.UNPROCESSABLE_ENTITY,
                        "legitimate_scenario_not_matched",
                        "the approved scenario does not match this "
                        "run's mine, context and feature bounds",
                    )
                    return
                scenario_reference = (
                    f"{matched['scenario_id']}@{matched['version']}"
                )
            event = self._repository.append_run_reference_label(
                run_id,
                label=request.label,
                actor=principal.username,
                note=request.note,
                expected_sequence=request.expected_sequence,
                scenario_id=scenario_reference,
            )
            self._record_audit(
                principal,
                "run_reference_label_appended",
                {
                    "run_id": run_id,
                    "mine_id": run["mine_id"],
                    "label": request.label,
                    "sequence": event["sequence"],
                    "scenario_reference": scenario_reference,
                },
            )
            self._send_json(
                HTTPStatus.CREATED,
                self._run_reference_label_payload(run_id),
            )
        except RunNotFoundError as error:
            self._send_error(
                HTTPStatus.NOT_FOUND,
                "analysis_run_not_found",
                str(error),
            )
        except VersionConflictError as error:
            self._send_error(
                HTTPStatus.CONFLICT,
                "version_conflict",
                str(error),
            )
        except (ValidationError, ValueError) as error:
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "invalid_reference_label",
                str(error),
            )

    def _handle_legitimate_scenario_list(self) -> None:
        scenarios = self._repository.list_legitimate_scenarios(
            include_inactive=True,
            all_versions=True,
            limit=1_000,
        )
        self._send_json(
            HTTPStatus.OK,
            {
                "items": scenarios,
                "immutability_notice": (
                    "返回完整版本历史（最多1000条）。场景版本不可删除或"
                    "覆盖，且必须从1开始连续递增；变更请新增版本，停用请"
                    "新增 active=false 版本。"
                ),
            },
        )

    def _handle_external_event_snapshot_list(self) -> None:
        try:
            snapshots = self._repository.list_external_event_snapshots(
                limit=1_000,
            )
            self._send_json(
                HTTPStatus.OK,
                {
                    "items": snapshots,
                    "immutability_notice": (
                        "事件查询快照不可删除或覆盖；相同 snapshot_id "
                        "仅允许完全相同内容的幂等重试。"
                    ),
                },
            )
        except AlgorithmRecordIntegrityError as error:
            self._send_error(
                HTTPStatus.CONFLICT,
                "external_event_snapshot_integrity_error",
                str(error),
            )

    def _handle_external_event_snapshot_create(
        self,
        principal: Principal,
    ) -> None:
        validated = self._read_model(ExternalEventSnapshotRequest)
        if validated is None:
            return
        request = validated
        assert isinstance(request, ExternalEventSnapshotRequest)
        content = request.model_dump(mode="json")
        content["created_by"] = principal.username
        try:
            snapshot = self._repository.save_external_event_snapshot(
                content
            )
            self._record_audit(
                principal,
                "external_event_snapshot_registered",
                {
                    "snapshot_id": snapshot["snapshot_id"],
                    "mine_id": snapshot["mine_id"],
                    "window_start": snapshot["window_start"],
                    "window_end": snapshot["window_end"],
                    "event_codes": snapshot["event_codes"],
                    "evidence_sha256": snapshot["evidence_sha256"],
                    "content_sha256": snapshot["content_sha256"],
                    "created": snapshot["created"],
                },
            )
            self._send_json(
                (
                    HTTPStatus.CREATED
                    if snapshot["created"]
                    else HTTPStatus.OK
                ),
                {"snapshot": snapshot},
            )
        except ExternalEventSnapshotConflictError as error:
            self._send_error(
                HTTPStatus.CONFLICT,
                "external_event_snapshot_conflict",
                str(error),
            )
        except AlgorithmRecordIntegrityError as error:
            self._send_error(
                HTTPStatus.CONFLICT,
                "external_event_snapshot_integrity_error",
                str(error),
            )
        except ValueError as error:
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "invalid_external_event_snapshot",
                str(error),
            )

    def _handle_external_confirmer_list(self) -> None:
        try:
            registrations = (
                self._repository.list_external_confirmer_registrations(
                    limit=1_000,
                )
            )
            self._send_json(
                HTTPStatus.OK,
                {
                    "items": registrations,
                    "immutability_notice": (
                        "确认人备案不可删除或覆盖；同一 client、enterprise、"
                        "confirmer 的变更必须追加连续版本。停用请追加 "
                        "active=false 的下一版本。"
                    ),
                },
            )
        except AlgorithmRecordIntegrityError as error:
            self._send_error(
                HTTPStatus.CONFLICT,
                "external_confirmer_registration_integrity_error",
                str(error),
            )

    def _handle_external_confirmer_create(
        self,
        principal: Principal,
    ) -> None:
        validated = self._read_model(
            ExternalConfirmerRegistrationRequest
        )
        if validated is None:
            return
        request = validated
        assert isinstance(
            request,
            ExternalConfirmerRegistrationRequest,
        )
        content = request.model_dump(mode="json")
        content["created_by"] = principal.username
        try:
            registration = (
                self._repository.save_external_confirmer_registration(
                    content
                )
            )
            self._record_audit(
                principal,
                "external_confirmer_registration_version_registered",
                {
                    "registration_id": registration["registration_id"],
                    "client_id": registration["client_id"],
                    "enterprise_id": registration["enterprise_id"],
                    "confirmer_id": registration["confirmer_id"],
                    "version": registration["version"],
                    "active": registration["active"],
                    "content_sha256": registration["content_sha256"],
                    "created": registration["created"],
                },
            )
            self._send_json(
                (
                    HTTPStatus.CREATED
                    if registration["created"]
                    else HTTPStatus.OK
                ),
                {"registration": registration},
            )
        except ExternalConfirmerRegistrationConflictError as error:
            self._send_error(
                HTTPStatus.CONFLICT,
                "external_confirmer_registration_conflict",
                str(error),
            )
        except AlgorithmRecordIntegrityError as error:
            self._send_error(
                HTTPStatus.CONFLICT,
                "external_confirmer_registration_integrity_error",
                str(error),
            )
        except ValueError as error:
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "invalid_external_confirmer_registration",
                str(error),
            )

    def _handle_legitimate_scenario_create(
        self,
        principal: Principal,
    ) -> None:
        validated = self._read_model(LegitimateScenarioCreateRequest)
        if validated is None:
            return
        request = validated
        assert isinstance(request, LegitimateScenarioCreateRequest)
        definition = request.scenario.model_dump(mode="json")
        definition["created_by"] = principal.username
        try:
            scenario = self._repository.save_legitimate_scenario(
                definition
            )
            self._record_audit(
                principal,
                "legitimate_scenario_version_registered",
                {
                    "scenario_id": scenario["scenario_id"],
                    "version": scenario["version"],
                    "active": scenario["active"],
                    "created": scenario["created"],
                    "definition_sha256": scenario[
                        "definition_sha256"
                    ],
                },
            )
            self._send_json(
                (
                    HTTPStatus.CREATED
                    if scenario["created"]
                    else HTTPStatus.OK
                ),
                {"scenario": scenario},
            )
        except LegitimateScenarioConflictError as error:
            self._send_error(
                HTTPStatus.CONFLICT,
                "legitimate_scenario_conflict",
                str(error),
            )
        except AlgorithmRecordIntegrityError as error:
            self._send_error(
                HTTPStatus.CONFLICT,
                "legitimate_scenario_integrity_error",
                str(error),
            )
        except ValueError as error:
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "invalid_legitimate_scenario",
                str(error),
            )

    def _handle_analysis_run(
        self,
        run_id: str,
        principal: Principal,
    ) -> None:
        try:
            stored = self._repository.get_run(run_id)
            if stored.get("batch_integrity_valid") is not True:
                self._send_error(
                    HTTPStatus.CONFLICT,
                    "batch_integrity_error",
                    "analysis run belongs to a batch that failed "
                    "integrity verification",
                )
                return
            if not self._require_permission(
                principal,
                Permission.ANALYSIS_READ,
                mine_id=str(stored["mine_id"]),
            ):
                return
            run = {
                "analysis_run_id": stored["run_id"],
                "batch_id": stored["batch_id"],
                "mine_id": stored["mine_id"],
                "technical_status": stored["technical_status"],
                "snapshot_hash": stored["input_sha256"],
                "snapshot_hash_valid": stored["input_hash_valid"],
                "input_snapshot": stored["input"],
                "result_hash": stored["result_sha256"],
                "result_hash_valid": stored["result_hash_valid"],
                "batch_integrity_valid": stored[
                    "batch_integrity_valid"
                ],
                "batch_context_hash_valid": stored[
                    "batch_context_hash_valid"
                ],
                "batch_response_hash_valid": stored[
                    "batch_response_hash_valid"
                ],
                "result": stored["result"],
                "engine_version": stored["engine_version"],
                "runtime_manifest": (
                    stored.get("batch_context") or {}
                ).get("runtime_manifest"),
                "created_at": stored["created_at"],
            }
            batch = self._repository.get_batch(str(stored["batch_id"]))
            if batch is not None:
                item = next(
                    (
                        candidate
                        for candidate in batch["response"].get("items", [])
                        if isinstance(candidate, dict)
                        and str(candidate.get("mine_id") or "")
                        == str(stored["mine_id"])
                    ),
                    None,
                )
                if item is not None:
                    for key in (
                        "historical_evidence",
                        "temporal_evidence",
                        "legitimate_scenario_matches",
                        "evidence_fusion",
                    ):
                        if key in item:
                            run[key] = item[key]
            current_label = self._repository.get_run_reference_label(
                run_id
            )
            run["reference_label"] = current_label
            self._send_json(HTTPStatus.OK, {"run": run})
        except RunNotFoundError as error:
            self._send_error(
                HTTPStatus.NOT_FOUND,
                "analysis_run_not_found",
                str(error),
            )

    def _handle_evidence_create(
        self,
        case_id: str,
        principal: Principal,
    ) -> None:
        validated = self._read_model(EvidenceCreateRequest)
        if validated is None:
            return
        request = validated
        assert isinstance(request, EvidenceCreateRequest)
        try:
            case = self._authorized_case(
                case_id,
                principal,
                Permission.CASE_REVIEW,
            )
            if case is None:
                return
            if int(case["version"]) != request.expected_version:
                raise VersionConflictError(
                    "case version changed; reload before exporting evidence"
                )
            existing = self._evidence_repository.get_for_case_version(
                case_id,
                request.expected_version,
            )
            if existing is not None:
                verification = self._evidence_service.verify(
                    self._evidence_repository.read(existing["bundle_id"])
                )
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "evidence": existing,
                        "verification": verification,
                    },
                )
                return

            run = None
            if case.get("run_id"):
                run = self._repository.get_run(str(case["run_id"]))
            previous = (
                self._evidence_repository.latest_manifest_sha256(case_id)
            )
            bundle, manifest = self._evidence_service.build(
                case=self._decorate_case(case),
                events=self._repository.get_case_events(case_id),
                run=run,
                engine_version=__version__,
                previous_manifest_sha256=previous,
            )
            saved = self._evidence_repository.save(
                bundle,
                manifest,
                created_by=principal.username,
            )
            self._record_audit(
                principal,
                "evidence_bundle_created",
                {
                    "case_id": case_id,
                    "bundle_id": saved["bundle_id"],
                    "case_version": request.expected_version,
                },
            )
            self._send_json(
                HTTPStatus.CREATED,
                {
                    "evidence": saved,
                    "verification": self._evidence_service.verify(bundle),
                },
            )
        except CaseNotFoundError:
            self._send_error(
                HTTPStatus.NOT_FOUND,
                "case_not_found",
                "case not found",
            )
        except VersionConflictError as error:
            self._send_error(
                HTTPStatus.CONFLICT,
                "version_conflict",
                str(error),
            )
        except EvidenceError:
            self._send_error(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "evidence_error",
                "evidence bundle could not be created",
            )

    def _handle_evidence_get(
        self,
        bundle_id: str,
        principal: Principal,
        *,
        verify_only: bool,
    ) -> None:
        try:
            record = self._evidence_repository.get(bundle_id)
            case = self._authorized_case(
                str(record["case_id"]),
                principal,
                Permission.CASE_READ,
            )
            if case is None:
                return
            bundle = self._evidence_repository.read(bundle_id)
            if verify_only:
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "evidence": record,
                        "verification": self._evidence_service.verify(bundle),
                    },
                )
                return
            self._send_bytes(
                HTTPStatus.OK,
                bundle,
                content_type="application/zip",
                headers={
                    "Content-Disposition": (
                        f'attachment; filename="{bundle_id}.zip"'
                    )
                },
            )
        except (EvidenceNotFoundError, CaseNotFoundError):
            self._send_error(
                HTTPStatus.NOT_FOUND,
                "evidence_not_found",
                "evidence bundle not found",
            )
        except EvidenceError:
            self._send_error(
                HTTPStatus.CONFLICT,
                "evidence_integrity_failed",
                "stored evidence bundle failed integrity verification",
            )

    def _read_request_body(self) -> bytes:
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            raise _BadRequest("Content-Length header is required")
        try:
            length = int(raw_length)
        except ValueError as error:
            raise _BadRequest("invalid Content-Length header") from error
        if length < 0:
            raise _BadRequest("invalid Content-Length header")
        if length > MAX_REQUEST_BYTES:
            raise _RequestTooLarge(
                f"request body exceeds {MAX_REQUEST_BYTES} bytes"
            )

        body = self.rfile.read(length)
        if len(body) != length:
            raise _BadRequest("incomplete request body")
        if not body:
            raise _BadRequest("request body is required")
        return body

    def _send_not_found(self) -> None:
        self._send_error(
            HTTPStatus.NOT_FOUND,
            "not_found",
            "route not found",
        )

    def _send_method_not_allowed(self, allowed: str) -> None:
        self._send_json(
            HTTPStatus.METHOD_NOT_ALLOWED,
            {
                "error": {
                    "code": "method_not_allowed",
                    "message": f"method not allowed; use {allowed}",
                }
            },
            headers={"Allow": allowed},
        )

    def _send_error(
        self,
        status: HTTPStatus,
        code: str,
        message: str,
        details: list[dict[str, Any]] | None = None,
        *,
        headers: dict[str, str] | None = None,
    ) -> None:
        error: dict[str, Any] = {"code": code, "message": message}
        if details is not None:
            error["details"] = details
        self._send_json(status, {"error": error}, headers=headers)

    def _send_json(
        self,
        status: HTTPStatus,
        payload: Any,
        *,
        headers: dict[str, str] | None = None,
    ) -> None:
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            default=_json_default,
        ).encode("utf-8")
        self.send_response(status)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header(
            "X-Request-ID",
            getattr(self, "_request_log_id", ""),
        )
        self.send_header("Connection", "close")
        self.close_connection = True
        self.end_headers()
        self.wfile.write(encoded)

    def _send_bytes(
        self,
        status: HTTPStatus,
        payload: bytes,
        *,
        content_type: str,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header(
            "X-Request-ID",
            getattr(self, "_request_log_id", ""),
        )
        self.send_header("Connection", "close")
        self.close_connection = True
        self.end_headers()
        self.wfile.write(payload)

    def _send_static(self, filename: str, content_type: str) -> None:
        """Serve one explicitly allowlisted frontend file."""

        try:
            encoded = (WEB_ROOT / filename).read_bytes()
        except (FileNotFoundError, IsADirectoryError, OSError):
            # A source or packaging error must not disclose local filesystem
            # details to the caller.
            self._send_not_found()
            return

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header(
            "X-Request-ID",
            getattr(self, "_request_log_id", ""),
        )
        self.send_header(
            "Content-Security-Policy",
            STATIC_CONTENT_SECURITY_POLICY,
        )
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Connection", "close")
        self.close_connection = True
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format: str, *args: Any) -> None:
        """Emit one-line structured logs without query strings or payloads."""

        status: int | None = None
        if len(args) >= 2:
            try:
                status = int(args[1])
            except (TypeError, ValueError):
                status = None
        started = getattr(self, "_request_started_monotonic", None)
        duration_ms = (
            round((time.monotonic() - started) * 1000, 3)
            if isinstance(started, float)
            else None
        )
        record = {
            "timestamp": datetime.now(UTC).isoformat(),
            "request_id": getattr(self, "_request_log_id", None),
            "client": self.client_address[0],
            "method": getattr(self, "command", None),
            "path": urlsplit(getattr(self, "path", "")).path,
            "status": status,
            "duration_ms": duration_ms,
            # Keep the format template for diagnostics, never the expanded
            # BaseHTTPRequestHandler request line (which contains queries).
            "message_template": format,
        }
        sys.stderr.write(
            json.dumps(
                record,
                ensure_ascii=False,
                separators=(",", ":"),
            )
            + "\n"
        )

    def _start_request_log(self) -> None:
        self._request_started_monotonic = time.monotonic()
        self._request_log_id = secrets.token_hex(8)


class MineGuardHTTPServer(ThreadingHTTPServer):
    """Thread-per-request server that does not delay process shutdown."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        server_address: tuple[str, int],
        repository: LocalRepository,
        *,
        local_actor: str,
        auth_store: LocalAuthStore,
        auth_required: bool,
        secure_cookie: bool,
        job_repository: JobRepository,
        job_manager: JobManager,
        evidence_repository: EvidenceRepository,
        evidence_service: EvidenceBundleService,
        governance_repository: GovernanceRepository,
        governance_service: GovernanceService,
        source_key_store: SourceKeyStore,
        external_clients: dict[str, ExternalClient],
        readiness: ReadinessChecker,
        backup_manager: BackupManager | None,
        backup_databases: dict[str, Path],
        runtime_directory: tempfile.TemporaryDirectory[str] | None = None,
    ) -> None:
        self.repository = repository
        self.local_actor = local_actor
        self.auth_store = auth_store
        self.auth_required = auth_required
        self.secure_cookie = secure_cookie
        self.job_repository = job_repository
        self.job_manager = job_manager
        self.evidence_repository = evidence_repository
        self.evidence_service = evidence_service
        self.governance_repository = governance_repository
        self.governance_service = governance_service
        self.source_key_store = source_key_store
        self.external_clients = external_clients
        self.readiness = readiness
        self.backup_manager = backup_manager
        self.backup_databases = backup_databases
        self.mutation_lock = threading.RLock()
        self.runtime_directory = runtime_directory
        super().__init__(server_address, MineGuardRequestHandler)
        self.job_manager.start()

    def server_close(self) -> None:
        try:
            try:
                self.job_manager.stop()
            finally:
                super().server_close()
        finally:
            try:
                self.repository.close()
            finally:
                try:
                    self.job_repository.close()
                finally:
                    try:
                        self.auth_store.close()
                    finally:
                        try:
                            self.evidence_repository.close()
                        finally:
                            self.governance_repository.close()
                            self.source_key_store.close()
                            if self.runtime_directory is not None:
                                self.runtime_directory.cleanup()


class _BadRequest(ValueError):
    pass


class _RequestTooLarge(ValueError):
    pass


def create_server(
    host: str = "127.0.0.1",
    port: int = 8080,
    *,
    database_path: str | Path = ":memory:",
    local_actor: str = "local-reviewer",
    auth_required: bool = False,
    auth_database_path: str | Path = ":memory:",
    bootstrap_admin: tuple[str, str] | None = None,
    secure_cookie: bool = False,
    job_database_path: str | Path = ":memory:",
    evidence_database_path: str | Path | None = None,
    evidence_directory: str | Path | None = None,
    evidence_secret: bytes | None = None,
    evidence_key_id: str = "local-evidence-key",
    governance_database_path: str | Path | None = None,
    source_key_directory: str | Path | None = None,
    backup_directory: str | Path | None = None,
    backup_secret: bytes | None = None,
    backup_key_id: str = "local-backup-key",
    external_clients: dict[str, ExternalClient] | None = None,
) -> ThreadingHTTPServer:
    """Create a server instance, primarily for embedding and tests."""

    repository = LocalRepository(database_path)
    auth_store = LocalAuthStore(auth_database_path)
    job_repository = JobRepository(job_database_path)
    runtime_directory: tempfile.TemporaryDirectory[str] | None = None
    if (
        evidence_database_path is None
        or evidence_directory is None
        or governance_database_path is None
        or source_key_directory is None
    ):
        runtime_directory = tempfile.TemporaryDirectory(
            prefix="mineguard-runtime-"
        )
        runtime_root = Path(runtime_directory.name)
        evidence_database_path = (
            evidence_database_path or runtime_root / "evidence.db"
        )
        evidence_directory = (
            evidence_directory or runtime_root / "evidence-bundles"
        )
        governance_database_path = (
            governance_database_path or runtime_root / "governance.db"
        )
        source_key_directory = (
            source_key_directory or runtime_root / "source-keys"
        )
    governance_repository = GovernanceRepository(governance_database_path)
    source_key_store = SourceKeyStore(source_key_directory)
    stored_evidence_secret = source_key_store.get_system(
        "evidence-signing-key"
    )
    if evidence_secret is not None:
        source_key_store.put_system(
            "evidence-signing-key",
            evidence_secret,
        )
        evidence_secret_value = evidence_secret
    elif stored_evidence_secret is not None:
        evidence_secret_value = stored_evidence_secret
    else:
        evidence_secret_value = secrets.token_bytes(32)
        source_key_store.put_system(
            "evidence-signing-key",
            evidence_secret_value,
        )
    evidence_repository = EvidenceRepository(
        evidence_database_path,
        evidence_directory,
    )
    evidence_service = EvidenceBundleService(
        lambda key_id: (
            evidence_secret_value if key_id == evidence_key_id else None
        ),
        signing_key_id=evidence_key_id,
    )
    governance_service = GovernanceService(
        governance_repository,
        source_key_store.get,
    )

    if auth_required and not auth_store.list_users():
        if bootstrap_admin is None:
            repository.close()
            auth_store.close()
            job_repository.close()
            evidence_repository.close()
            governance_repository.close()
            source_key_store.close()
            if runtime_directory is not None:
                runtime_directory.cleanup()
            raise ValueError(
                "auth_required needs a bootstrap administrator "
                "when the user store is empty"
            )
        auth_store.bootstrap_admin(*bootstrap_admin)

    def refresh_job_temporal_audit(
        mine_ids: set[str],
    ) -> dict[str, Any]:
        try:
            return refresh_temporal_audit(
                repository,
                mine_ids=mine_ids,
            )
        except Exception:
            return {
                "status": "refresh_failed",
                "mine_ids": sorted(mine_ids),
            }

    def job_operation(payload: dict[str, Any]) -> dict[str, Any]:
        if payload.get("_mineguard_kind") == "governed_production":
            try:
                governed = GovernedProductionRequest.model_validate_json(
                    json.dumps(
                        payload.get("request"),
                        ensure_ascii=False,
                        separators=(",", ":"),
                    )
                )
                request_hash = governance_sha256_json(governed)
                batch_id = f"trusted-job-{request_hash[:32]}"
                existing = repository.get_batch(batch_id)
                if existing is not None:
                    if existing.get("integrity_valid") is not True:
                        raise PublicJobError(
                            "batch_integrity_error",
                            "stored batch failed request, response or "
                            "context integrity verification",
                        )
                    temporal_audit = refresh_job_temporal_audit(
                        {governed.mine_id}
                    )
                    return {
                        "batch_id": batch_id,
                        "created": False,
                        "batch": existing["response"],
                        "governance": existing.get("context"),
                        "temporal_audit": temporal_audit,
                    }
                prepared = governance_service.prepare(governed)
                blocking = [
                    issue.model_dump(mode="json")
                    for issue in prepared.quality_issues
                    if issue.blocking
                ]
                if blocking or prepared.request is None:
                    raise PublicJobError(
                        "governance_rejected",
                        "trusted observations failed governance checks",
                    )
                calibrated_request, calibration = (
                    apply_historical_calibration(
                        repository,
                        prepared.request,
                        engine_version=__version__,
                        trusted_mode="governed",
                        profile_id=governed.profile_id,
                        profile_version=prepared.profile_version,
                        registry_snapshot_hash=(
                            prepared.registry_snapshot_hash
                        ),
                        operational_context=(
                            governed.operational_context
                        ),
                    )
                )
                context = {
                    "kind": "governed_production_job",
                    "ingested_by": payload.get("ingested_by"),
                    "runtime_manifest": build_runtime_manifest(),
                    "governed_request_sha256": request_hash,
                    "profile_id": governed.profile_id,
                    "profile_version": prepared.profile_version,
                    "registry_snapshot_hash": (
                        prepared.registry_snapshot_hash
                    ),
                    "accepted_count": prepared.accepted_count,
                    "rejected_count": prepared.rejected_count,
                    "quality_issues": [
                        issue.model_dump(mode="json")
                        for issue in prepared.quality_issues
                    ],
                    "calibration": calibration.model_dump(mode="json"),
                    "operational_context": (
                        governed.operational_context.model_dump(mode="json")
                    ),
                    "observation_envelopes": [
                        observation.model_dump(mode="json")
                        for observation in governed.observations
                    ],
                }
                portfolio_request = PortfolioAnalysisRequest(
                    batch_id=batch_id,
                    portfolio_name=f"{governed.mine_id}可信异步接入",
                    expected_mine_ids=[governed.mine_id],
                    analyses=[calibrated_request],
                )
                physical_result = analyze_production_portfolio(
                    portfolio_request
                )
                result = enrich_portfolio_historical_evidence(
                    repository,
                    portfolio_request,
                    physical_result,
                    engine_version=__version__,
                    context_obj=context,
                )
                stored = repository.save_portfolio_batch(
                    portfolio_request,
                    result,
                    __version__,
                    context_obj=context,
                )
                temporal_audit = refresh_job_temporal_audit(
                    {governed.mine_id}
                )
                return {
                    "batch_id": batch_id,
                    "created": stored["created"],
                    "batch": stored["batch"],
                    "governance": {
                        key: value
                        for key, value in context.items()
                        if key != "observation_envelopes"
                    },
                    "temporal_audit": temporal_audit,
                }
            except PublicJobError:
                raise
            except (
                ProfileNotApprovedError,
                ProfileNotEffectiveError,
                ProfileNotFoundError,
            ) as error:
                raise PublicJobError(
                    "governance_configuration_rejected",
                    str(error),
                ) from error
            except (GovernanceError, ValidationError) as error:
                raise PublicJobError(
                    "governance_processing_failed",
                    "trusted observation processing failed",
                ) from error
        request = ProductionAnalysisRequest.model_validate(payload)
        return analyze_production(request).model_dump(mode="json")

    initialize_temporal_model_snapshot(repository)
    job_manager = JobManager(job_repository, job_operation)
    readiness = ReadinessChecker()

    def case_store_ready() -> bool:
        repository.list_batches(limit=1)
        return True

    def auth_store_ready() -> bool:
        auth_store.list_users()
        return True

    def job_store_ready() -> bool:
        job_repository.list(limit=1)
        return True

    def evidence_store_ready() -> bool:
        evidence_repository.latest_manifest_sha256("__readiness__")
        return True

    def governance_store_ready() -> bool:
        governance_repository.list_profiles()
        source_key_store.get("__readiness__")
        return True

    def worker_ready() -> ReadinessCheckResult:
        if job_manager.is_running():
            return ReadinessCheckResult("ready", "异步分析线程正常")
        return ReadinessCheckResult("not_ready", "异步分析线程未运行")

    readiness.register("case_store", case_store_ready)
    readiness.register("auth_store", auth_store_ready)
    readiness.register("job_store", job_store_ready)
    readiness.register("evidence_store", evidence_store_ready)
    readiness.register("governance_store", governance_store_ready)
    readiness.register("analysis_worker", worker_ready)

    configured_external_clients = dict(external_clients or {})

    def import_configured_event_snapshots() -> None:
        # Compatibility migration: regulator-owned deployment configuration
        # from the first enterprise-intake version is copied into the durable
        # registry. Intake itself only queries LocalRepository, so this is no
        # longer a parallel source of truth after startup.
        for client in configured_external_clients.values():
            for configured_snapshot in client.verified_event_snapshots:
                identity = {
                    "client_id": client.client_id,
                    "mine_id": configured_snapshot.mine_id,
                    "window_start": configured_snapshot.window_start,
                    "window_end": configured_snapshot.window_end,
                    "event_codes": list(configured_snapshot.event_codes),
                    "evidence_sha256": (
                        configured_snapshot.evidence_sha256
                    ),
                }
                identity_sha256 = sha256_json(identity)
                repository.save_external_event_snapshot(
                    {
                        "snapshot_id": (
                            f"configured-event-{identity_sha256[:32]}"
                        ),
                        "mine_id": configured_snapshot.mine_id,
                        "window_start": configured_snapshot.window_start,
                        "window_end": configured_snapshot.window_end,
                        "event_codes": list(
                            configured_snapshot.event_codes
                        ),
                        "evidence_sha256": (
                            configured_snapshot.evidence_sha256
                        ),
                        "source_system": (
                            "external_client_configuration"
                        ),
                        "record_id": (
                            f"{client.client_id}:{identity_sha256[:32]}"
                        ),
                        "created_by": (
                            f"configuration:{client.client_id}"
                        ),
                    }
                )

    def import_configured_confirmer_registrations() -> None:
        # Compatibility migration only. Once any version exists for a natural
        # key, the database history is authoritative and later environment
        # changes cannot overwrite or append it implicitly.
        for client in configured_external_clients.values():
            for configured_confirmer in client.authorized_confirmers:
                existing = (
                    repository.list_external_confirmer_registrations(
                        client_id=client.client_id,
                        enterprise_id=client.enterprise_id,
                        confirmer_id=configured_confirmer.confirmer_id,
                        limit=1,
                    )
                )
                if existing:
                    continue
                identity = {
                    "client_id": client.client_id,
                    "enterprise_id": client.enterprise_id,
                    "confirmer_id": configured_confirmer.confirmer_id,
                    "confirmer_name": configured_confirmer.confirmer_name,
                    "confirmer_roles": sorted(
                        configured_confirmer.confirmer_roles
                    ),
                    "confirmation_methods": sorted(
                        configured_confirmer.confirmation_methods
                    ),
                }
                identity_sha256 = sha256_json(identity)
                repository.save_external_confirmer_registration(
                    {
                        "registration_id": (
                            f"configured-confirmer-{identity_sha256[:32]}"
                        ),
                        **identity,
                        "version": 1,
                        "active": True,
                        "source_system": (
                            "external_client_configuration_migration"
                        ),
                        "record_id": (
                            f"legacy-config:{identity_sha256}"
                        ),
                        "created_by": "configuration:migration",
                    }
                )

    backup_databases: dict[str, Path] = {}
    backup_manager: BackupManager | None = None
    if backup_directory is not None or backup_secret is not None:
        if backup_directory is None or backup_secret is None:
            raise ValueError(
                "backup_directory and backup_secret must be configured together"
            )
        configured_paths = {
            "mineguard.db": database_path,
            "auth.db": auth_database_path,
            "jobs.db": job_database_path,
            "evidence.db": evidence_database_path,
            "governance.db": governance_database_path,
            "source-keys.db": source_key_store.database_path,
        }
        if any(str(path) == ":memory:" for path in configured_paths.values()):
            raise ValueError(
                "backup manager requires persistent database paths"
            )
        backup_databases = {
            name: Path(path).expanduser().resolve()
            for name, path in configured_paths.items()
        }
        backup_manager = BackupManager(
            backup_directory,
            backup_secret,
            backup_key_id,
            __version__,
        )
    try:
        import_configured_event_snapshots()
        import_configured_confirmer_registrations()
        return MineGuardHTTPServer(
            (host, port),
            repository,
            local_actor=local_actor,
            auth_store=auth_store,
            auth_required=auth_required,
            secure_cookie=secure_cookie,
            job_repository=job_repository,
            job_manager=job_manager,
            evidence_repository=evidence_repository,
            evidence_service=evidence_service,
            governance_repository=governance_repository,
            governance_service=governance_service,
            source_key_store=source_key_store,
            external_clients=configured_external_clients,
            readiness=readiness,
            backup_manager=backup_manager,
            backup_databases=backup_databases,
            runtime_directory=runtime_directory,
        )
    except Exception:
        repository.close()
        job_repository.close()
        auth_store.close()
        evidence_repository.close()
        governance_repository.close()
        source_key_store.close()
        if runtime_directory is not None:
            runtime_directory.cleanup()
        raise


def serve(
    host: str = "127.0.0.1",
    port: int = 8080,
    *,
    database_path: str | Path = ".mineguard/mineguard.db",
    local_actor: str = "local-reviewer",
    auth_required: bool = True,
    auth_database_path: str | Path = ".mineguard/auth.db",
    bootstrap_admin: tuple[str, str] | None = None,
    secure_cookie: bool = False,
    job_database_path: str | Path = ".mineguard/jobs.db",
    evidence_database_path: str | Path = ".mineguard/evidence.db",
    evidence_directory: str | Path = ".mineguard/evidence",
    evidence_key_path: str | Path = ".mineguard/evidence.key",
    governance_database_path: str | Path = ".mineguard/governance.db",
    source_key_directory: str | Path = ".mineguard/source-keys",
    backup_directory: str | Path = ".mineguard/backups",
    backup_key_path: str | Path = ".mineguard/backup.key",
) -> None:
    """Run the MineGuard API until interrupted."""

    evidence_key = _read_secret_if_exists(evidence_key_path)
    backup_key = _load_or_create_secret(backup_key_path)
    external_clients = parse_external_clients(
        os.environ.get("MINEGUARD_EXTERNAL_CLIENTS_JSON")
    )
    with create_server(
        host,
        port,
        database_path=database_path,
        local_actor=local_actor,
        auth_required=auth_required,
        auth_database_path=auth_database_path,
        bootstrap_admin=bootstrap_admin,
        secure_cookie=secure_cookie,
        job_database_path=job_database_path,
        evidence_database_path=evidence_database_path,
        evidence_directory=evidence_directory,
        evidence_secret=evidence_key,
        governance_database_path=governance_database_path,
        source_key_directory=source_key_directory,
        backup_directory=backup_directory,
        backup_secret=backup_key,
        external_clients=external_clients,
    ) as server:
        server.serve_forever()


def _load_or_create_secret(path: str | Path) -> bytes:
    secret_path = Path(path).expanduser().resolve()
    secret_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        secret = secret_path.read_bytes()
    except FileNotFoundError:
        secret = secrets.token_bytes(32)
        descriptor = os.open(
            secret_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(secret)
                stream.flush()
                os.fsync(stream.fileno())
        except Exception:
            try:
                secret_path.unlink()
            except FileNotFoundError:
                pass
            raise
    if len(secret) < 32:
        raise ValueError("evidence key must contain at least 32 bytes")
    return secret


def _read_secret_if_exists(path: str | Path) -> bytes | None:
    secret_path = Path(path).expanduser().resolve()
    try:
        secret = secret_path.read_bytes()
    except FileNotFoundError:
        return None
    if len(secret) < 32:
        raise ValueError("existing key must contain at least 32 bytes")
    return secret
