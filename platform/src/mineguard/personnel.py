"""井口人脸与定位卡的一对一交叉匹配。"""

from __future__ import annotations

from math import isfinite

import numpy as np
from scipy.optimize import linear_sum_assignment

from .models import (
    CardEvent,
    FaceEvent,
    PersonnelIssue,
    PersonnelMatch,
    PersonnelMatchRequest,
    PersonnelMatchResult,
)

IDENTITY_CONFIRMATION_THRESHOLD = 0.8


def _identity_cost(
    face: FaceEvent,
    card: CardEvent,
    mismatch_penalty: float,
) -> float:
    """Return the expected identity-disagreement cost.

    A high-confidence matching identity receives a low cost.  An unidentified
    or low-confidence face remains eligible for a *temporal* association, but
    it receives no identity benefit.  A high-confidence different identity is
    deliberately more expensive, so the optimizer first prefers a compatible
    card if one exists and never treats low confidence as stronger conflict
    evidence.
    """

    if (
        face.candidate_person_id is None
        or face.match_probability < IDENTITY_CONFIRMATION_THRESHOLD
    ):
        return mismatch_penalty
    if face.candidate_person_id == card.bound_person_id:
        return mismatch_penalty * (1.0 - face.match_probability)
    # Keep a reliable disagreement eligible throughout the configured time
    # window, while making it more expensive than an unidentified temporal
    # pair.  A compatible reliable identity still has a much lower cost.
    return mismatch_penalty * (1.0 + 0.2 * face.match_probability)


def _candidate_cost(
    face: FaceEvent,
    card: CardEvent,
    request: PersonnelMatchRequest,
) -> float | None:
    """Calculate an admissible face/card edge cost, or reject the edge."""

    try:
        time_delta = abs((face.event_time - card.event_time).total_seconds())
    except TypeError as exc:
        raise ValueError(
            "face and card event_time values must use consistent timezone "
            "awareness"
        ) from exc

    if time_delta > request.max_time_delta_seconds:
        return None

    time_cost = time_delta / request.max_time_delta_seconds
    identity_cost = _identity_cost(
        face,
        card,
        request.mismatch_penalty,
    )
    direction_cost = (
        request.mismatch_penalty
        if (
            face.direction is not None
            and card.direction is not None
            and face.direction != card.direction
        )
        else 0.0
    )
    cost = time_cost + identity_cost + direction_cost

    # Matching the edge must be strictly better than rejecting its two ends.
    # This also removes equality ties in which the Hungarian algorithm could
    # otherwise force an arbitrary real-real assignment.
    rejection_cost = (
        request.unmatched_face_cost + request.unmatched_card_cost
    )
    if not isfinite(cost) or cost >= rejection_cost:
        return None
    return cost


def _build_cost_matrix(
    request: PersonnelMatchRequest,
) -> tuple[np.ndarray, np.ndarray]:
    """Build the square assignment matrix with explicit virtual nodes.

    Rows are ``faces + one virtual row per card`` and columns are
    ``cards + one virtual column per face``.  The lower-right zero block lets
    unused virtual nodes pair with each other without changing the objective.
    """

    face_count = len(request.faces)
    card_count = len(request.cards)
    size = face_count + card_count

    matrix = np.full((size, size), np.inf, dtype=float)
    real_costs = np.full((face_count, card_count), np.inf, dtype=float)

    for face_index, face in enumerate(request.faces):
        for card_index, card in enumerate(request.cards):
            cost = _candidate_cost(face, card, request)
            if cost is not None:
                matrix[face_index, card_index] = cost
                real_costs[face_index, card_index] = cost

    # Each real face/card may only use its own unmatched virtual node.  This
    # makes the rejected event explicit while retaining a square assignment.
    for face_index in range(face_count):
        matrix[face_index, card_count + face_index] = (
            request.unmatched_face_cost
        )
    for card_index in range(card_count):
        matrix[face_count + card_index, card_index] = (
            request.unmatched_card_cost
        )

    if face_count and card_count:
        matrix[face_count:, card_count:] = 0.0

    return matrix, real_costs


def match_personnel(
    request: PersonnelMatchRequest,
) -> PersonnelMatchResult:
    """Globally match face tracks and card events within one passage session.

    The result contains only accepted real-real assignments.  All other real
    events are returned as unmatched, with concise Chinese findings suitable
    for a review queue.
    """

    if not isinstance(request, PersonnelMatchRequest):
        raise TypeError("request must be a PersonnelMatchRequest")

    if not request.faces and not request.cards:
        return PersonnelMatchResult(session_id=request.session_id)

    matrix, real_costs = _build_cost_matrix(request)
    row_indices, column_indices = linear_sum_assignment(matrix)

    accepted_pairs: list[tuple[int, int]] = []
    for row_index, column_index in zip(
        row_indices.tolist(),
        column_indices.tolist(),
        strict=True,
    ):
        if (
            row_index < len(request.faces)
            and column_index < len(request.cards)
            and isfinite(real_costs[row_index, column_index])
        ):
            accepted_pairs.append((row_index, column_index))

    accepted_pairs.sort()
    matched_face_indices = {face_index for face_index, _ in accepted_pairs}
    matched_card_indices = {card_index for _, card_index in accepted_pairs}

    matches: list[PersonnelMatch] = []
    findings: list[str] = []
    issues: list[PersonnelIssue] = []
    for face_index, card_index in accepted_pairs:
        face = request.faces[face_index]
        card = request.cards[card_index]
        identity_is_reliable = (
            face.candidate_person_id is not None
            and face.match_probability >= IDENTITY_CONFIRMATION_THRESHOLD
        )
        identity_mismatch = (
            identity_is_reliable
            and face.candidate_person_id != card.bound_person_id
        )
        identity_confirmed = (
            identity_is_reliable
            and face.candidate_person_id == card.bound_person_id
        )
        time_delta_seconds = abs(
            (face.event_time - card.event_time).total_seconds()
        )

        matches.append(
            PersonnelMatch(
                face_track_id=face.face_track_id,
                card_event_id=card.card_event_id,
                card_id=card.card_id,
                face_person_id=face.candidate_person_id,
                card_person_id=card.bound_person_id,
                time_delta_seconds=time_delta_seconds,
                identity_confidence=face.match_probability,
                cost=float(real_costs[face_index, card_index]),
                status=(
                    "identity_conflict"
                    if identity_mismatch
                    else (
                        "identity_confirmed"
                        if identity_confirmed
                        else "temporal_pair_only"
                    )
                ),
            )
        )

        if identity_mismatch:
            finding = (
                "人卡不符：人脸轨迹 "
                f"{face.face_track_id} 的候选身份为 "
                f"{face.candidate_person_id}（置信度 "
                f"{face.match_probability:.1%}），定位卡 "
                f"{card.card_id} 绑定身份为 {card.bound_person_id}，"
                "建议调阅通行视频复核。"
            )
            findings.append(finding)
            issues.append(
                PersonnelIssue(
                    code="identity_conflict",
                    severity="review",
                    summary=finding,
                    face_track_id=face.face_track_id,
                    card_event_id=card.card_event_id,
                )
            )
        elif not identity_confirmed:
            finding = (
                "仅时间关联：人脸轨迹 "
                f"{face.face_track_id} 与定位卡事件 "
                f"{card.card_event_id} 在时间和方向上可关联，"
                "但人脸身份未知或置信度不足，不能据此确认人卡一致。"
            )
            findings.append(finding)
            issues.append(
                PersonnelIssue(
                    code="temporal_pair_only",
                    severity="data",
                    summary=finding,
                    face_track_id=face.face_track_id,
                    card_event_id=card.card_event_id,
                )
            )
        if (
            face.direction is not None
            and card.direction is not None
            and face.direction != card.direction
        ):
            finding = (
                "通行方向不一致：人脸轨迹 "
                f"{face.face_track_id} 为 {face.direction}，定位卡事件 "
                f"{card.card_event_id} 为 {card.direction}，"
                "建议检查方向标记和设备时钟。"
            )
            findings.append(finding)
            issues.append(
                PersonnelIssue(
                    code="direction_conflict",
                    severity="data",
                    summary=finding,
                    face_track_id=face.face_track_id,
                    card_event_id=card.card_event_id,
                )
            )

    unmatched_face_indices = [
        index
        for index in range(len(request.faces))
        if index not in matched_face_indices
    ]
    unmatched_card_indices = [
        index
        for index in range(len(request.cards))
        if index not in matched_card_indices
    ]
    unmatched_face_tracks = [
        request.faces[index].face_track_id
        for index in unmatched_face_indices
    ]
    unmatched_card_events = [
        request.cards[index].card_event_id
        for index in unmatched_card_indices
    ]

    for face_index in unmatched_face_indices:
        face = request.faces[face_index]
        finding = (
            "有脸无卡：人脸轨迹 "
            f"{face.face_track_id} 未匹配到定位卡，"
            "疑似无卡通行或读卡器漏读，需结合原始视频复核。"
        )
        findings.append(finding)
        issues.append(
            PersonnelIssue(
                code="unmatched_face",
                severity="review",
                summary=finding,
                face_track_id=face.face_track_id,
            )
        )
    for card_index in unmatched_card_indices:
        card = request.cards[card_index]
        finding = (
            "有卡无人：定位卡事件 "
            f"{card.card_event_id}（卡号 {card.card_id}，绑定身份 "
            f"{card.bound_person_id}）未匹配到人脸，"
            "疑似带卡不入井或摄像机漏检，需人工复核。"
        )
        findings.append(finding)
        issues.append(
            PersonnelIssue(
                code="unmatched_card",
                severity="review",
                summary=finding,
                card_event_id=card.card_event_id,
            )
        )

    return PersonnelMatchResult(
        session_id=request.session_id,
        matches=matches,
        unmatched_face_tracks=unmatched_face_tracks,
        unmatched_card_events=unmatched_card_events,
        issues=issues,
        findings=findings,
    )


__all__ = ["IDENTITY_CONFIRMATION_THRESHOLD", "match_personnel"]
