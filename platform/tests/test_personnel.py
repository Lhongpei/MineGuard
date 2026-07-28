from datetime import UTC, datetime, timedelta

import pytest

from mineguard.models import (
    CardEvent,
    FaceEvent,
    PersonnelMatchRequest,
)
from mineguard.personnel import match_personnel


BASE_TIME = datetime(2026, 7, 15, 8, 0, tzinfo=UTC)


def _face(
    track_id: str,
    person_id: str | None,
    *,
    seconds: float = 0,
    probability: float = 0.99,
    direction: str | None = "entry",
) -> FaceEvent:
    return FaceEvent(
        face_track_id=track_id,
        event_time=BASE_TIME + timedelta(seconds=seconds),
        candidate_person_id=person_id,
        match_probability=probability,
        direction=direction,
    )


def _card(
    event_id: str,
    card_id: str,
    person_id: str,
    *,
    seconds: float = 0,
    direction: str | None = "entry",
) -> CardEvent:
    return CardEvent(
        card_event_id=event_id,
        card_id=card_id,
        bound_person_id=person_id,
        event_time=BASE_TIME + timedelta(seconds=seconds),
        direction=direction,
    )


def test_global_assignment_prefers_high_confidence_identities() -> None:
    request = PersonnelMatchRequest(
        session_id="session-1",
        faces=[
            _face("face-a", "person-a", seconds=0),
            _face("face-b", "person-b", seconds=1),
        ],
        cards=[
            _card("event-b", "card-b", "person-b", seconds=0),
            _card("event-a", "card-a", "person-a", seconds=1),
        ],
    )

    result = match_personnel(request)

    assert [
        (match.face_track_id, match.card_event_id)
        for match in result.matches
    ] == [
        ("face-a", "event-a"),
        ("face-b", "event-b"),
    ]
    assert all(
        match.status == "identity_confirmed" for match in result.matches
    )
    assert result.unmatched_face_tracks == []
    assert result.unmatched_card_events == []
    assert result.findings == []


def test_out_of_window_events_are_rejected_instead_of_forced() -> None:
    request = PersonnelMatchRequest(
        session_id="session-2",
        faces=[_face("face-a", "person-a")],
        cards=[
            _card(
                "event-a",
                "card-a",
                "person-a",
                seconds=31,
            )
        ],
        max_time_delta_seconds=30,
    )

    result = match_personnel(request)

    assert result.matches == []
    assert result.unmatched_face_tracks == ["face-a"]
    assert result.unmatched_card_events == ["event-a"]
    assert any("有脸无卡" in finding for finding in result.findings)
    assert any("有卡无人" in finding for finding in result.findings)
    assert [issue.code for issue in result.issues] == [
        "unmatched_face",
        "unmatched_card",
    ]


def test_identity_disagreement_is_matched_and_reported() -> None:
    request = PersonnelMatchRequest(
        session_id="session-3",
        faces=[_face("face-a", "person-a", probability=0.98)],
        cards=[_card("event-b", "card-b", "person-b")],
    )

    result = match_personnel(request)

    assert len(result.matches) == 1
    assert result.matches[0].status == "identity_conflict"
    assert result.matches[0].face_person_id == "person-a"
    assert result.matches[0].card_person_id == "person-b"
    assert any("人卡不符" in finding for finding in result.findings)
    assert result.issues[0].code == "identity_conflict"


def test_reliable_identity_conflict_remains_visible_near_window_edge() -> None:
    request = PersonnelMatchRequest(
        session_id="session-conflict-near-edge",
        faces=[
            _face(
                "face-a",
                "person-a",
                seconds=0,
                probability=0.98,
            )
        ],
        cards=[
            _card(
                "event-b",
                "card-b",
                "person-b",
                seconds=29,
            )
        ],
        max_time_delta_seconds=30,
    )

    result = match_personnel(request)

    assert len(result.matches) == 1
    assert result.matches[0].status == "identity_conflict"
    assert result.unmatched_face_tracks == []
    assert result.unmatched_card_events == []


def test_direction_conflict_can_trigger_explicit_rejection() -> None:
    request = PersonnelMatchRequest(
        session_id="session-4",
        faces=[_face("face-a", "person-a", direction="entry")],
        cards=[
            _card(
                "event-a",
                "card-a",
                "person-a",
                direction="exit",
            )
        ],
        unmatched_face_cost=0.4,
        unmatched_card_cost=0.4,
    )

    result = match_personnel(request)

    assert result.matches == []
    assert result.unmatched_face_tracks == ["face-a"]
    assert result.unmatched_card_events == ["event-a"]


def test_unknown_face_is_only_a_temporal_pair() -> None:
    request = PersonnelMatchRequest(
        session_id="session-5",
        faces=[_face("face-unknown", None, probability=0)],
        cards=[_card("event-a", "card-a", "person-a")],
    )

    result = match_personnel(request)

    assert len(result.matches) == 1
    assert result.matches[0].status == "temporal_pair_only"
    assert result.matches[0].face_person_id is None
    assert result.matches[0].cost == pytest.approx(1.0)
    assert any("仅时间关联" in finding for finding in result.findings)
    assert result.issues[0].code == "temporal_pair_only"


def test_low_confidence_different_identity_is_not_reported_as_conflict() -> None:
    request = PersonnelMatchRequest(
        session_id="session-low-confidence",
        faces=[_face("face-a", "person-a", probability=0.2)],
        cards=[_card("event-b", "card-b", "person-b")],
    )

    result = match_personnel(request)

    assert len(result.matches) == 1
    assert result.matches[0].status == "temporal_pair_only"
    assert not any("人卡不符" in finding for finding in result.findings)
    assert any("不能据此确认" in finding for finding in result.findings)


@pytest.mark.parametrize(
    ("faces", "cards", "expected_faces", "expected_cards"),
    [
        ([], [], [], []),
        (
            [_face("face-only", "person-a")],
            [],
            ["face-only"],
            [],
        ),
        (
            [],
            [_card("event-only", "card-a", "person-a")],
            [],
            ["event-only"],
        ),
    ],
)
def test_empty_sides_are_handled(
    faces: list[FaceEvent],
    cards: list[CardEvent],
    expected_faces: list[str],
    expected_cards: list[str],
) -> None:
    result = match_personnel(
        PersonnelMatchRequest(
            session_id="session-empty",
            faces=faces,
            cards=cards,
        )
    )

    assert result.unmatched_face_tracks == expected_faces
    assert result.unmatched_card_events == expected_cards
