import http.client
import json
import threading

import pytest

from mineguard.api import create_server
from mineguard.map_data import (
    load_boundary_geojson,
    validate_boundary_geojson,
)


BOUNDARY = {
    "type": "FeatureCollection",
    "features": [
        {
            "type": "Feature",
            "properties": {
                "name": "试点边界",
                "untrusted_html": "<script>alert(1)</script>",
            },
            "geometry": {
                "type": "Polygon",
                "coordinates": [
                    [
                        [112.1, 36.2],
                        [112.3, 36.2],
                        [112.3, 36.4],
                        [112.1, 36.2],
                    ]
                ],
            },
        }
    ],
}


def test_boundary_is_validated_and_properties_are_minimized(tmp_path) -> None:
    source = tmp_path / "boundary.geojson"
    source.write_text(json.dumps(BOUNDARY), encoding="utf-8")

    result = load_boundary_geojson(source)

    assert result["point_count"] == 4
    assert result["features"][0]["properties"] == {"name": "试点边界"}


@pytest.mark.parametrize(
    "value",
    [
        {"type": "FeatureCollection", "features": []},
        {
            "type": "FeatureCollection",
            "features": [
                {
                    "type": "Feature",
                    "geometry": {
                        "type": "Point",
                        "coordinates": [112.1, 36.2],
                    },
                }
            ],
        },
    ],
)
def test_boundary_rejects_empty_or_unsupported_geometry(value) -> None:
    with pytest.raises(ValueError):
        validate_boundary_geojson(value)


def test_configured_boundary_is_available_through_data_api(
    tmp_path,
) -> None:
    source = tmp_path / "boundary.geojson"
    source.write_text(json.dumps(BOUNDARY), encoding="utf-8")
    server = create_server(
        "127.0.0.1",
        0,
        database_path=tmp_path / "main.db",
        auth_required=False,
        auth_database_path=tmp_path / "auth.db",
        job_database_path=tmp_path / "jobs.db",
        map_geojson_path=source,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = http.client.HTTPConnection(
            "127.0.0.1",
            server.server_address[1],
            timeout=3,
        )
        connection.request("GET", "/v1/map/boundary")
        response = connection.getresponse()
        payload = json.loads(response.read())
        connection.close()
        assert response.status == 200
        assert payload["configured"] is True
        assert payload["boundary"]["point_count"] == 4
        assert payload["boundary"]["features"][0]["properties"] == {
            "name": "试点边界"
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
