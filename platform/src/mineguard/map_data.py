"""Validation for an optional, deployment-supplied offline map boundary."""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any


MAX_GEOJSON_BYTES = 5 * 1024 * 1024
MAX_GEOJSON_POINTS = 200_000


def _position(value: Any) -> list[float]:
    if (
        not isinstance(value, list)
        or len(value) < 2
        or isinstance(value[0], bool)
        or isinstance(value[1], bool)
    ):
        raise ValueError("GeoJSON position must contain longitude and latitude")
    longitude = float(value[0])
    latitude = float(value[1])
    if (
        not math.isfinite(longitude)
        or not math.isfinite(latitude)
        or not -180 <= longitude <= 180
        or not -90 <= latitude <= 90
    ):
        raise ValueError("GeoJSON coordinate is outside valid bounds")
    return [longitude, latitude]


def _polygon(value: Any, *, counter: list[int]) -> list[list[list[float]]]:
    if not isinstance(value, list) or not value:
        raise ValueError("GeoJSON polygon must contain at least one ring")
    polygon: list[list[list[float]]] = []
    for raw_ring in value:
        if not isinstance(raw_ring, list) or len(raw_ring) < 4:
            raise ValueError("GeoJSON polygon ring requires four positions")
        ring = [_position(item) for item in raw_ring]
        counter[0] += len(ring)
        if counter[0] > MAX_GEOJSON_POINTS:
            raise ValueError("GeoJSON point limit exceeded")
        if ring[0] != ring[-1]:
            raise ValueError("GeoJSON polygon ring must be closed")
        polygon.append(ring)
    return polygon


def validate_boundary_geojson(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("type") != "FeatureCollection":
        raise ValueError("map boundary must be a GeoJSON FeatureCollection")
    features = value.get("features")
    if not isinstance(features, list) or not features:
        raise ValueError("GeoJSON FeatureCollection must contain features")
    counter = [0]
    sanitized: list[dict[str, Any]] = []
    for index, raw_feature in enumerate(features):
        if not isinstance(raw_feature, dict) or raw_feature.get("type") != "Feature":
            raise ValueError("GeoJSON item must be a Feature")
        geometry = raw_feature.get("geometry")
        if not isinstance(geometry, dict):
            raise ValueError("GeoJSON feature geometry is required")
        geometry_type = geometry.get("type")
        coordinates = geometry.get("coordinates")
        if geometry_type == "Polygon":
            safe_coordinates: Any = _polygon(
                coordinates,
                counter=counter,
            )
        elif geometry_type == "MultiPolygon":
            if not isinstance(coordinates, list) or not coordinates:
                raise ValueError("GeoJSON MultiPolygon must not be empty")
            safe_coordinates = [
                _polygon(item, counter=counter) for item in coordinates
            ]
        else:
            raise ValueError(
                "map boundary accepts only Polygon or MultiPolygon"
            )
        properties = raw_feature.get("properties")
        name = (
            str(properties.get("name"))[:200]
            if isinstance(properties, dict)
            and properties.get("name") is not None
            else f"boundary-{index + 1}"
        )
        sanitized.append(
            {
                "type": "Feature",
                "id": str(raw_feature.get("id", index + 1))[:128],
                "properties": {"name": name},
                "geometry": {
                    "type": geometry_type,
                    "coordinates": safe_coordinates,
                },
            }
        )
    return {
        "type": "FeatureCollection",
        "features": sanitized,
        "point_count": counter[0],
    }


def load_boundary_geojson(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    if not source.is_file():
        raise ValueError("map GeoJSON path is not a regular file")
    if source.stat().st_size > MAX_GEOJSON_BYTES:
        raise ValueError("map GeoJSON file exceeds size limit")
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("map GeoJSON cannot be read") from error
    return validate_boundary_geojson(value)


__all__ = [
    "MAX_GEOJSON_BYTES",
    "MAX_GEOJSON_POINTS",
    "load_boundary_geojson",
    "validate_boundary_geojson",
]
