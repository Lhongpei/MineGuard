#!/usr/bin/env python3
"""Local GET-only production API for the connector demo."""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def records() -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for index, day in enumerate(("2026-07-29", "2026-07-30", "2026-07-31")):
        shifts = (1080 + index * 20, 1120 + index * 20, 1080 + index * 20)
        extracted = tuple(
            value + offset
            for value, offset in zip(shifts, (12, 8, 15), strict=True)
        )
        for hour, scope, value, extracted_value in zip(
            (0, 8, 16),
            ("SHIFT_0", "SHIFT_8", "SHIFT_16"),
            shifts,
            extracted,
            strict=True,
        ):
            result.append(
                {
                    "measuredAt": f"{day}T{hour:02d}:00:00+08:00",
                    "reportingScope": scope,
                    "rawTonnes": value,
                    "faceExtractedTonnes": extracted_value,
                }
            )
        result.append(
            {
                "measuredAt": f"{day}T23:59:00+08:00",
                "reportingScope": "DAY",
                "rawTonnes": sum(shifts),
                "faceExtractedTonnes": sum(extracted),
            }
        )
    return result


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/production":
            self.send_error(404)
            return
        body = json.dumps({"records": records()}, ensure_ascii=False).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        print(format % args)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18092)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"mock production API: http://{args.host}:{args.port}/production")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
