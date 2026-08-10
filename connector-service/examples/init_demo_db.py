#!/usr/bin/env python3
"""Create the demo read-only source database; not connector state."""

from __future__ import annotations

import sqlite3
from pathlib import Path


def main() -> None:
    path = Path(__file__).with_name("demo-source.sqlite3")
    if path.exists():
        path.unlink()
    connection = sqlite3.connect(path)
    connection.execute(
        """
        CREATE TABLE energy_readonly (
            meter_time TEXT NOT NULL,
            meter_bucket TEXT NOT NULL,
            active_energy_kwh REAL,
            airflow_avg REAL
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE business_daily_readonly (
            business_date TEXT NOT NULL,
            scope_code TEXT NOT NULL,
            sales_t REAL NOT NULL CHECK (sales_t >= 0),
            outbound_transport_t REAL NOT NULL CHECK (outbound_transport_t >= 0),
            wash_feed_t REAL NOT NULL CHECK (wash_feed_t >= 0),
            blue_invoice_t REAL NOT NULL CHECK (blue_invoice_t >= 0)
        )
        """
    )
    rows = []
    for index, day in enumerate(("2026-07-29", "2026-07-30", "2026-07-31")):
        daily_energy = 123000 + index * 2400
        rows.extend(
            (
                (f"{day}T00:00:00+08:00", "Z0", daily_energy * 0.31, 8050 + index * 20),
                (f"{day}T08:00:00+08:00", "Z8", daily_energy * 0.34, 8150 + index * 20),
                (f"{day}T16:00:00+08:00", "Z16", daily_energy * 0.35, 8160 + index * 20),
                (f"{day}T23:59:00+08:00", "D", daily_energy, 8120 + index * 20),
            )
        )
    connection.executemany("INSERT INTO energy_readonly VALUES (?,?,?,?)", rows)
    business_rows = []
    for index, day in enumerate(("2026-07-29", "2026-07-30", "2026-07-31")):
        business_rows.append(
            (
                day,
                "DAY",
                2980 + index * 35,
                2940 + index * 32,
                1620 + index * 20,
                2870 + index * 30,
            )
        )
    connection.executemany(
        "INSERT INTO business_daily_readonly VALUES (?,?,?,?,?,?)", business_rows
    )
    connection.commit()
    connection.close()
    print(path)


if __name__ == "__main__":
    main()
