#!/usr/bin/env python3
"""Confirm the ClickHouse Cloud connection and show which backend is active.

    set -a; . ./.env; set +a
    python check_cloud.py
"""
from ais.store import Store

s = Store()
print(f"backend: {s.backend}")
if s.backend == "local":
    print("CLICKHOUSE_HOST not set. Did you source .env? (set -a; . ./.env; set +a)")
    raise SystemExit(1)
rows = s.query("SELECT version() AS v, now() AS t")
print("connected. ClickHouse", rows[0]["v"], "| server time", rows[0]["t"])
cnt = s.query("SELECT count() AS c FROM events")
print("events table rows:", cnt[0]["c"])
print("\nOK. Now: python run.py seed 200 && python run.py scale 1000000 && python run.py demo")
