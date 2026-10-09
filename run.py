#!/usr/bin/env python3
"""Agent Immune System CLI.

    python run.py seed [N]     record benign + attack sessions (default 200 each)
    python run.py scale [N]    backfill N benign sessions into ClickHouse (default 1_000_000)
    python run.py demo         run the full detect->replay->vaccinate->reverify demo
    python run.py reset        drop local data
"""
import json
import shutil
import sys

from ais.agent import Harness
from ais.backfill import backfill
from ais.pipeline import record, run_demo
from ais.scenarios import attack, benign
from ais.store import Store


def seed(store, n=200):
    h = Harness()
    for i in range(n):
        record(store, benign(i), h, run_id="corpus")
        record(store, attack(i), h, run_id="corpus")
    print(f"seeded {n} benign + {n} attack sessions ({store.backend})")


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "demo"
    if cmd == "reset":
        shutil.rmtree("data", ignore_errors=True)
        print("local data cleared")
        return
    store = Store()
    if cmd == "seed":
        seed(store, int(sys.argv[2]) if len(sys.argv) > 2 else 200)
    elif cmd == "scale":
        n = int(sys.argv[2]) if len(sys.argv) > 2 else 1_000_000
        print(json.dumps(backfill(store, n), indent=2))
    elif cmd == "demo":
        print(json.dumps(run_demo(store), indent=2, default=str))
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
