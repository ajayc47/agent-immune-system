"""ClickHouse storage.

Uses ClickHouse Cloud when CLICKHOUSE_HOST is set, otherwise embedded
ClickHouse (chDB) in ./data so everything runs offline on a laptop.
"""
import json
import os
import time

SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS events (
        ts            DateTime64(3) DEFAULT now64(3),
        session_id    String,
        run_id        String,
        step          UInt16,
        kind          LowCardinality(String),   -- input | tool_call | reply | guardrail_block
        item_id       String,
        source        LowCardinality(String),   -- user | system | kb | ticket | web | tool
        trust         LowCardinality(String),   -- trusted | untrusted
        tool          LowCardinality(String),
        dest          String,
        dest_external UInt8,
        contains_pii  UInt8,
        content       String,
        content_norm  String,
        label         LowCardinality(String)    -- benign | attack (synthetic ground truth) | live
    ) ENGINE = MergeTree
    ORDER BY (label, session_id, step)
    """,
    """
    CREATE TABLE IF NOT EXISTS rules (
        created        DateTime64(3) DEFAULT now64(3),
        rule_id        String,
        spec           String,
        variants_total UInt32,
        variants_blocked UInt32,
        history_rows   UInt64,
        false_positives UInt64,
        verify_ms      Float64,
        deployed       UInt8
    ) ENGINE = MergeTree ORDER BY created
    """,
]


class Store:
    def __init__(self):
        self.backend = "cloud" if os.getenv("CLICKHOUSE_HOST") else "local"
        if self.backend == "cloud":
            import clickhouse_connect
            self.client = clickhouse_connect.get_client(
                host=os.environ["CLICKHOUSE_HOST"],
                username=os.getenv("CLICKHOUSE_USER", "default"),
                password=os.getenv("CLICKHOUSE_PASSWORD", ""),
                secure=True,
                port=int(os.getenv("CLICKHOUSE_PORT", "8443")),
                database=os.getenv("CLICKHOUSE_DATABASE", "default"),
            )
        else:
            from chdb import session
            path = os.getenv("AIS_DATA_DIR", os.path.join(os.path.dirname(__file__), "..", "data"))
            os.makedirs(path, exist_ok=True)
            self.sess = session.Session(path)
        for ddl in SCHEMA:
            self.execute(ddl)

    def execute(self, sql: str):
        if self.backend == "cloud":
            self.client.command(sql)
        else:
            self.sess.query(sql)

    def query(self, sql: str) -> list[dict]:
        if self.backend == "cloud":
            r = self.client.query(sql)
            return [dict(zip(r.column_names, row)) for row in r.result_rows]
        out = self.sess.query(sql, "JSONEachRow")
        text = out.data() if hasattr(out, "data") else str(out)
        return [json.loads(line) for line in text.splitlines() if line.strip()]

    def timed(self, sql: str) -> tuple[list[dict], float]:
        t0 = time.perf_counter()
        rows = self.query(sql)
        return rows, (time.perf_counter() - t0) * 1000

    def insert(self, table: str, rows: list[dict]):
        if not rows:
            return
        body = "\n".join(json.dumps(r, default=str) for r in rows)
        if self.backend == "cloud":
            self.client.raw_insert(table, insert_block=body.encode(), fmt="JSONEachRow")
        else:
            self.sess.query(f"INSERT INTO {table} FORMAT JSONEachRow\n{body}")


def q(s: str) -> str:
    """Quote a string literal for ClickHouse SQL."""
    return "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"
