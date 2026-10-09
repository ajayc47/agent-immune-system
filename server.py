#!/usr/bin/env python3
"""Dashboard server for the live demo.

    uvicorn server:app --reload      # http://127.0.0.1:8000

GET /            -> dashboard page
GET /api/stats   -> corpus size + rolling detection summary (with query latency)
POST /api/run    -> run the full detect->replay->vaccinate->reverify pipeline
"""
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
import pathlib

from ais.detect import summary
from ais.pipeline import run_demo
from ais.store import Store

app = FastAPI(title="Agent Immune System")
INDEX = (pathlib.Path(__file__).parent / "static" / "index.html").read_text(encoding="utf-8")


@app.get("/", response_class=HTMLResponse)
def index():
    return INDEX


@app.get("/api/stats")
def stats():
    store = Store()
    s, ms = summary(store)
    return {"backend": store.backend, "summary": s, "latency_ms": round(ms, 2)}


@app.post("/api/run")
def run():
    return run_demo(Store())
