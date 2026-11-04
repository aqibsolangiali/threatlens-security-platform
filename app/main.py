from __future__ import annotations

import ipaddress
import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("THREATLENS_DB_PATH", Path(__file__).resolve().parent.parent / "threatlens.db"))
app = FastAPI(title="ThreatLens", version="1.0.0", description="Explainable URL safety analysis")
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")


class ScanRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2048)


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with db() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            domain TEXT NOT NULL,
            score INTEGER NOT NULL,
            level TEXT NOT NULL,
            findings TEXT NOT NULL,
            created_at TEXT NOT NULL
        )""")


init_db()


def analyze_url(raw: str) -> dict:
    value = raw.strip()
    if not value:
        raise HTTPException(status_code=422, detail="Enter a website address to scan.")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(status_code=422, detail="Enter a valid HTTP or HTTPS website address.")
    host = parsed.hostname.lower().rstrip(".")
    findings: list[dict] = []
    score = 0

    def flag(points: int, title: str, detail: str, severity: str = "warning") -> None:
        nonlocal score
        score += points
        findings.append({"title": title, "detail": detail, "severity": severity})

    if parsed.scheme == "http":
        flag(18, "Connection is not encrypted", "This address uses HTTP, so information sent to the site may not be protected in transit.")
    else:
        findings.append({"title": "HTTPS connection", "detail": "The address uses HTTPS. This protects the connection, but does not prove the site itself is trustworthy.", "severity": "good"})

    try:
        ipaddress.ip_address(host)
        flag(20, "Uses a raw IP address", "Legitimate sites can use IP addresses, but unexpected numeric addresses are often used in deceptive links.")
    except ValueError:
        pass

    if host.startswith("xn--") or ".xn--" in host:
        flag(22, "Internationalized domain", "This domain uses encoded characters. Some lookalike domains use characters that resemble familiar letters.")
    if host.count(".") >= 4:
        flag(10, "Unusually deep subdomain", "The address contains several subdomain levels. Check the registered domain carefully.")
    if "@" in parsed.netloc:
        flag(25, "Misleading @ symbol", "Text before @ in a URL can disguise the destination. The browser connects to the host after @.")
    if len(value) > 100:
        flag(8, "Unusually long address", "Long URLs can hide the real destination or contain confusing tracking parameters.")
    if host.count("-") >= 3:
        flag(8, "Many hyphens in domain", "A domain with several hyphens deserves a closer look, especially if it imitates a known brand.")
    if re.search(r"(login|verify|secure|account|update|password|wallet|bank)", host):
        flag(12, "Sensitive wording in domain", "The domain contains wording often used in account or payment lures. Confirm you recognize the exact domain.")
    if parsed.port and parsed.port not in {80, 443}:
        flag(10, "Non-standard web port", f"This site uses port {parsed.port}, which is less common for public websites.")
    if not findings or all(f["severity"] == "good" for f in findings):
        findings.append({"title": "No obvious URL patterns found", "detail": "This basic check did not identify common suspicious URL patterns. It cannot verify the site's content or reputation.", "severity": "good"})

    score = min(score, 100)
    if score >= 50:
        level, label = "high", "High risk indicators"
    elif score >= 25:
        level, label = "medium", "Caution advised"
    else:
        level, label = "low", "Fewer risk indicators"
    return {"url": value, "domain": host, "score": score, "level": level, "label": label, "findings": findings}


@app.get("/")
def home():
    return FileResponse(ROOT / "static" / "index.html")


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "ThreatLens", "version": "1.0.0"}


@app.post("/api/scan")
def scan(request: ScanRequest):
    result = analyze_url(request.url)
    created = datetime.now(timezone.utc).isoformat()
    with db() as conn:
        cursor = conn.execute(
            "INSERT INTO scans (url, domain, score, level, findings, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (result["url"], result["domain"], result["score"], result["level"], json.dumps(result["findings"]), created),
        )
        result["id"] = cursor.lastrowid
        result["created_at"] = created
    return result


@app.get("/api/history")
def history(limit: int = 20):
    limit = max(1, min(limit, 100))
    with db() as conn:
        rows = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [{"id": r["id"], "url": r["url"], "domain": r["domain"], "score": r["score"], "level": r["level"], "created_at": r["created_at"]} for r in rows]


@app.get("/api/stats")
def stats():
    with db() as conn:
        row = conn.execute("SELECT COUNT(*) total, SUM(CASE WHEN level='high' THEN 1 ELSE 0 END) high, SUM(CASE WHEN level='medium' THEN 1 ELSE 0 END) medium FROM scans").fetchone()
    return {"total_scans": row["total"] or 0, "high_risk": row["high"] or 0, "caution": row["medium"] or 0}


@app.delete("/api/history")
def clear_history():
    with db() as conn:
        conn.execute("DELETE FROM scans")
    return {"deleted": True}
