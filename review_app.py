"""Local, human-reviewed KEV candidate queue with a tamper-evident decision log."""

import argparse
import csv
import hashlib
import json
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from evidence_assistant import answer, load_evidence
from ui import render_page

ROOT = Path(__file__).resolve().parent
DB = ROOT / "data" / "reviews.sqlite3"
CSV = ROOT / "data" / "review_candidates.csv"
STATUSES = {"NEEDS_VERSION_AND_CONFIGURATION_REVIEW", "INVESTIGATING", "NOT_AFFECTED", "AFFECTED", "REMEDIATED"}
TOKEN = secrets.token_urlsafe(32)


@contextmanager
def connect():
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def initialize():
    with connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS candidates (
            asset_id TEXT NOT NULL, cve_id TEXT NOT NULL, business_criticality TEXT NOT NULL,
            date_added TEXT NOT NULL, cisa_due_date TEXT NOT NULL,
            cisa_required_action TEXT NOT NULL, evidence_url TEXT NOT NULL,
            source_sha256 TEXT NOT NULL, review_status TEXT NOT NULL,
            PRIMARY KEY (asset_id,cve_id)
        );
        CREATE TABLE IF NOT EXISTS decisions (
            id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id TEXT NOT NULL, cve_id TEXT NOT NULL,
            old_status TEXT NOT NULL, new_status TEXT NOT NULL, reviewer TEXT NOT NULL,
            rationale TEXT NOT NULL, at_utc TEXT NOT NULL, previous_hash TEXT NOT NULL,
            event_hash TEXT NOT NULL
        );
        """)
        with CSV.open(newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                db.execute("""INSERT OR IGNORE INTO candidates VALUES (?,?,?,?,?,?,?,?,?)""",
                           tuple(row[k] for k in ("asset_id", "cve_id", "business_criticality", "date_added", "cisa_due_date", "cisa_required_action", "evidence_url", "source_sha256", "review_status")))
        return db.execute("SELECT COUNT(*) FROM candidates").fetchone()[0]


def event_digest(event):
    return hashlib.sha256(json.dumps(event, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def decide(asset_id, cve_id, new_status, reviewer, rationale):
    reviewer, rationale = reviewer.strip(), rationale.strip()
    if new_status not in STATUSES or not reviewer or not rationale or len(reviewer) > 80 or len(rationale) > 2000:
        raise ValueError("Select a status and provide a reviewer name and rationale.")
    with connect() as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT review_status FROM candidates WHERE asset_id=? AND cve_id=?", (asset_id, cve_id)).fetchone()
        if row is None:
            raise ValueError("Candidate not found.")
        if row[0] == new_status:
            raise ValueError("Select a different status.")
        last = db.execute("SELECT event_hash FROM decisions ORDER BY id DESC LIMIT 1").fetchone()
        event = dict(asset_id=asset_id, cve_id=cve_id, old_status=row[0], new_status=new_status,
                     reviewer=reviewer, rationale=rationale, at_utc=datetime.now(timezone.utc).isoformat(),
                     previous_hash=last[0] if last else "GENESIS")
        digest = event_digest(event)
        db.execute("UPDATE candidates SET review_status=? WHERE asset_id=? AND cve_id=?", (new_status, asset_id, cve_id))
        db.execute("INSERT INTO decisions (asset_id,cve_id,old_status,new_status,reviewer,rationale,at_utc,previous_hash,event_hash) VALUES (?,?,?,?,?,?,?,?,?)",
                   (*event.values(), digest))
        return digest


def check_chain():
    previous = "GENESIS"
    with connect() as db:
        rows = db.execute("SELECT * FROM decisions ORDER BY id").fetchall()
        latest = {}
        for row in rows:
            event = {k: row[k] for k in ("asset_id", "cve_id", "old_status", "new_status", "reviewer", "rationale", "at_utc", "previous_hash")}
            if event["previous_hash"] != previous or event_digest(event) != row["event_hash"]:
                raise ValueError(f"Audit chain failed at event {row['id']}")
            key = (row["asset_id"], row["cve_id"])
            expected = latest.get(key, "NEEDS_VERSION_AND_CONFIGURATION_REVIEW")
            if row["old_status"] != expected:
                raise ValueError(f"Invalid status transition at event {row['id']}")
            latest[key] = row["new_status"]
            previous = row["event_hash"]
        for row in db.execute("SELECT asset_id,cve_id,review_status FROM candidates"):
            key = (row["asset_id"], row["cve_id"])
            if row["review_status"] != latest.get(key, "NEEDS_VERSION_AND_CONFIGURATION_REVIEW"):
                raise ValueError(f"Candidate status differs from decision log: {key}")
    return len(rows)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        url = urlsplit(self.path)
        if url.path != "/":
            self.send_error(404)
            return
        query = parse_qs(url.query).get("q", [""])[0][:200].strip()
        evidence = load_evidence()
        search_result = answer(query, evidence) if query else None
        with connect() as db:
            candidates = db.execute("SELECT * FROM candidates ORDER BY CASE business_criticality WHEN 'high' THEN 0 ELSE 1 END, date_added DESC, asset_id").fetchall()
            decisions = db.execute("SELECT * FROM decisions ORDER BY id DESC LIMIT 12").fetchall()
        body = render_page(candidates, decisions, evidence, search_result, query, TOKEN)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/decide":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        if length > 4096:
            self.send_error(413)
            return
        form = parse_qs(self.rfile.read(length).decode("utf-8"))
        value = lambda key: form.get(key, [""])[0]
        if not secrets.compare_digest(value("token"), TOKEN):
            self.send_error(403)
            return
        try:
            decide(value("asset_id"), value("cve_id"), value("status"), value("reviewer"), value("rationale"))
        except ValueError as exc:
            self.send_error(400, str(exc))
            return
        self.send_response(303)
        self.send_header("Location", "/")
        self.end_headers()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("init", "serve", "check"))
    args = parser.parse_args()
    if args.command == "init":
        print(f"{initialize()} candidates loaded")
    elif args.command == "check":
        print(f"{check_chain()} audit events verified")
    else:
        initialize()
        print("Local review interface: http://127.0.0.1:8765/")
        HTTPServer(("127.0.0.1", 8765), Handler).serve_forever()
