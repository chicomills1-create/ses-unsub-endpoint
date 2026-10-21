#!/usr/bin/env python3
"""Durable suppression registry for the SES platform.

Store choice: SQLite (data/suppression.sqlite).
Justification: three independent writers/readers converge here (event processor
writes, sender reads at decision time, partitioner bulk-reads), writes must be
dedupe-safe under concurrency (PK + INSERT OR IGNORE), and the sender needs a
point lookup per candidate — a JSON file would force full-file lock+rewrite per
event and lose updates on a crash mid-write. SQLite gives WAL-mode concurrent
readers, single-writer transactions, and it is a file the whole platform shares.

UNION semantics: this registry UNIONS every suppression source; it never
replaces or deletes. Sources loaded by load_union_sources():
  1. ~/workspace/apex-email-sender/suppression-list.txt  (hard bounces, human-kept)
  2. RB2B exclusions snapshot emails (prior-contact / do-not-approach universe)
     — loaded with reason='prior-contact-exclusion' and enforced ONLY where the
     caller asks for exclusion enforcement (partitioner), NOT as SES bounce
     suppression; kept in a separate table so the two semantics never blur.
  3. Live SES events written by event_processor.py (bounce/complaint).
"""
import sqlite3, os, json, datetime, re

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "data", "suppression.sqlite")
SUPPRESSION_LIST = os.path.expanduser("~/workspace/apex-email-sender/suppression-list.txt")
RB2B_EXCLUSIONS = os.path.expanduser(
    "~/workspace/growth-marketing-2026-10-13/rb2b-auto/exclusions.json")

SCHEMA = """
CREATE TABLE IF NOT EXISTS suppressions(
  email TEXT PRIMARY KEY,
  reason TEXT NOT NULL,            -- hard_bounce | complaint | manual | source-list
  source TEXT NOT NULL,            -- ses-event | suppression-list | manual
  event_id TEXT,
  detail TEXT,
  first_seen TEXT NOT NULL,
  updated TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS exclusions(
  email TEXT PRIMARY KEY,
  source TEXT NOT NULL,
  detail TEXT,
  loaded TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS seen_events(
  event_key TEXT PRIMARY KEY,      -- SNS MessageId + SES mail.messageId + eventType
  event_type TEXT,
  email TEXT,
  processed TEXT NOT NULL,
  outcome TEXT);
CREATE TABLE IF NOT EXISTS heartbeat(
  id INTEGER PRIMARY KEY CHECK(id=1),
  last_poll TEXT,
  last_poll_ok INTEGER,
  last_event TEXT,
  queue_depth INTEGER);
"""


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def connect():
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    db = sqlite3.connect(DB, timeout=30)
    db.execute("PRAGMA journal_mode=WAL")
    db.executescript(SCHEMA)
    return db


def add_suppression(db, email, reason, source, event_id=None, detail=None):
    email = email.strip().lower()
    db.execute(
        "INSERT INTO suppressions(email,reason,source,event_id,detail,first_seen,updated)"
        " VALUES(?,?,?,?,?,?,?) ON CONFLICT(email) DO UPDATE SET updated=excluded.updated,"
        " detail=excluded.detail",
        (email, reason, source, event_id, detail, now_iso(), now_iso()))
    db.commit()


def is_suppressed(db, email):
    row = db.execute("SELECT reason FROM suppressions WHERE email=?",
                     (email.strip().lower(),)).fetchone()
    return row[0] if row else None


def load_union_sources(db):
    """Load file-based sources into the registry (idempotent). Returns counts."""
    counts = {"suppression_list": 0, "exclusions": 0}
    if os.path.exists(SUPPRESSION_LIST):
        with open(SUPPRESSION_LIST) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                email = line.split("#")[0].strip().lower()
                detail = line.split("#", 1)[1].strip() if "#" in line else ""
                if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
                    add_suppression(db, email, "hard_bounce", "suppression-list",
                                    detail=detail)
                    counts["suppression_list"] += 1
    if os.path.exists(RB2B_EXCLUSIONS):
        d = json.load(open(RB2B_EXCLUSIONS))
        for email in d.get("emails", []):
            db.execute("INSERT OR IGNORE INTO exclusions(email,source,detail,loaded)"
                       " VALUES(?,?,?,?)",
                       (email.strip().lower(), "rb2b-exclusions",
                        f"snapshot built_at={d.get('built_at')}", now_iso()))
            counts["exclusions"] += 1
        db.commit()
    return counts


def record_heartbeat(db, ok=True, queue_depth=None, event=False):
    ts = now_iso()
    db.execute("INSERT INTO heartbeat(id,last_poll,last_poll_ok,last_event,queue_depth)"
               " VALUES(1,?,?,?,?) ON CONFLICT(id) DO UPDATE SET last_poll=excluded.last_poll,"
               " last_poll_ok=excluded.last_poll_ok, queue_depth=excluded.queue_depth,"
               " last_event=CASE WHEN excluded.last_event IS NOT NULL THEN excluded.last_event"
               " ELSE heartbeat.last_event END",
               (ts, 1 if ok else 0, ts if event else None, queue_depth))
    db.commit()


STALE_WINDOW_HOURS = 6  # consult: stale telemetry = automatic hold


def pipeline_health(db):
    """Watchdog: the event pipeline is healthy only if the processor has polled
    successfully within STALE_WINDOW_HOURS. Returns (healthy: bool, detail: str).
    The sender's --live path MUST refuse to run when this is False."""
    row = db.execute("SELECT last_poll,last_poll_ok,last_event FROM heartbeat WHERE id=1").fetchone()
    if not row or not row[0]:
        return False, "no processor heartbeat on record — pipeline never ran"
    if not row[1]:
        return False, f"last poll FAILED at {row[0]}"
    last = datetime.datetime.fromisoformat(row[0])
    age_h = (datetime.datetime.now(datetime.timezone.utc) - last).total_seconds() / 3600
    if age_h > STALE_WINDOW_HOURS:
        return False, (f"STALE telemetry: last successful poll {age_h:.1f}h ago "
                       f"(window {STALE_WINDOW_HOURS}h) — automatic hold per consult")
    return True, f"healthy: last poll {age_h:.2f}h ago, last event {row[2]}"
