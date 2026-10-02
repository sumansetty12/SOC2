"""
Lightweight SQLite storage for Continuous Monitoring history.

This is intentionally a single local file (soc2_history.db), not a hosted
database — consistent with the project's self-hosted, zero-infrastructure-
cost design. Stores: each monitoring poll run, and each check result
triggered by a detected change.
"""
import sqlite3
import json
from datetime import datetime, timezone
from contextlib import contextmanager

DB_PATH = "soc2_history.db"


def init_db():
    with get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS poll_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                polled_at TEXT NOT NULL,
                source TEXT NOT NULL,              -- 'aws' or 'github'
                events_found INTEGER NOT NULL,      -- count of relevant changes detected
                triggered_recheck INTEGER NOT NULL  -- 0 or 1
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS check_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                checked_at TEXT NOT NULL,
                source TEXT NOT NULL,               -- 'aws' or 'github'
                trigger_reason TEXT NOT NULL,       -- what caused this re-check
                result_json TEXT NOT NULL,          -- full collector output
                summary TEXT NOT NULL               -- short human-readable summary
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS github_repo_state (
                repo_full_name TEXT PRIMARY KEY,
                last_branch_protected INTEGER,
                last_checked_at TEXT
            )
        """)


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def record_poll_run(source: str, events_found: int, triggered_recheck: bool):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO poll_runs (polled_at, source, events_found, triggered_recheck) VALUES (?, ?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(), source, events_found, int(triggered_recheck)),
        )


def record_check(source: str, trigger_reason: str, result: dict, summary: str):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO check_history (checked_at, source, trigger_reason, result_json, summary) VALUES (?, ?, ?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(), source, trigger_reason, json.dumps(result), summary),
        )


def get_recent_polls(limit: int = 20) -> list:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM poll_runs ORDER BY polled_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def get_check_history(limit: int = 20) -> list:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, checked_at, source, trigger_reason, summary FROM check_history ORDER BY checked_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_github_repo_state(repo_full_name: str):
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM github_repo_state WHERE repo_full_name = ?", (repo_full_name,)
        ).fetchone()
        return dict(row) if row else None


def set_github_repo_state(repo_full_name: str, branch_protected: bool):
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO github_repo_state (repo_full_name, last_branch_protected, last_checked_at)
               VALUES (?, ?, ?)
               ON CONFLICT(repo_full_name) DO UPDATE SET
                 last_branch_protected = excluded.last_branch_protected,
                 last_checked_at = excluded.last_checked_at""",
            (repo_full_name, int(branch_protected), datetime.now(timezone.utc).isoformat()),
        )
