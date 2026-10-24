"""
DSAC — Ledger SQLite append-only
Chaine par prev_hash. Triggers SQL interdisant UPDATE/DELETE.

Auteur : NECDEM Wilfried — Univ. Dschang — URIFIA — 2026
"""
import sqlite3, hashlib, json, os
from datetime import datetime, timezone

DB_PATH = os.path.expanduser("~/dsac/ledger/dsac_ledger.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS dsac_ledger (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,
    sender_pk   TEXT NOT NULL,
    tuple_hash  TEXT NOT NULL,
    verdict     TEXT NOT NULL,
    rules       TEXT NOT NULL DEFAULT '[]',
    score_tau   REAL DEFAULT 0.0,
    justif      TEXT DEFAULT '',
    onto_ver    TEXT NOT NULL DEFAULT 'sdn_ew_v1.0',
    signed_hash TEXT NOT NULL,
    prev_hash   TEXT NOT NULL DEFAULT 'GENESIS'
);
CREATE TRIGGER IF NOT EXISTS no_update
    BEFORE UPDATE ON dsac_ledger
    BEGIN SELECT RAISE(ABORT,'UPDATE interdit : append-only'); END;
CREATE TRIGGER IF NOT EXISTS no_delete
    BEFORE DELETE ON dsac_ledger
    BEGIN SELECT RAISE(ABORT,'DELETE interdit : append-only'); END;
"""


def init_ledger():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()
    print(f"[LEDGER] Pret : {DB_PATH}")


def _last_hash() -> str:
    conn = sqlite3.connect(DB_PATH)
    row  = conn.execute(
        "SELECT signed_hash FROM dsac_ledger ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.close()
    return row[0] if row else "GENESIS"


def write_entry(sender_pk: str, tuple_hash: str,
                verdict: str, onto_version: str,
                signature: str,
                rules: list = None,
                score_tau: float = 0.0,
                justif: str = "") -> str:
    prev  = _last_hash()
    ts    = datetime.now(timezone.utc).isoformat()
    payload = f"{ts}|{sender_pk}|{tuple_hash}|{verdict}|{prev}"
    signed  = hashlib.sha256(
        (payload + "DSAC_PDP_KEY").encode()).hexdigest()
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""
            INSERT INTO dsac_ledger
            (timestamp,sender_pk,tuple_hash,verdict,
             rules,score_tau,justif,onto_ver,signed_hash,prev_hash)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        """, (ts, sender_pk, tuple_hash, verdict,
              json.dumps(rules or []), score_tau, justif,
              onto_version, signed, prev))
        conn.commit()
        conn.close()
        return signed
    except Exception as e:
        print(f"[LEDGER][ERREUR] {e}")
        return ""


def read_ledger(limit: int = 100) -> list:
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT * FROM dsac_ledger ORDER BY timestamp DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    return rows


def verify_chain() -> tuple:
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT id, signed_hash, prev_hash FROM dsac_ledger ORDER BY id ASC"
    ).fetchall()
    conn.close()
    for i in range(1, len(rows)):
        if rows[i][2] != rows[i-1][1]:
            return False, f"Incoherence entre id={rows[i-1][0]} et id={rows[i][0]}"
    return True, f"Chaine OK ({len(rows)} entrees)"
