# ~/dsac/pdp/pdp.py
import redis
import hashlib
import threading
from pdp.reasoner import run_inference
from ledger.ledger import write_entry

redis_client = redis.Redis(
    host='localhost', port=6379, db=0)
ONTO_VERSION = "v1.0.0"

def decide(tuple_abac, tuple_hash, sender_pk):
    """
    Retourne : (verdict, rule, cache_hit)
    """
    # ── Cache Redis ────────────────────────────
    cached = redis_client.get(tuple_hash)
    if cached:
        data    = cached.decode().split("|")
        verdict = data[0]
        rule    = data[1] if len(data) > 1 \
                          else "CACHE"
        print(f"[PDP][HIT]  {verdict} / {rule}")
        _async_ledger(sender_pk, tuple_hash,
                      verdict)
        return verdict, rule, True

    # ── Inférence ─────────────────────────────
    print("[PDP][MISS] → Inférence")
    verdict, rule = run_inference(tuple_abac)

    # ── Mise en cache ─────────────────────────
    ttl = 300 if verdict == "PERMIT" else 60
    redis_client.setex(
        tuple_hash, ttl,
        f"{verdict}|{rule}")

    # ── Ledger ─────────────────────────────────
    _async_ledger(sender_pk, tuple_hash, verdict)

    return verdict, rule, False

def _async_ledger(sender_pk, tuple_hash, verdict):
    signed = hashlib.sha256(
        f"{tuple_hash}{verdict}".encode()
    ).hexdigest()
    t = threading.Thread(
        target=write_entry,
        args=(sender_pk, tuple_hash,
              verdict, ONTO_VERSION, signed),
        daemon=True
    )
    t.start()
