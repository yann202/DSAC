# ~/dsac/proxy/main.py
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
import httpx
import time
import uuid
from pip_dsac.context import collect_context
from pdp.pdp import decide
from ledger.ledger import init_ledger
from monitor.metrics import (
    init_metrics_file, save_metric)

app = FastAPI(title="DSAC Proxy PEP")

ONOS_BASE  = "http://localhost:8181"
ODL_BASE   = "http://localhost:8182"
ONOS_AUTH  = ("onos", "rocks")
ODL_AUTH   = ("admin", "admin")

@app.on_event("startup")
async def startup():
    init_ledger()
    init_metrics_file()
    print("\n[DSAC] Proxy PEP démarré :8000\n")

@app.middleware("http")
async def dsac_middleware(request: Request,
                          call_next):
    if request.url.path in [
        "/health", "/ledger", "/metrics",
        "/metrics/summary",
        "/metrics/live",
        "/reset-freq",
        "/metrics/dashboard",
        "/dashboard",
        "/reset-freq",
        "/metrics/dashboard",
        "/dashboard",
        "/docs", "/openapi.json"
    ]:
        return await call_next(request)

    # Identifiant unique de la requête
    req_id = str(uuid.uuid4())[:8]
    t_total_start = time.perf_counter()

    # Extraction des attributs
    source    = request.headers.get(
        "X-Source-Controller", "onos")
    target    = request.headers.get(
        "X-Target-Controller", "odl")
    pk        = request.headers.get(
        "X-Sender-PK", f"pk_{source}")
    urgency   = float(request.headers.get(
        "X-Urgency", "0.5"))
    operation = (request.method + ":"
                 + str(request.url.path))

    metric = {
        "request_id": req_id,
        "source":     source,
        "target":     target,
        "operation":  operation,
        "urgency":    urgency
    }

    print(f"\n[{req_id}] ── Requête EW ──────────")
    print(f"[{req_id}] {source} → {target}")
    print(f"[{req_id}] op={operation} urg={urgency}")

    # ── PIP : mesure précise ───────────────────
    t_pip_start = time.perf_counter()
    tuple_abac, tuple_hash = collect_context(
        source, operation, target, urgency,
        headers=dict(request.headers))
    metric["t_pip_ms"] = (
        time.perf_counter() - t_pip_start) * 1000
    print(f"[{req_id}] PIP : "
          f"{metric['t_pip_ms']:.2f} ms")

    # ── PDP : mesure cache vs inférence ───────
    t_pdp_start = time.perf_counter()
    verdict, rule, cache_hit = decide(
        tuple_abac, tuple_hash, pk)
    t_pdp_total = (
        time.perf_counter() - t_pdp_start) * 1000

    if cache_hit:
        metric["t_cache_ms"]     = t_pdp_total
        metric["t_inference_ms"] = 0.0
    else:
        metric["t_cache_ms"]     = 0.0
        metric["t_inference_ms"] = t_pdp_total

    metric["cache_hit"] = cache_hit
    metric["verdict"]   = verdict
    metric["rule"]      = rule

    print(f"[{req_id}] PDP : {t_pdp_total:.2f} ms "
          f"({'HIT' if cache_hit else 'MISS'})")
    print(f"[{req_id}] Verdict : {verdict} ({rule})")

    # ── Application du verdict ─────────────────
    http_status    = 0
    t_forward_ms   = 0.0

    if verdict == "PERMIT":
        # Mode test : repondre sans forward (mesure latence decision pure)
        if request.headers.get("X-Trust-Score") is not None:
            metric["t_forward_ms"] = 0.0
            metric["t_total_ms"] = (time.perf_counter() - t_total_start) * 1000
            metric["http_status"] = 200
            import threading
            threading.Thread(target=save_metric, args=(metric,), daemon=True).start()
            return JSONResponse(status_code=200,
                content={"verdict":"PERMIT","mode":"test"})
        if target == "odl":
            base_url = ODL_BASE
            auth     = ODL_AUTH
        else:
            base_url = ONOS_BASE
            auth     = ONOS_AUTH

        target_url = base_url + str(request.url.path)
        body = await request.body()

        forward_headers = {
            k: v for k, v
            in request.headers.items()
            if k.lower() not in [
                'host', 'content-length',
                'x-source-controller',
                'x-target-controller',
                'x-sender-pk', 'x-urgency'
            ]
        }

        t_fwd_start = time.perf_counter()
        async with httpx.AsyncClient() as client:
            try:
                resp = await client.request(
                    method  = request.method,
                    url     = target_url,
                    headers = forward_headers,
                    content = body,
                    auth    = auth,
                    timeout = 10.0
                )
                t_forward_ms = (
                    time.perf_counter()
                    - t_fwd_start) * 1000
                http_status = resp.status_code
                print(f"[{req_id}] Forward : "
                      f"{t_forward_ms:.2f} ms "
                      f"→ {http_status}")
                response = Response(
                    content    = resp.content,
                    status_code= resp.status_code,
                    media_type = resp.headers.get(
                        "content-type",
                        "application/json")
                )
            except httpx.ConnectError as e:
                t_forward_ms = (
                    time.perf_counter()
                    - t_fwd_start) * 1000
                http_status = 502
                response = JSONResponse(
                    status_code=502,
                    content={
                        "error":   "CTRL_UNREACHABLE",
                        "target":  target_url,
                        "details": str(e)
                    }
                )
    else:
        http_status = 403
        response = JSONResponse(
            status_code=403,
            content={
                "error":      "PERMISSION_DENIED",
                "verdict":    "DENY",
                "rule":       rule,
                "source":     source,
                "target":     target,
                "request_id": req_id
            }
        )

    # ── Métriques finales ──────────────────────
    metric["t_forward_ms"] = t_forward_ms
    metric["t_total_ms"]   = (
        time.perf_counter() - t_total_start) * 1000
    metric["http_status"]  = http_status

    print(f"[{req_id}] TOTAL : "
          f"{metric['t_total_ms']:.2f} ms")
    print(f"[{req_id}] ─────────────────────────")

    # Sauvegarde asynchrone
    import threading
    threading.Thread(
        target=save_metric,
        args=(metric,),
        daemon=True
    ).start()

    return response

@app.get("/health")
async def health():
    import requests as req
    try:
        r = req.get(
            f"{ONOS_BASE}/onos/v1/devices",
            auth=ONOS_AUTH, timeout=2)
        onos = f"OK ({r.status_code})"
    except Exception as e:
        onos = f"KO - {e}"
    try:
        r = req.get(
            f"{ODL_BASE}/restconf/operational/"
            "network-topology:network-topology",
            auth=ODL_AUTH, timeout=2)
        odl = f"OK ({r.status_code})"
    except Exception as e:
        odl = f"KO - {e}"
    return {
        "proxy": "DSAC :8000",
        "onos":  onos,
        "odl":   odl
    }

@app.get("/ledger")
async def get_ledger():
    from ledger.ledger import read_ledger
    rows = read_ledger()
    return {
        "total":   len(rows),
        "entries": [
            {"no": r[0], "timestamp": r[1],
             "verdict": r[4], "rule": ""}
            for r in rows
        ]
    }

@app.get("/metrics/summary")
async def metrics_summary():
    """Résumé des métriques en temps réel"""
    import pandas as pd
    from monitor.metrics import METRICS_FILE
    try:
        df = pd.read_csv(METRICS_FILE)
        if df.empty:
            return {"message": "Aucune métrique"}
        return {
            "total_requests": len(df),
            "permit_count":   int(
                (df['verdict']=='PERMIT').sum()),
            "deny_count":     int(
                (df['verdict']=='DENY').sum()),
            "cache_hit_ratio": round(
                df['cache_hit'].mean() * 100, 1),
            "latence": {
                "pip_mean_ms": round(
                    df['t_pip_ms'].mean(), 2),
                "inference_mean_ms": round(
                    df['t_inference_ms'].mean(), 2),
                "total_mean_ms": round(
                    df['t_total_ms'].mean(), 2),
                "total_p99_ms": round(
                    df['t_total_ms'].quantile(.99),
                    2)
            }
        }
    except Exception as e:
        return {"error": str(e)}

@app.get("/metrics/live")
async def metrics_live():
    """Résumé des métriques en temps réel — sans pandas"""
    import csv
    from monitor.metrics import METRICS_FILE
    try:
        rows = []
        with open(METRICS_FILE, newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                rows.append(row)
        if not rows:
            return {"message": "Aucune metrique"}
        total    = len(rows)
        permits  = sum(1 for r in rows if r["verdict"] == "PERMIT")
        denies   = total - permits
        hits     = sum(1 for r in rows if r["cache_hit"] == "True")
        latences = [float(r["t_total_ms"]) for r in rows
                    if r["t_total_ms"]]
        latences.sort()
        p99_idx  = int(0.99 * len(latences))
        p99      = round(latences[p99_idx], 2) if latences else 0
        avg      = round(sum(latences)/len(latences), 2) if latences else 0
        return {
            "total_requests":  total,
            "permit_count":    permits,
            "deny_count":      denies,
            "precision_pct":   round(permits/total*100, 1),
            "cache_hit_ratio": round(hits/total*100, 1),
            "latence": {
                "mean_ms": avg,
                "p99_ms":  p99,
            }
        }
    except Exception as e:
        return {"error": str(e)}

@app.post("/reset-freq")
async def reset_freq():
    """Remet a zero le compteur de frequence du PIP entre les runs."""
    try:
        from pip_dsac.context import _freq_window
        _freq_window.clear()
        import redis as _redis
        _redis.Redis(host='localhost', port=6379, db=0).flushdb()
        return {"status": "reset OK", "timestamp": __import__('time').time()}
    except Exception as e:
        return {"status": "erreur", "detail": str(e)}

@app.post("/reset-freq")
async def reset_freq():
    """Remet a zero le compteur de frequence du PIP entre les runs."""
    try:
        from pip_dsac.context import _freq_window
        _freq_window.clear()
        import redis as _redis
        _redis.Redis(host='localhost', port=6379, db=0).flushdb()
        return {"status": "reset OK", "timestamp": __import__('time').time()}
    except Exception as e:
        return {"status": "erreur", "detail": str(e)}

@app.get("/metrics/dashboard")
async def metrics_dashboard():
    """Donnees du tableau de bord : metriques validees (campagne) + flux live."""
    import csv, json, os
    from collections import Counter
    from monitor.metrics import METRICS_FILE

    validated = None
    try:
        with open(os.path.expanduser("~/dsac/monitor/campaign_summary.json")) as f:
            validated = json.load(f)
    except Exception:
        validated = None

    live = {"total": 0, "permit": 0, "deny": 0, "cache_hit": None,
            "lat_mean": None, "lat_p99": None, "recent": [], "attaques": {}}
    try:
        rows = []
        with open(METRICS_FILE, newline="") as f:
            for r in csv.DictReader(f):
                rows.append(r)
        if rows:
            total   = len(rows)
            permits = sum(1 for r in rows if r["verdict"] == "PERMIT")
            hits    = sum(1 for r in rows if r.get("cache_hit") == "True")
            lats    = sorted(float(r["t_total_ms"]) for r in rows if r.get("t_total_ms"))
            regles  = Counter(r["rule"] for r in rows if r["verdict"] == "DENY")
            recent  = []
            for r in rows[-15:]:
                recent.append({
                    "id":      r.get("request_id", ""),
                    "source":  r.get("source", ""),
                    "verdict": r.get("verdict", ""),
                    "rule":    r.get("rule", ""),
                    "latence": r.get("t_total_ms", ""),
                })
            recent.reverse()
            live = {
                "total":     total,
                "permit":    permits,
                "deny":      total - permits,
                "cache_hit": round(hits/total*100, 1),
                "lat_mean":  round(sum(lats)/len(lats), 1) if lats else None,
                "lat_p99":   round(lats[int(0.99*len(lats))], 1) if lats else None,
                "attaques":  dict(regles.most_common(8)),
                "recent":    recent,
            }
    except Exception as e:
        live["error"] = str(e)

    return {"validated": validated, "live": live}

from fastapi.responses import FileResponse
import os as _os

@app.get("/dashboard")
async def dashboard():
    """Sert la page HTML du tableau de bord."""
    path = _os.path.expanduser("~/dsac/dashboard.html")
    return FileResponse(path)
