"""
DSAC — PIP Context Collector v3 (FINAL)
Lit les headers HTTP en priorite ABSOLUE (insensible a la casse).
N'incremente le compteur de frequence QUE si le header est absent.
Auteur : NECDEM Wilfried — Univ. Dschang — URIFIA — 2026
"""
import time, hashlib, json, os
try:
    import psutil
    _HAS_PSUTIL = True
except ImportError:
    _HAS_PSUTIL = False

_freq_window: dict = {}
F_NORM = {"topology":3.0,"sync":2.0,"flow":5.0,"policy":1.0}

def _get_freq(source, action):
    key = f"{source}:{action.split(':')[0].lower()}"
    now = time.time()
    _freq_window.setdefault(key, [])
    _freq_window[key] = [t for t in _freq_window[key] if now-t < 60.0]
    _freq_window[key].append(now)
    return float(len(_freq_window[key]))

def _get_load():
    if _HAS_PSUTIL:
        try: return psutil.cpu_percent(interval=0.05)
        except: pass
    return 50.0

def _get_zone(source):
    return {"onos":"DC1","odl":"DC2"}.get(source.lower(),"UNKNOWN")

def _get_trust(source):
    return {"onos":0.85,"odl":0.80}.get(source.lower(),0.70)

def _action_type(action):
    a = action.lower()
    if "topology" in a: return "topology"
    if "sync"     in a: return "sync"
    if "flow"     in a: return "flow"
    if "policy"   in a: return "policy"
    return "other"

def collect_context(source, operation, target, urgency=0.5, headers=None):
    """Assemble tau. Headers du dataset prioritaires (insensible casse)."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    h   = headers or {}

    # Normalisation casse : FastAPI met les headers en minuscules
    h_lower = {k.lower(): v for k, v in h.items()}

    def hget_str(key, default):
        v = h_lower.get(key.lower())
        return v if v is not None else default

    def hget_float(key, default):
        v = h_lower.get(key.lower())
        if v is not None:
            try: return float(v)
            except: pass
        return default

    def hget_bool(key, default):
        v = h_lower.get(key.lower())
        if v is not None:
            return v.strip().lower() == "true"
        return default

    hour  = now.hour
    atype = _action_type(operation)

    # FREQUENCE : header prioritaire, sinon compteur local
    # (n'incremente PAS le compteur si le header existe)
    _freq_hdr = h_lower.get("x-update-freq")
    if _freq_hdr is not None:
        freq = float(_freq_hdr)
    else:
        freq = _get_freq(source, operation)

    load  = hget_float("X-Network-Load",         _get_load())
    siem  = hget_bool ("X-SIEM-Alert",           False)
    zone  = hget_str  ("X-Zone",                 _get_zone(source))
    trust = hget_float("X-Trust-Score",          _get_trust(source))
    just  = hget_bool ("X-Has-Justifying-Event", True)
    trig  = hget_bool ("X-Has-Triggering-Event", True)
    elaps = hget_float("X-Elapsed-Since-Event",  999.0)
    tamp  = hget_bool ("X-H-Tau-Tampered",       False)
    comp  = hget_bool ("X-Is-Compromised",       False)
    crit  = hget_bool ("X-Is-Critical",          False)
    ronly = hget_bool ("X-Is-Readonly",          False)
    malf  = hget_bool ("X-Is-Malformed",         False)

    # Type d'action explicite via header (prioritaire sur l'endpoint)
    action_hdr = h_lower.get("x-action-type")
    if action_hdr:
        operation = action_hdr
    op = operation.lower()
    context = {
        "subject":  source,
        "action":   operation,
        "resource": target,
        "environment": {
            "hour":                  hour,
            "network_load_pct":      round(load, 1),
            "trust_score":           trust,
            "siem_alert":            siem,
            "urgency":               urgency,
            "is_critical":           crit or any(k in op for k in
                                       ["flow","policy","block","delete"]),
            "is_readonly":           ronly or any(k in op for k in
                                       ["get","read","list","query"]),
            "zone":                  zone,
            "update_freq_60s":       freq,
            "has_justifying_event":  just,
            "has_triggering_event":  trig,
            "elapsed_since_event_s": elaps,
            "signature_valid":       True,
            "h_tau_tampered":        tamp,
            "is_compromised":        comp,
            "is_malformed":          malf,
        },
        "timestamp": now.isoformat(),
    }

    # Cle de cache = signature de DECISION (sans le timestamp volatil).
    # L'ancienne version hachait "timestamp" (microseconde) -> cle unique a
    # chaque requete -> 0 % de HIT. On ne hache que les attributs qui
    # determinent reellement le verdict.
    _cache_view = {
        "subject":     context["subject"],
        "action":      context["action"],
        "resource":    context["resource"],
        "environment": context["environment"],
    }
    h_tau = hashlib.sha256(
        json.dumps(_cache_view, sort_keys=True).encode()
    ).hexdigest()
    return context, h_tau
