"""
DSAC — Generateur Dataset Synthetique 10 000 requetes
6000 legitimes + 1000 Spoofing + 1000 MitM +
1000 TopologyPoisoning (Marionette) + 1000 FalseSync

References :
  Alrashede (2025b) : Spoofing + MitM signatures
  Cai et al. (2021) Marionette : Topology Poisoning
  Skowyra (2018) IEEE DSN : fenetre glissante 60s
  Alrashede (2025a) : False Sync fenetre 120s
  Jain (1991) : graine 42 pour reproductibilite

Auteur : NECDEM Wilfried — Univ. Dschang — URIFIA — 2026
"""
import json, random, hashlib, csv, os
from datetime import datetime, timezone, timedelta
from collections import Counter

BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
JSON_OUT  = os.path.join(BASE_DIR, "dsac_dataset_10k.json")
CSV_OUT   = os.path.join(BASE_DIR, "dsac_dataset_10k.csv")

F_NORM      = 3.0
LOAD_CRIT   = 85.0
TRUST_THRESH= 0.6
SYNC_WINDOW = 120.0
BASE_DATE   = datetime(2026, 1, 1, tzinfo=timezone.utc)

CONTROLLERS = [
    {"id": "onos-ctrl-A-dc1", "pk": "PK_ONOS_A_valid", "zone": "DC1"},
    {"id": "odl-ctrl-B-dc2",  "pk": "PK_ODL_B_valid",  "zone": "DC2"},
    {"id": "onos-ctrl-C-dc3", "pk": "PK_ONOS_C_valid",  "zone": "DC3"},
]


def ts(day=0, hour=10, minute=0):
    return (BASE_DATE + timedelta(
        days=day, hours=hour, minutes=minute)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")


def h_tau(sender, action, target, timestamp):
    raw = "|".join([sender, action, target, timestamp])
    return hashlib.sha256(raw.encode()).hexdigest()


def score(e):
    """S(tau) = w1*T_id + w2*T_comp + w3*T_ctx + w4*T_hist"""
    t_id = 1.0 if (e["signature_valid"]
                   and not e["h_tau_tampered"]) else 0.0
    if t_id == 0.0:
        return 0.0
    freq   = e["update_freq_60s"]
    t_comp = max(0.0, 1.0-(freq-F_NORM)/F_NORM) if freq>F_NORM else 1.0
    if e["zone"] == "UNKNOWN":
        t_comp = min(t_comp, 0.2)
    h    = e["hour"]
    sc_h = 1.0 if 8<=h<=18 else 0.1
    load = e["network_load_pct"]
    sc_l = 1.0 if load<70 else (0.5 if load<LOAD_CRIT else 0.1)
    sc_a = 0.0 if e["siem_alert"] else 1.0
    t_ctx  = (sc_h+sc_l+sc_a)/3.0
    t_hist = e["trust_score"]
    if not e["has_triggering_event"]:
        t_hist = min(t_hist, 0.5)
    return round(0.30*t_id+0.25*t_comp+0.25*t_ctx+0.20*t_hist, 4)


def rules(e, action, sc):
    """Retourne les regles declenchees."""
    if e["is_malformed"]:           return ["R0-MALFORMED"]
    if e["h_tau_tampered"]:         return ["R_MITM-HASH"]
    if e["siem_alert"]:             return ["R1-SIEM"]
    if e["is_compromised"]:         return ["R6-COMPROMISED"]
    if e["trust_score"] < 0.4:      return ["R3-LOW-TRUST"]
    if e["network_load_pct"]>LOAD_CRIT and e["is_critical"]:
        return ["R5-OVERLOAD"]
    if e["zone"]=="UNKNOWN" and e["update_freq_60s"]>10:
        return ["R_B3-SPOOFING"]
    if ("topology" in action.lower()
            and e["update_freq_60s"]>F_NORM
            and not e["has_justifying_event"]):
        return ["R_B1-TOPO-POISONING"]
    if ("sync" in action.lower()
            and not e["has_triggering_event"]
            and e["elapsed_since_event_s"]<SYNC_WINDOW):
        return ["R_B2-FALSE-SYNC"]
    if e["urgency"]>=0.8 and e["trust_score"]>=0.7:
        return ["R9-URGENT"]
    if e["is_readonly"] and e["trust_score"]>=0.5:
        return ["R8-READONLY"]
    if 8<=e["hour"]<=18 and sc>=TRUST_THRESH:
        return ["R7-BUSINESS-HOURS"]
    return ["R0-DEFAULT-DENY"]


def verdict_from_rules(r_list):
    deny_kw = ["DENY","MITM","SIEM","COMPROMISED","TRUST",
                "OVERLOAD","SPOOFING","POISONING","SYNC",
                "MALFORMED","DEFAULT"]
    for r in r_list:
        if any(k in r for k in deny_kw):
            return "DENY"
    return "PERMIT"


def build(base, action, attack_type, ref):
    sc   = score(base)
    rls  = rules(base, action, sc)
    verd = verdict_from_rules(rls)
    base.update({
        "action_type":      action,
        "score_tau":        sc,
        "triggered_rules":  rls,
        "computed_verdict": verd,
        "attack_type":      attack_type,
        "ref_article":      ref,
        "h_tau":            h_tau(base["sender_id"],
                                  action,
                                  base["target_resource"],
                                  base["timestamp"]),
    })
    if base["expected_label"] != verd:
        base["label_conflict"] = True
    return base


# ── Generateurs ───────────────────────────────────────────────────

def gen_legitimate(n=6000):
    actions = ["TopologyUpdateRequest","SynchronizationRequest",
                "FlowRuleModificationRequest","PolicyDistributionRequest"]
    out = []
    for i in range(n):
        c  = random.choice(CONTROLLERS)
        tg = random.choice([x for x in CONTROLLERS if x["id"]!=c["id"]])
        act= random.choice(actions)
        d  = random.randint(0,89)
        h  = random.randint(8,17)
        m  = random.randint(0,59)
        e  = {
            "id":f"leg_{i:05d}",
            "sender_id":c["id"], "sender_pk":c["pk"],
            "target_resource":f"{tg['id']}/{act.lower()}",
            "timestamp":ts(d,h,m),
            "signature_valid":True, "h_tau_tampered":False,
            "hour":h, "network_load_pct":random.randint(10,75),
            "siem_alert":False, "zone":c["zone"],
            "urgency":round(random.uniform(0.1,0.6),2),
            "is_critical":random.choice([True,False]),
            "is_readonly":random.choice([True,False]),
            "update_freq_60s":random.randint(1,3),
            "elapsed_since_event_s":random.randint(120,600),
            "has_justifying_event":True,
            "has_triggering_event":True,
            "trust_score":round(random.uniform(0.65,0.99),2),
            "is_malformed":False, "is_compromised":False,
            "expected_label":"PERMIT",
        }
        out.append(build(e, act, None,
                         "Trafic legitime de reference"))
    return out


def gen_spoofing(n=1000):
    """
    Signature Spoofing — Alrashede (2025b) section 4.2
    Cle ECDSA valide (copiee) + zone inconnue + comportement anormal.
    DSAC detecte ce que la verification cryptographique seule manque.
    """
    out = []
    for i in range(n):
        c = CONTROLLERS[0]
        h = random.choice([0,1,2,3,22,23])
        d = random.randint(0,89)
        e = {
            "id":f"spoof_{i:04d}",
            "sender_id":c["id"], "sender_pk":c["pk"],
            "target_resource":"odl-ctrl-B-dc2/flows/critical",
            "timestamp":ts(d,h,random.randint(0,59)),
            "signature_valid":True,        # cle valide copiee
            "h_tau_tampered":False,
            "hour":h,
            "network_load_pct":random.randint(20,55),
            "siem_alert":False,
            "zone":"UNKNOWN",              # zone inconnue
            "urgency":round(random.uniform(0.1,0.3),2),
            "is_critical":False,
            "is_readonly":False,
            "update_freq_60s":random.randint(15,40),  # freq anormale
            "elapsed_since_event_s":600,
            "has_justifying_event":True,
            "has_triggering_event":True,
            "trust_score":round(random.uniform(0.25,0.52),2),
            "is_malformed":False, "is_compromised":False,
            "expected_label":"DENY",
        }
        out.append(build(e, "FlowRuleModificationRequest",
                         "SPOOFING",
                         "Alrashede (2025b) §4.2 — Behavioral Spoofing"))
    return out


def gen_mitm(n=1000):
    """
    Signature MitM — Alrashede (2025b) section 4.3
    Modification d'un champ de tau en transit.
    H(tau) declare != H(tau) recalcule par le recepteur.
    """
    out = []
    for i in range(n):
        c = random.choice(CONTROLLERS[:2])
        h = random.randint(9,17)
        d = random.randint(0,89)
        e = {
            "id":f"mitm_{i:04d}",
            "sender_id":c["id"], "sender_pk":c["pk"],
            "target_resource":"odl-ctrl-B-dc2/flows/route_TAMPERED",
            "timestamp":ts(d,h,random.randint(0,59)),
            "signature_valid":True,
            "h_tau_tampered":True,         # hash falsifie
            "hour":h,
            "network_load_pct":random.randint(20,65),
            "siem_alert":False,
            "zone":c["zone"],
            "urgency":round(random.uniform(0.2,0.5),2),
            "is_critical":True,
            "is_readonly":False,
            "update_freq_60s":random.randint(1,3),
            "elapsed_since_event_s":600,
            "has_justifying_event":True,
            "has_triggering_event":True,
            "trust_score":round(random.uniform(0.70,0.90),2),
            "is_malformed":False, "is_compromised":False,
            "expected_label":"DENY",
        }
        out.append(build(e, "FlowRuleModificationRequest",
                         "MITM",
                         "Alrashede (2025b) §4.3 — MitM via H(tau) tampering"))
    return out


def gen_topology_poisoning(n=1000):
    """
    Signature Topology Poisoning — Cai et al. (2021) Marionette
    + Skowyra et al. (2018) IEEE DSN fenetre glissante 60s.
    Injection de TopologyUpdate a haute frequence sans evenement reseau.
    """
    out = []
    for i in range(n):
        c = random.choice(CONTROLLERS[:2])
        h = random.randint(8,18)   # discret : heures ouvrees
        d = random.randint(0,89)
        e = {
            "id":f"topopois_{i:04d}",
            "sender_id":c["id"], "sender_pk":c["pk"],
            "target_resource":"odl-ctrl-B-dc2/topology/links",
            "timestamp":ts(d,h,random.randint(0,59)),
            "signature_valid":True,
            "h_tau_tampered":False,
            "hour":h,
            "network_load_pct":random.randint(25,70),
            "siem_alert":False,
            "zone":c["zone"],
            "urgency":round(random.uniform(0.1,0.3),2),
            "is_critical":False,
            "is_readonly":False,
            "update_freq_60s":random.randint(8,25),  # >> F_norm=3
            "elapsed_since_event_s":random.randint(5,55),
            "has_justifying_event":False,  # CLE : pas d'evenement
            "has_triggering_event":True,
            "trust_score":round(random.uniform(0.65,0.88),2),
            "is_malformed":False, "is_compromised":False,
            "expected_label":"DENY",
        }
        out.append(build(e, "TopologyUpdateRequest",
                         "TOPOLOGY_POISONING",
                         "Cai et al. (2021) Marionette + Skowyra (2018) IEEE DSN"))
    return out


def gen_false_sync(n=1000):
    """
    Signature False Synchronization — Alrashede (2025a) section 3.4
    Vecteur : State Exhaustion via False Sync.
    SyncRequest sans evenement declencheur dans les 120s.
    """
    out = []
    for i in range(n):
        c  = random.choice(CONTROLLERS)
        tg = random.choice([x for x in CONTROLLERS if x["id"]!=c["id"]])
        h  = random.randint(8,18)
        d  = random.randint(0,89)
        e  = {
            "id":f"falsesync_{i:04d}",
            "sender_id":c["id"], "sender_pk":c["pk"],
            "target_resource":f"{tg['id']}/state/sync",
            "timestamp":ts(d,h,random.randint(0,59)),
            "signature_valid":True,
            "h_tau_tampered":False,
            "hour":h,
            "network_load_pct":random.randint(20,60),
            "siem_alert":False,
            "zone":c["zone"],
            "urgency":round(random.uniform(0.05,0.25),2),
            "is_critical":False,
            "is_readonly":False,
            "update_freq_60s":random.randint(1,3),
            "elapsed_since_event_s":random.randint(10,115),
            "has_justifying_event":True,
            "has_triggering_event":False,  # CLE : pas de declencheur
            "trust_score":round(random.uniform(0.65,0.82),2),
            "is_malformed":False, "is_compromised":False,
            "expected_label":"DENY",
        }
        out.append(build(e, "SynchronizationRequest",
                         "FALSE_SYNC",
                         "Alrashede (2025a) §3.4 — State Exhaustion via False Sync"))
    return out


# ── Main ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Generation du dataset DSAC (10 000 requetes)...")
    print("  -> 6000 requetes legitimes...")
    leg   = gen_legitimate(6000)
    print("  -> 1000 attaques Spoofing (Alrashede 2025b)...")
    spoof = gen_spoofing(1000)
    print("  -> 1000 attaques MitM (Alrashede 2025b)...")
    mitm  = gen_mitm(1000)
    print("  -> 1000 attaques Topology Poisoning (Marionette)...")
    topo  = gen_topology_poisoning(1000)
    print("  -> 1000 attaques False Sync (Alrashede 2025a)...")
    fsync = gen_false_sync(1000)

    dataset = leg + spoof + mitm + topo + fsync
    random.seed(42)   # reproductibilite (Jain 1991)
    random.shuffle(dataset)
    for i, e in enumerate(dataset):
        e["global_id"] = i

    # Verification coherence
    conflicts = [r for r in dataset if r.get("label_conflict")]
    print(f"\nVerification : {len(conflicts)} conflit(s) "
          f"({'OK' if not conflicts else 'ATTENTION'})")

    # Sauvegarde JSON
    with open(JSON_OUT, "w", encoding="utf-8") as f:
        json.dump(dataset, f, indent=2, ensure_ascii=False)
    print(f"JSON : {JSON_OUT}")

    # Sauvegarde CSV
    fields = ["global_id","id","sender_id","action_type",
              "timestamp","hour","network_load_pct","siem_alert",
              "zone","urgency","is_critical","update_freq_60s",
              "elapsed_since_event_s","has_justifying_event",
              "has_triggering_event","trust_score",
              "signature_valid","h_tau_tampered","score_tau",
              "expected_label","computed_verdict","attack_type",
              "triggered_rules"]
    with open(CSV_OUT, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for row in dataset:
            row2 = row.copy()
            row2["triggered_rules"] = ";".join(row.get("triggered_rules",[]))
            w.writerow(row2)
    print(f"CSV  : {CSV_OUT}")

    # Statistiques
    cats   = Counter(r.get("attack_type") or "LEGITIMATE" for r in dataset)
    labels = Counter(r["expected_label"] for r in dataset)
    scores_p = [r["score_tau"] for r in dataset if r["expected_label"]=="PERMIT"]
    scores_d = [r["score_tau"] for r in dataset if r["expected_label"]=="DENY"]
    print("\n=== STATISTIQUES ===")
    print(f"Total : {len(dataset)}")
    for k,v in sorted(cats.items(), key=lambda x:-x[1]):
        print(f"  {k:<30} : {v:>5}  ({100*v/len(dataset):.1f}%)")
    print(f"PERMIT : {labels['PERMIT']}  "
          f"avg S(tau)={sum(scores_p)/len(scores_p):.4f}")
    print(f"DENY   : {labels['DENY']}  "
          f"avg S(tau)={sum(scores_d)/len(scores_d):.4f}")
    print("\nDataset pret.")
