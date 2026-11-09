"""
DSAC — Campagne de tests 50 runs (FINAL)
Mesure la latence de DECISION (PIP+PDP), pas le forward reseau.
Auteur : NECDEM Wilfried — Univ. Dschang — URIFIA — 2026
"""
import json, time, random, requests, statistics, csv, redis

PROXY_URL   = "http://localhost:8000"
import os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET     = os.path.join(ROOT, "dataset", "dsac_dataset_10k.json")
N_RUNS      = 50
REQ_PER_RUN = 200
random.seed(42)

r_client = redis.Redis(host='localhost', port=6379, db=0)

print("Chargement dataset...")
with open(DATASET) as f:
    dataset = json.load(f)
print(f"  {len(dataset)} requetes\n")

# Tous les endpoints pointent vers /health (exclu du forward)
# pour mesurer UNIQUEMENT la latence de decision DSAC
ENDPOINT = "/restconf/operational/network-topology:network-topology"

def send_request(entry):
    src = entry.get("sender_id", "onos-ctrl-A-dc1").split("-")[0]
    headers = {
        "X-Action-Type":          entry.get("action_type","TopologyUpdateRequest"),
        "X-Source-Controller":    src,
        "X-Target-Controller":    "odl",
        "X-Sender-PK":            entry.get("sender_pk", "PK_valid"),
        "X-Urgency":              str(entry.get("urgency", 0.3)),
        "X-Trust-Score":          str(entry.get("trust_score", 0.80)),
        "X-Update-Freq":          str(entry.get("update_freq_60s", 2)),
        "X-Network-Load":         str(entry.get("network_load_pct", 40)),
        "X-SIEM-Alert":           str(entry.get("siem_alert", False)),
        "X-Zone":                 str(entry.get("zone", "DC1")),
        "X-Has-Justifying-Event": str(entry.get("has_justifying_event", True)),
        "X-Has-Triggering-Event": str(entry.get("has_triggering_event", True)),
        "X-Elapsed-Since-Event":  str(entry.get("elapsed_since_event_s", 999)),
        "X-H-Tau-Tampered":       str(entry.get("h_tau_tampered", False)),
        "X-Is-Compromised":       str(entry.get("is_compromised", False)),
        "X-Is-Critical":          str(entry.get("is_critical", False)),
        "X-Is-Readonly":          str(entry.get("is_readonly", False)),
        "X-Is-Malformed":         str(entry.get("is_malformed", False)),
    }
    t0 = time.perf_counter()
    try:
        resp = requests.get(f"{PROXY_URL}{ENDPOINT}",
                            headers=headers, timeout=10.0)
        lat = (time.perf_counter() - t0) * 1000
        got = "PERMIT" if resp.status_code == 200 else "DENY"
        exp = entry.get("expected_label", "PERMIT")
        return {"lat": round(lat,2), "got": got, "exp": exp,
                "ok": got==exp, "atk": entry.get("attack_type")}
    except Exception:
        return {"lat":9999,"got":"ERR","exp":"PERMIT","ok":False,"atk":None}

print(f"Campagne : {N_RUNS} x {REQ_PER_RUN} = {N_RUNS*REQ_PER_RUN} requetes\n")

run_p99s, run_precs, all_results = [], [], []

for run in range(1, N_RUNS+1):
    # Reset complet entre runs
    r_client.flushdb()
    try:
        requests.post(f"{PROXY_URL}/reset-freq", timeout=3)
    except: pass

    sample  = random.sample(dataset, REQ_PER_RUN)
    results = [send_request(e) for e in sample]
    lats    = sorted(r["lat"] for r in results if r["lat"] < 9000)

    total   = len(results)
    ok      = sum(1 for r in results if r["ok"])
    permits = sum(1 for r in results if r["got"]=="PERMIT")
    denies  = total - permits
    atks    = [r for r in results if r["atk"]]
    tp      = sum(1 for r in atks if r["got"]=="DENY")
    fp      = sum(1 for r in results if not r["atk"] and r["got"]=="DENY")
    p99     = lats[int(0.99*len(lats))] if lats else 0
    prec    = ok/total*100

    run_p99s.append(p99)
    run_precs.append(prec)
    all_results.extend(results)

    print(f"Run {run:02d}/{N_RUNS} | P99={p99:6.1f}ms | "
          f"Prec={prec:5.1f}% | PERMIT={permits:3d} DENY={denies:3d} | "
          f"TP={tp}/{len(atks)} FP={fp}")
    time.sleep(0.1)

# Synthese
print("\n" + "="*60)
print("SYNTHESE — 50 RUNS")
print("="*60)
all_lats = sorted(r["lat"] for r in all_results if r["lat"]<9000)
p99_g    = all_lats[int(0.99*len(all_lats))] if all_lats else 0
total_r  = len(all_results)
total_ok = sum(1 for r in all_results if r["ok"])
total_fp = sum(1 for r in all_results if not r["atk"] and r["got"]=="DENY")
total_tp = sum(1 for r in all_results if r["atk"] and r["got"]=="DENY")
total_atk= sum(1 for r in all_results if r["atk"])

print(f"Total requetes  : {total_r}")
print(f"Latence P99     : {p99_g:.2f} ms")
print(f"Latence moyenne : {statistics.mean(all_lats):.2f} ms")
print(f"P99 moy/run     : {statistics.mean(run_p99s):.2f} +/- {statistics.stdev(run_p99s):.2f} ms")
print(f"Precision       : {total_ok/total_r*100:.1f}%")
print(f"Prec moy/run    : {statistics.mean(run_precs):.1f}% +/- {statistics.stdev(run_precs):.2f}")
print(f"Faux positifs   : {total_fp/total_r*100:.1f}%")
print(f"Detection atk   : {total_tp}/{total_atk} ({total_tp/total_atk*100:.1f}%)")
print("="*60)

with open(os.path.join(ROOT, "tests", "resultats_50runs.csv"),"w",newline="") as f:
    w = csv.writer(f)
    w.writerow(["run","p99_ms","precision_pct"])
    for i,(p,pr) in enumerate(zip(run_p99s,run_precs),1):
        w.writerow([i, round(p,2), round(pr,1)])
print("Resultats : ~/dsac/tests/resultats_50runs.csv")
