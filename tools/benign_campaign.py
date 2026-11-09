#!/usr/bin/env python3
"""
DSAC - Validation on independently generated legitimate traffic.

Sends a fixed number of legitimate East-West requests through the DSAC proxy
(PEP) and measures the false-positive rate, i.e. the share of requests that
DSAC refuses although all of them are legitimate by construction.

IMPORTANT DESIGN CHOICE
-----------------------
The script does NOT send the test headers used by the existing campaigns
(X-Trust-Score, X-Network-Load, X-Zone, X-Update-Freq, ...). Without
X-Trust-Score the proxy leaves its "test mode": the PIP measures the context
itself (real CPU load through psutil, real request frequency through its
sliding window, real UTC hour, zone and trust derived from the controller
identity) and PERMIT requests are forwarded to the controller. Only
X-Source-Controller, X-Target-Controller, X-Sender-PK and X-Urgency are sent.

Usage (from the project directory, with the infrastructure running):
    python3 tools/benign_campaign.py --requests 10000 --hours 10 --utc-window 8-18
    python3 tools/benign_campaign.py --analyze-only results/benign_.../requests.csv
"""
import argparse
import csv
import json
import math
import os
import random
import statistics
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone

import requests

# ---------------------------------------------------------------------------
# Workload model (documented assumption, to be stated in the paper)
# ---------------------------------------------------------------------------
# (name, method, weight, {target: path}, is_write)
OPERATIONS = [
    ("topology_read", "GET", 30,
     {"odl": "/restconf/operational/network-topology:network-topology",
      "onos": "/onos/v1/topology"}, False),
    ("inventory_read", "GET", 15,
     {"odl": "/restconf/operational/opendaylight-inventory:nodes",
      "onos": "/onos/v1/devices"}, False),
    ("sync_state_read", "GET", 10,
     {"odl": "/restconf/operational/sync/state",
      "onos": "/onos/v1/topology/clusters"}, False),
    ("topology_update", "PUT", 15,
     {"odl": "/restconf/operational/network-topology:network-topology",
      "onos": "/onos/v1/topology"}, True),
    ("synchronisation", "POST", 15,
     {"odl": "/restconf/operational/sync",
      "onos": "/onos/v1/sync"}, True),
    ("flow_rule", "POST", 8,
     {"odl": "/restconf/config/opendaylight-inventory:nodes/node/openflow:2/"
             "flow-node-inventory:table/0/flow/1",
      "onos": "/onos/v1/flows/of:0000000000000001"}, True),
    ("policy_push", "POST", 7,
     {"odl": "/restconf/config/policy",
      "onos": "/onos/v1/policy/distribute"}, True),
]
OTHER = {"onos": "odl", "odl": "onos"}
REFERENCE_FPR = 4.0  # percent, synthetic corpus (Table metrics of the paper)


def wilson(k, n, z=1.96):
    """Wilson score interval for a proportion, returned in percent."""
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (100 * max(0.0, c - h), 100 * min(1.0, c + h))


def errbars(rates, cis):
    """Asymmetric error bars from Wilson intervals, clamped at zero."""
    return [[max(0.0, r - c[0]) for r, c in zip(rates, cis)],
            [max(0.0, c[1] - r) for r, c in zip(rates, cis)]]


def pick_operation(rng):
    total = sum(o[2] for o in OPERATIONS)
    x = rng.uniform(0, total)
    acc = 0
    for op in OPERATIONS:
        acc += op[2]
        if x <= acc:
            return op
    return OPERATIONS[-1]


def parse_window(text):
    a, b = text.split("-")
    a, b = int(a), int(b)
    if not (0 <= a < b <= 24):
        raise SystemExit("--utc-window must look like 8-18 (0 <= start < end <= 24)")
    return a, b


def wait_for_window(win, log=True):
    a, b = win
    while True:
        h = datetime.now(timezone.utc).hour
        if a <= h < b:
            return
        if log:
            print(f"  [window] UTC hour {h} is outside {a}-{b}, waiting...", flush=True)
            log = False
        time.sleep(30)


def send(proxy, source, urgency, op, timeout):
    name, method, _, paths, _w = op
    target = OTHER[source]
    url = proxy + paths[target]
    headers = {
        "X-Source-Controller": source,
        "X-Target-Controller": target,
        "X-Sender-PK": f"pk_{source}",
        "X-Urgency": f"{urgency:.2f}",
    }
    kwargs = {"headers": headers, "timeout": timeout}
    if method in ("PUT", "POST"):
        kwargs["json"] = {"origin": source, "op": name}
    t0 = time.perf_counter()
    try:
        r = requests.request(method, url, **kwargs)
    except Exception as exc:  # network error: not a DSAC decision
        return {"decision": "ERR", "rule": "", "status": 0,
                "lat_ms": (time.perf_counter() - t0) * 1000, "err": str(exc)[:80]}
    lat = (time.perf_counter() - t0) * 1000
    rule = ""
    decision = "PERMIT"
    if r.status_code == 403:
        try:
            body = r.json()
        except Exception:
            body = {}
        if body.get("error") == "PERMISSION_DENIED":
            decision = "DENY"
            rule = body.get("rule", "")
    return {"decision": decision, "rule": rule, "status": r.status_code,
            "lat_ms": lat, "err": ""}


def run_campaign(args):
    rng = random.Random(args.seed)
    win = parse_window(args.utc_window)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = args.outdir or os.path.join("results", f"benign_{stamp}")
    os.makedirs(outdir, exist_ok=True)
    csv_path = os.path.join(outdir, "requests.csv")

    try:
        requests.get(args.proxy + "/health", timeout=5)
    except Exception as exc:
        raise SystemExit(f"Proxy unreachable at {args.proxy}: {exc}\n"
                         "Start the infrastructure first (see instructions).")

    mean_gap = (args.hours * 3600.0 / args.requests) if args.hours > 0 else 0.0
    print(f"Campaign: {args.runs} run(s) x {args.requests} requests, "
          f"mean inter-arrival {mean_gap:.2f}s, UTC window {win[0]}-{win[1]}, "
          f"seed {args.seed}\nOutput: {outdir}\n", flush=True)

    fields = ["run", "seq", "utc_iso", "utc_hour", "source", "target", "operation",
              "method", "is_write", "urgency", "decision", "rule", "http_status",
              "lat_ms", "err"]
    with open(csv_path, "w", newline="") as fh:
        wr = csv.DictWriter(fh, fieldnames=fields)
        wr.writeheader()
        for run in range(1, args.runs + 1):
            try:
                requests.post(args.proxy + "/reset-freq", timeout=5)  # clears PIP window + Redis
            except Exception:
                pass
            sent = fp = 0
            seq = 0
            burst_left = 0
            while sent < args.requests:
                wait_for_window(win)
                source = rng.choice(["onos", "odl"])
                op = pick_operation(rng)
                if rng.random() < args.urgent_share:
                    urgency = rng.uniform(0.8, 0.95)
                else:
                    urgency = rng.uniform(0.1, 0.6)
                res = send(args.proxy, source, urgency, op, args.timeout)
                seq += 1
                now = datetime.now(timezone.utc)
                if res["decision"] != "ERR":
                    sent += 1
                    fp += res["decision"] == "DENY"
                wr.writerow({
                    "run": run, "seq": seq, "utc_iso": now.isoformat(),
                    "utc_hour": now.hour, "source": source, "target": OTHER[source],
                    "operation": op[0], "method": op[1], "is_write": int(op[4]),
                    "urgency": f"{urgency:.2f}", "decision": res["decision"],
                    "rule": res["rule"], "http_status": res["status"],
                    "lat_ms": f"{res['lat_ms']:.2f}", "err": res["err"]})
                fh.flush()
                if sent % 250 == 0 and res["decision"] != "ERR":
                    print(f"  run {run}: {sent}/{args.requests}  "
                          f"FP so far {fp} ({100*fp/sent:.2f}%)", flush=True)
                # inter-arrival: occasional short bursts, otherwise exponential gaps
                if burst_left > 0:
                    burst_left -= 1
                    time.sleep(rng.uniform(0.05, 0.3))
                elif rng.random() < args.burst_prob:
                    burst_left = rng.randint(2, 6)
                    time.sleep(rng.uniform(0.05, 0.3))
                elif mean_gap > 0:
                    time.sleep(rng.expovariate(1.0 / mean_gap))
            print(f"Run {run} done: {sent} requests, {fp} refused "
                  f"({100*fp/sent:.2f}%)\n", flush=True)
    return csv_path


# ---------------------------------------------------------------------------
# Analysis and curves
# ---------------------------------------------------------------------------
def load_rows(csv_path):
    rows = []
    with open(csv_path) as fh:
        for r in csv.DictReader(fh):
            if r["decision"] == "ERR":
                continue
            r["run"] = int(r["run"])
            r["utc_hour"] = int(r["utc_hour"])
            r["is_write"] = int(r["is_write"])
            r["lat_ms"] = float(r["lat_ms"])
            r["deny"] = r["decision"] == "DENY"
            rows.append(r)
    return rows


def analyse(csv_path):
    rows = load_rows(csv_path)
    if not rows:
        raise SystemExit("No valid request in the CSV.")
    outdir = os.path.dirname(os.path.abspath(csv_path))
    n = len(rows)
    k = sum(r["deny"] for r in rows)
    lo, hi = wilson(k, n)
    fpr = 100 * k / n

    by_run = defaultdict(lambda: [0, 0])
    by_hour = defaultdict(lambda: [0, 0])
    by_op = defaultdict(lambda: [0, 0])
    by_rule = defaultdict(int)
    by_write = defaultdict(lambda: [0, 0])
    for r in rows:
        for d, key in ((by_run, r["run"]), (by_hour, r["utc_hour"]),
                       (by_op, r["operation"]), (by_write, r["is_write"])):
            d[key][1] += 1
            d[key][0] += r["deny"]
        if r["deny"]:
            by_rule[r["rule"]] += 1

    run_rates = [100 * a / b for a, b in (by_run[x] for x in sorted(by_run))]
    lats = sorted(r["lat_ms"] for r in rows)
    pct = lambda p: lats[min(len(lats) - 1, int(p * len(lats)))]

    office = [r for r in rows if 8 <= r["utc_hour"] < 18]
    k_off = sum(r["deny"] for r in office)
    lo_o, hi_o = wilson(k_off, len(office)) if office else (0, 0)

    summary = {
        "n_requests": n, "n_refused": k, "fpr_percent": round(fpr, 3),
        "ci95_wilson_percent": [round(lo, 3), round(hi, 3)],
        "reference_synthetic_fpr_percent": REFERENCE_FPR,
        "reference_inside_ci": lo <= REFERENCE_FPR <= hi,
        "n_runs": len(by_run),
        "per_run_fpr_percent": [round(x, 3) for x in run_rates],
        "per_run_mean": round(statistics.mean(run_rates), 3),
        "per_run_std": round(statistics.stdev(run_rates), 3) if len(run_rates) > 1 else None,
        "refused_by_rule": dict(sorted(by_rule.items(), key=lambda kv: -kv[1])),
        "fpr_by_operation_percent": {o: round(100 * a / b, 2) for o, (a, b) in sorted(by_op.items())},
        "fpr_read_percent": round(100 * by_write[0][0] / by_write[0][1], 3) if by_write[0][1] else None,
        "fpr_write_percent": round(100 * by_write[1][0] / by_write[1][1], 3) if by_write[1][1] else None,
        "office_hours_utc_8_18": {"n": len(office), "refused": k_off,
                                  "fpr_percent": round(100 * k_off / len(office), 3) if office else None,
                                  "ci95": [round(lo_o, 3), round(hi_o, 3)]},
        "utc_hours_covered": sorted(by_hour),
        "client_latency_ms_end_to_end": {"p50": round(pct(0.50), 2), "p95": round(pct(0.95), 2),
                                         "p99": round(pct(0.99), 2)},
    }
    with open(os.path.join(outdir, "summary.json"), "w") as fh:
        json.dump(summary, fh, indent=2)

    if summary["reference_inside_ci"]:
        verdict = "is consistent with"
    elif fpr < REFERENCE_FPR:
        verdict = "is lower than"
    else:
        verdict = "is higher than"
    text = (f"Over {n} legitimate requests ({len(by_run)} run(s)), DSAC refused {k}, "
            f"a false-positive rate of {fpr:.2f}% (95% Wilson interval "
            f"{lo:.2f} to {hi:.2f}%). This {verdict} the {REFERENCE_FPR:.1f}% measured "
            f"on the synthetic corpus.\n")
    with open(os.path.join(outdir, "summary.txt"), "w") as fh:
        fh.write(text)
    print(json.dumps(summary, indent=2))
    print("\n" + text)
    make_plots(rows, outdir, by_hour, by_op, by_rule, by_run, fpr, lo, hi)
    print(f"Files written in {outdir}")


def make_plots(rows, outdir, by_hour, by_op, by_rule, by_run, fpr, lo, hi):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    NAVY, CYAN, RED, GREEN, GRAY = "#163664", "#0091af", "#b92323", "#196e3c", "#888888"
    plt.rcParams.update({"font.size": 10, "axes.spines.top": False,
                         "axes.spines.right": False})

    def save(fig, name):
        fig.tight_layout()
        fig.savefig(os.path.join(outdir, name), dpi=300)
        plt.close(fig)

    # 1. FPR by UTC hour
    hours = sorted(by_hour)
    rates = [100 * by_hour[h][0] / by_hour[h][1] for h in hours]
    cis = [wilson(by_hour[h][0], by_hour[h][1]) for h in hours]
    err = errbars(rates, cis)
    fig, ax = plt.subplots(figsize=(7, 3.6))
    ax.bar(hours, rates, color=CYAN, yerr=err, capsize=2, ecolor=NAVY)
    ax.axhline(REFERENCE_FPR, color=RED, ls="--", lw=1, label=f"Synthetic corpus ({REFERENCE_FPR:.1f}%)")
    for h, r in zip(hours, rates):
        ax.text(h, 0, f"n={by_hour[h][1]}", rotation=90, ha="center", va="bottom",
                fontsize=7, color="white" if r > 8 else NAVY)
    ax.set_xlabel("UTC hour of the request")
    ax.set_ylabel("False-positive rate (%)")
    ax.set_xticks(hours)
    ax.legend(frameon=False)
    save(fig, "fpr_by_hour.png")

    # 2. FPR by operation type
    ops = sorted(by_op)
    r_op = [100 * by_op[o][0] / by_op[o][1] for o in ops]
    c_op = [wilson(by_op[o][0], by_op[o][1]) for o in ops]
    e_op = errbars(r_op, c_op)
    fig, ax = plt.subplots(figsize=(7, 3.6))
    ax.barh(ops, r_op, color=NAVY, xerr=e_op, capsize=2, ecolor=GRAY)
    ax.axvline(REFERENCE_FPR, color=RED, ls="--", lw=1)
    ax.set_xlabel("False-positive rate (%)")
    save(fig, "fpr_by_operation.png")

    # 3. Convergence of the cumulative FPR
    ordered = sorted(rows, key=lambda r: (r["run"], int(r["seq"])))
    cum, xs, ys, lows, highs = 0, [], [], [], []
    step = max(1, len(ordered) // 400)
    for i, r in enumerate(ordered, 1):
        cum += r["deny"]
        if i % step == 0 or i == len(ordered):
            a, b = wilson(cum, i)
            xs.append(i); ys.append(100 * cum / i); lows.append(a); highs.append(b)
    fig, ax = plt.subplots(figsize=(7, 3.6))
    ax.plot(xs, ys, color=NAVY, lw=1.5, label="Cumulative FPR")
    ax.fill_between(xs, lows, highs, color=CYAN, alpha=0.25, label="95% Wilson interval")
    ax.axhline(REFERENCE_FPR, color=RED, ls="--", lw=1, label=f"Synthetic corpus ({REFERENCE_FPR:.1f}%)")
    ax.set_xlabel("Number of legitimate requests")
    ax.set_ylabel("False-positive rate (%)")
    ax.legend(frameon=False)
    save(fig, "fpr_convergence.png")

    # 4. Refused requests by rule
    if by_rule:
        items = sorted(by_rule.items(), key=lambda kv: kv[1])
        fig, ax = plt.subplots(figsize=(7, 3.0))
        ax.barh([i[0] for i in items], [i[1] for i in items], color=RED)
        ax.set_xlabel("Number of refused legitimate requests")
        save(fig, "refusals_by_rule.png")

    # 5. Per-run FPR (only if several runs)
    if len(by_run) > 1:
        runs = sorted(by_run)
        vals = [100 * by_run[x][0] / by_run[x][1] for x in runs]
        fig, ax = plt.subplots(figsize=(7, 3.2))
        ax.bar([str(x) for x in runs], vals, color=CYAN)
        ax.axhline(statistics.mean(vals), color=NAVY, lw=1, label="Mean")
        ax.axhline(REFERENCE_FPR, color=RED, ls="--", lw=1, label=f"Synthetic corpus ({REFERENCE_FPR:.1f}%)")
        ax.set_xlabel("Run")
        ax.set_ylabel("False-positive rate (%)")
        ax.legend(frameon=False)
        save(fig, "fpr_per_run.png")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--proxy", default="http://localhost:8000")
    ap.add_argument("--requests", type=int, default=10000, help="legitimate requests per run")
    ap.add_argument("--runs", type=int, default=1, help="independent runs (state reset between runs)")
    ap.add_argument("--hours", type=float, default=0.0,
                    help="duration of one run in hours (0 = no pause between requests)")
    ap.add_argument("--utc-window", default="0-24",
                    help="send only while the UTC hour is in [start,end), e.g. 8-18")
    ap.add_argument("--burst-prob", type=float, default=0.03,
                    help="probability that a request starts a short burst of 2 to 6 requests")
    ap.add_argument("--urgent-share", type=float, default=0.0,
                    help="share of legitimate requests with urgency in [0.8,0.95]")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--seed", type=int, default=2026)
    ap.add_argument("--outdir", default=None)
    ap.add_argument("--analyze-only", metavar="CSV", help="skip the campaign, analyse an existing requests.csv")
    args = ap.parse_args()
    csv_path = args.analyze_only or run_campaign(args)
    analyse(csv_path)


if __name__ == "__main__":
    sys.exit(main())
