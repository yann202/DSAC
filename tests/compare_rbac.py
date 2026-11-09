"""
DSAC — Comparaison RBAC statique vs DSAC semantique
Fait tourner les deux modeles sur le meme dataset et compare.
Prouve que le RBAC laisse passer les attaques que DSAC bloque.

Reference : modele RBAC natif des controleurs SDN (ONOS/ODL)
Auteur : NECDEM Wilfried — Univ. Dschang — URIFIA — 2026
"""
import json, requests, random, time
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import os
from collections import defaultdict

PROXY    = "http://localhost:8000"
ENDPOINT = "/restconf/operational/network-topology:network-topology"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET  = os.path.join(ROOT, "dataset", "dsac_dataset_10k.json")
OUTDIR   = os.path.join(ROOT, "monitor", "graphs")
os.makedirs(OUTDIR, exist_ok=True)

C_NAVY="#163664"; C_CYAN="#0091af"; C_RED="#b92323"; C_GREEN="#196e3c"

random.seed(42)
dataset = json.load(open(DATASET))
sample  = random.sample(dataset, 2000)
print(f"Echantillon : {len(sample)} requetes\n")

# ════════════════════════════════════════════════════════════════
# MODELE RBAC STATIQUE (comme ONOS/ODL natif)
# ════════════════════════════════════════════════════════════════
# Le RBAC ne verifie QUE :
#   - l'identite (cle/signature presente)
#   - le role (controleur autorise dans la liste blanche)
# Il IGNORE : heure, charge, frequence, integrite H(tau), comportement

ROLES_AUTORISES = {
    "onos": ["TopologyUpdateRequest", "SynchronizationRequest",
             "FlowRuleModificationRequest", "PolicyDistributionRequest"],
    "odl":  ["TopologyUpdateRequest", "SynchronizationRequest",
             "FlowRuleModificationRequest", "PolicyDistributionRequest"],
}

def rbac_decision(entry):
    """
    RBAC statique : autorise si l'identite et le role sont valides.
    Ne regarde NI le contexte, NI l'integrite, NI le comportement.
    """
    src    = entry.get("sender_id","onos-ctrl-A").split("-")[0]
    action = entry.get("action_type","TopologyUpdateRequest")
    sig_valid = entry.get("signature_valid", True)

    # RBAC : signature valide + role autorise => PERMIT
    if sig_valid and action in ROLES_AUTORISES.get(src, []):
        return "PERMIT"
    return "DENY"

# ════════════════════════════════════════════════════════════════
# MODELE DSAC (via le proxy reel)
# ════════════════════════════════════════════════════════════════
def dsac_decision(entry):
    src = entry.get("sender_id","onos-ctrl-A").split("-")[0]
    h = {
        "X-Action-Type":          entry.get("action_type","TopologyUpdateRequest"),
        "X-Source-Controller":    src,
        "X-Trust-Score":          str(entry.get("trust_score",0.8)),
        "X-Update-Freq":          str(entry.get("update_freq_60s",2)),
        "X-Network-Load":         str(entry.get("network_load_pct",40)),
        "X-Zone":                 str(entry.get("zone","DC1")),
        "X-Has-Justifying-Event": str(entry.get("has_justifying_event",True)),
        "X-Has-Triggering-Event": str(entry.get("has_triggering_event",True)),
        "X-Elapsed-Since-Event":  str(entry.get("elapsed_since_event_s",999)),
        "X-H-Tau-Tampered":       str(entry.get("h_tau_tampered",False)),
        "X-Is-Critical":          str(entry.get("is_critical",False)),
        "X-Is-Readonly":          str(entry.get("is_readonly",False)),
    }
    try:
        r = requests.get(f"{PROXY}{ENDPOINT}", headers=h, timeout=10)
        return "PERMIT" if r.status_code==200 else "DENY"
    except Exception:
        return "DENY"

# ════════════════════════════════════════════════════════════════
# EVALUATION DES DEUX MODELES
# ════════════════════════════════════════════════════════════════
def evaluate(name, decision_fn, use_proxy=False):
    print(f"Evaluation : {name}...")
    if use_proxy:
        requests.post(f"{PROXY}/reset-freq", timeout=3)
    correct = 0; total = 0
    tp = fp = fn = tn = 0
    # Detection par type d'attaque
    atk = defaultdict(lambda:[0,0])

    for e in sample:
        verdict   = decision_fn(e)
        expected  = e.get("expected_label","PERMIT")
        is_attack = expected=="DENY"
        pred_atk  = verdict=="DENY"
        at = e.get("attack_type")

        if is_attack and pred_atk:       tp += 1
        elif is_attack and not pred_atk: fn += 1
        elif not is_attack and pred_atk: fp += 1
        else:                            tn += 1

        if at:
            atk[at][1] += 1
            if pred_atk: atk[at][0] += 1

        if verdict==expected: correct += 1
        total += 1

    precision = correct/total*100
    detection = tp/(tp+fn)*100 if (tp+fn)>0 else 0
    fp_rate   = fp/(fp+tn)*100 if (fp+tn)>0 else 0
    print(f"   Exactitude={precision:.1f}% Detection={detection:.1f}% FP={fp_rate:.1f}%")
    return {"precision":precision,"detection":detection,
            "fp_rate":fp_rate,"atk":dict(atk)}

res_rbac = evaluate("RBAC statique", rbac_decision, use_proxy=False)
print()
res_dsac = evaluate("DSAC semantique", dsac_decision, use_proxy=True)

# ════════════════════════════════════════════════════════════════
# GRAPHIQUE 1 — Comparaison globale
# ════════════════════════════════════════════════════════════════
print("\nGeneration des graphiques...")
metrics = ["Exactitude","Detection","Faux positifs"]
rbac_v  = [res_rbac["precision"],res_rbac["detection"],res_rbac["fp_rate"]]
dsac_v  = [res_dsac["precision"],res_dsac["detection"],res_dsac["fp_rate"]]

x = np.arange(len(metrics)); width=0.35
fig, ax = plt.subplots(figsize=(10,6))
b1 = ax.bar(x-width/2, rbac_v, width, label="RBAC statique", color=C_RED)
b2 = ax.bar(x+width/2, dsac_v, width, label="DSAC semantique", color=C_GREEN)
ax.set_ylabel("Pourcentage (%)",fontsize=12,fontweight="bold")
ax.set_title("RBAC statique vs DSAC semantique (n=2000)",
             fontsize=14,fontweight="bold",color=C_NAVY)
ax.set_xticks(x); ax.set_xticklabels(metrics,fontsize=11)
ax.legend(fontsize=12); ax.grid(alpha=0.3,axis="y"); ax.set_ylim(0,105)
for bars in [b1,b2]:
    for bar in bars:
        h=bar.get_height()
        ax.text(bar.get_x()+bar.get_width()/2,h+1,f"{h:.1f}",
                ha="center",fontsize=10,fontweight="bold")
plt.tight_layout()
plt.savefig(f"{OUTDIR}/07_rbac_vs_dsac.png",dpi=300)
plt.close()

# ════════════════════════════════════════════════════════════════
# GRAPHIQUE 2 — Detection par attaque (RBAC vs DSAC)
# ════════════════════════════════════════════════════════════════
atk_types = ["SPOOFING","MITM","TOPOLOGY_POISONING","FALSE_SYNC"]
rbac_det = []
dsac_det = []
for at in atk_types:
    r = res_rbac["atk"].get(at,[0,1])
    d = res_dsac["atk"].get(at,[0,1])
    rbac_det.append(r[0]/r[1]*100 if r[1]>0 else 0)
    dsac_det.append(d[0]/d[1]*100 if d[1]>0 else 0)

x = np.arange(len(atk_types)); width=0.35
fig, ax = plt.subplots(figsize=(11,6))
b1 = ax.bar(x-width/2, rbac_det, width, label="RBAC statique", color=C_RED)
b2 = ax.bar(x+width/2, dsac_det, width, label="DSAC semantique", color=C_GREEN)
ax.set_ylabel("Taux de detection (%)",fontsize=12,fontweight="bold")
ax.set_title("Detection par type d'attaque : RBAC vs DSAC",
             fontsize=14,fontweight="bold",color=C_NAVY)
ax.set_xticks(x)
ax.set_xticklabels(["Spoofing","MitM","Topology\nPoisoning","False\nSync"],
                   fontsize=10)
ax.legend(fontsize=12); ax.grid(alpha=0.3,axis="y"); ax.set_ylim(0,105)
for bars in [b1,b2]:
    for bar in bars:
        h=bar.get_height()
        ax.text(bar.get_x()+bar.get_width()/2,h+1,f"{h:.0f}%",
                ha="center",fontsize=9,fontweight="bold")
plt.tight_layout()
plt.savefig(f"{OUTDIR}/08_detection_rbac_vs_dsac.png",dpi=300)
plt.close()

# ─── Synthese ─────────────────────────────────────────────────────
print("\n"+"="*64)
print("COMPARAISON RBAC vs DSAC — SYNTHESE")
print("="*64)
print(f"{'Metrique':<20}{'RBAC':>12}{'DSAC':>12}{'Gain':>14}")
print("-"*64)
print(f"{'Exactitude':<20}{res_rbac['precision']:>11.1f}%"
      f"{res_dsac['precision']:>11.1f}%"
      f"{res_dsac['precision']-res_rbac['precision']:>+12.1f}pts")
print(f"{'Detection':<20}{res_rbac['detection']:>11.1f}%"
      f"{res_dsac['detection']:>11.1f}%"
      f"{res_dsac['detection']-res_rbac['detection']:>+12.1f}pts")
print(f"{'Faux positifs':<20}{res_rbac['fp_rate']:>11.1f}%"
      f"{res_dsac['fp_rate']:>11.1f}%"
      f"{res_dsac['fp_rate']-res_rbac['fp_rate']:>+12.1f}pts")
print("="*64)
print("\nDETECTION PAR ATTAQUE :")
for at,r,d in zip(atk_types,rbac_det,dsac_det):
    print(f"  {at:<22} RBAC {r:>5.0f}%  ->  DSAC {d:>5.0f}%")
print("\nGraphiques :")
print(f"  - {OUTDIR}/07_rbac_vs_dsac.png")
print(f"  - {OUTDIR}/08_detection_rbac_vs_dsac.png")
print("\nCONCLUSION : le RBAC laisse passer les attaques utilisant")
print("des identites valides (MitM, Spoofing). DSAC les detecte grace")
print("a l'analyse contextuelle et semantique.")
