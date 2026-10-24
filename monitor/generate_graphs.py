"""
DSAC — Generation des graphiques d'evaluation (bilingue FR/EN)
Rejoue le dataset UNE fois, puis produit chaque graphe en francais
(noms d'origine) et en anglais (suffixe _en).
Auteur : NECDEM Wilfried — Univ. Dschang — URIFIA — 2026
"""
import json, requests, os, random
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from collections import defaultdict
from datetime import datetime as _dt

PROXY    = "http://localhost:8000"
ENDPOINT = "/restconf/operational/network-topology:network-topology"
DATASET  = "/home/wilf/dsac/dataset/dsac_dataset_10k.json"
OUTDIR   = "/home/wilf/dsac/monitor/graphs"
os.makedirs(OUTDIR, exist_ok=True)

C_NAVY="#163664"; C_CYAN="#0091af"; C_RED="#b92323"
C_GREEN="#196e3c"; C_AMBER="#b46e00"; C_GRAY="#888888"

# ─── Textes FR (suffixe "") et EN (suffixe "_en") ────────────────
TEXTS = {
 "": {
  "cm_preds":["Autorise\n(PERMIT)","Bloque\n(DENY)"],
  "cm_labels":["Legitime\n(reel)","Attaque\n(reel)"],
  "cm_xlabel":"Prediction DSAC","cm_ylabel":"Verite terrain",
  "cm_title":"Matrice de confusion — DSAC (n={n})",
  "g2_ylabel":"Taux de detection (%)",
  "g2_title":"Taux de detection par type d'attaque East-West",
  "g2_target":"Cible 88%",
  "roc_random":"Aleatoire (AUC = 0.5)",
  "roc_xlabel":"Taux de faux positifs (FPR)",
  "roc_ylabel":"Taux de vrais positifs (TPR)",
  "roc_title":"Courbe ROC — Detection d'attaques DSAC",
  "m_labels":["Precision","Rappel","F1-score","Exactitude"],
  "m_ylabel":"Pourcentage (%)",
  "m_title":"Metriques de performance globales — DSAC",
  "cv_prec_run":"Precision par run","cv_cummean":"Moyenne cumulee",
  "cv_prec_ylabel":"Precision (%)","cv_prec_title":"Convergence de la precision",
  "cv_p99_run":"P99 par run","cv_p99_ylabel":"Latence P99 (ms)",
  "cv_p99_title":"Stabilite de la latence P99",
  "cv_suptitle":"Convergence statistique sur 50 runs (Jain, 1991)","cv_run":"Run",
 },
 "_en": {
  "cm_preds":["Permitted\n(PERMIT)","Denied\n(DENY)"],
  "cm_labels":["Legitimate\n(actual)","Attack\n(actual)"],
  "cm_xlabel":"DSAC prediction","cm_ylabel":"Ground truth",
  "cm_title":"Confusion matrix — DSAC (n={n})",
  "g2_ylabel":"Detection rate (%)",
  "g2_title":"Detection rate per East-West attack type",
  "g2_target":"Target 88%",
  "roc_random":"Random (AUC = 0.5)",
  "roc_xlabel":"False positive rate (FPR)",
  "roc_ylabel":"True positive rate (TPR)",
  "roc_title":"ROC curve — DSAC attack detection",
  "m_labels":["Precision","Recall","F1-score","Accuracy"],
  "m_ylabel":"Percentage (%)",
  "m_title":"Global performance metrics — DSAC",
  "cv_prec_run":"Precision per run","cv_cummean":"Cumulative mean",
  "cv_prec_ylabel":"Precision (%)","cv_prec_title":"Precision convergence",
  "cv_p99_run":"P99 per run","cv_p99_ylabel":"P99 latency (ms)",
  "cv_p99_title":"P99 latency stability",
  "cv_suptitle":"Statistical convergence over 50 runs (Jain, 1991)","cv_run":"Run",
 },
}

print("Chargement du dataset...")
dataset = json.load(open(DATASET))
print(f"  {len(dataset)} requetes\n")

def send(entry):
    src = entry.get("sender_id","onos-ctrl-A").split("-")[0]
    h = {
        "X-Action-Type":          entry.get("action_type","TopologyUpdateRequest"),
        "X-Source-Controller":    src,
        "X-Sender-PK":            entry.get("sender_pk","PK_valid"),
        "X-Urgency":              str(entry.get("urgency",0.3)),
        "X-Trust-Score":          str(entry.get("trust_score",0.8)),
        "X-Update-Freq":          str(entry.get("update_freq_60s",2)),
        "X-Network-Load":         str(entry.get("network_load_pct",40)),
        "X-SIEM-Alert":           str(entry.get("siem_alert",False)),
        "X-Zone":                 str(entry.get("zone","DC1")),
        "X-Has-Justifying-Event": str(entry.get("has_justifying_event",True)),
        "X-Has-Triggering-Event": str(entry.get("has_triggering_event",True)),
        "X-Elapsed-Since-Event":  str(entry.get("elapsed_since_event_s",999)),
        "X-H-Tau-Tampered":       str(entry.get("h_tau_tampered",False)),
        "X-Is-Compromised":       str(entry.get("is_compromised",False)),
        "X-Is-Critical":          str(entry.get("is_critical",False)),
        "X-Is-Readonly":          str(entry.get("is_readonly",False)),
    }
    try:
        r = requests.get(f"{PROXY}{ENDPOINT}", headers=h, timeout=10)
        verdict = "PERMIT" if r.status_code==200 else "DENY"
    except Exception:
        verdict = "DENY"
    return verdict, entry.get("score_tau", 0.5)

print("Rejeu du dataset contre DSAC (1-2 min)...")
try: requests.post(f"{PROXY}/reset-freq", timeout=3)
except Exception: pass
random.seed(42)
sample = random.sample(dataset, 2000)

y_true, y_pred, y_score, attack_types = [], [], [], []
for i, e in enumerate(sample):
    verdict, score = send(e)
    y_true.append(1 if e.get("expected_label")=="DENY" else 0)
    y_pred.append(1 if verdict=="DENY" else 0)
    y_score.append(1.0 - score)
    attack_types.append(e.get("attack_type") or "LEGITIMATE")
    if (i+1) % 200 == 0:
        print(f"  {i+1}/2000 requetes traitees...")
y_true=np.array(y_true); y_pred=np.array(y_pred); y_score=np.array(y_score)
print("Collecte terminee.\n")

# ─── Calcul des donnees (UNE fois) ───────────────────────────────
from sklearn.metrics import confusion_matrix, roc_curve, auc
cm = confusion_matrix(y_true, y_pred)
TN, FP, FN, TP = cm.ravel()
precision = TP/(TP+FP) if (TP+FP)>0 else 0
recall    = TP/(TP+FN) if (TP+FN)>0 else 0
f1        = 2*precision*recall/(precision+recall) if (precision+recall)>0 else 0
accuracy  = (TP+TN)/(TP+TN+FP+FN)
fp_rate   = FP/(FP+TN) if (FP+TN)>0 else 0
print(f"  TP={TP} TN={TN} FP={FP} FN={FN}")

atk_detect = defaultdict(lambda:[0,0])
for at, yp in zip(attack_types, y_pred):
    if at != "LEGITIMATE":
        atk_detect[at][1]+=1
        if yp==1: atk_detect[at][0]+=1
atk_names = list(atk_detect.keys())
atk_rates = [atk_detect[a][0]/atk_detect[a][1]*100 if atk_detect[a][1]>0 else 0 for a in atk_names]

fpr, tpr, _ = roc_curve(y_true, y_score)
roc_auc = auc(fpr, tpr)
m_vals = [precision*100, recall*100, f1*100, accuracy*100]

# Convergence (si csv present)
res_file = "/home/wilf/dsac/tests/resultats_50runs.csv"
has_conv = os.path.exists(res_file)
if has_conv:
    import csv as _csv
    runs, precs, p99s = [], [], []
    with open(res_file) as f:
        for row in _csv.DictReader(f):
            runs.append(int(row["run"])); precs.append(float(row["precision_pct"])); p99s.append(float(row["p99_ms"]))
    idx = np.arange(1, len(precs)+1)
    prec_cum = np.cumsum(np.array(precs,float))/idx
    p99_cum  = np.cumsum(np.array(p99s,float))/idx
    mean_p, mean_l = prec_cum[-1], p99_cum[-1]

# ─── Rendu des graphes pour chaque langue ────────────────────────
def render(suf, T):
    n = int(TP+TN+FP+FN)
    # G1 matrice
    fig, ax = plt.subplots(figsize=(7,6))
    im = ax.imshow(cm, cmap="Blues")
    ax.set_xticks([0,1]); ax.set_xticklabels(T["cm_preds"], fontsize=11)
    ax.set_yticks([0,1]); ax.set_yticklabels(T["cm_labels"], fontsize=11)
    ax.set_xlabel(T["cm_xlabel"], fontsize=12, fontweight="bold")
    ax.set_ylabel(T["cm_ylabel"], fontsize=12, fontweight="bold")
    ax.set_title(T["cm_title"].format(n=n), fontsize=14, fontweight="bold", color=C_NAVY)
    for i in range(2):
        for j in range(2):
            val=cm[i,j]; col="white" if val>cm.max()/2 else C_NAVY
            ax.text(j,i,f"{val}",ha="center",va="center",fontsize=20,fontweight="bold",color=col)
    plt.colorbar(im, ax=ax, fraction=0.046); plt.tight_layout()
    plt.savefig(f"{OUTDIR}/01_matrice_confusion{suf}.png", dpi=300); plt.close()
    # G2 detection par attaque
    fig, ax = plt.subplots(figsize=(9,5))
    colors=[C_RED,C_AMBER,C_CYAN,C_GREEN][:len(atk_names)]
    bars=ax.bar(atk_names, atk_rates, color=colors, edgecolor="black", linewidth=0.5)
    ax.set_ylabel(T["g2_ylabel"], fontsize=12, fontweight="bold")
    ax.set_title(T["g2_title"], fontsize=14, fontweight="bold", color=C_NAVY)
    ax.set_ylim(0,105); ax.axhline(y=88, color=C_GRAY, linestyle="--", label=T["g2_target"])
    for b,r in zip(bars, atk_rates):
        ax.text(b.get_x()+b.get_width()/2, b.get_height()+1, f"{r:.1f}%", ha="center", fontsize=11, fontweight="bold")
    ax.legend(); plt.xticks(rotation=15); plt.tight_layout()
    plt.savefig(f"{OUTDIR}/02_detection_par_attaque{suf}.png", dpi=300); plt.close()
    # G3 ROC
    fig, ax = plt.subplots(figsize=(7,6))
    ax.plot(fpr,tpr,color=C_CYAN,linewidth=2.5,label=f"DSAC (AUC = {roc_auc:.3f})")
    ax.plot([0,1],[0,1],color=C_GRAY,linestyle="--",label=T["roc_random"])
    ax.fill_between(fpr,tpr,alpha=0.1,color=C_CYAN)
    ax.set_xlabel(T["roc_xlabel"], fontsize=12, fontweight="bold")
    ax.set_ylabel(T["roc_ylabel"], fontsize=12, fontweight="bold")
    ax.set_title(T["roc_title"], fontsize=14, fontweight="bold", color=C_NAVY)
    ax.legend(loc="lower right", fontsize=11); ax.grid(alpha=0.3); plt.tight_layout()
    plt.savefig(f"{OUTDIR}/03_courbe_roc{suf}.png", dpi=300); plt.close()
    # G4 metriques globales
    fig, ax = plt.subplots(figsize=(8,5))
    bars=ax.bar(T["m_labels"], m_vals, color=[C_NAVY,C_CYAN,C_GREEN,C_AMBER], edgecolor="black", linewidth=0.5)
    ax.set_ylabel(T["m_ylabel"], fontsize=12, fontweight="bold")
    ax.set_title(T["m_title"], fontsize=14, fontweight="bold", color=C_NAVY)
    ax.set_ylim(0,105)
    for b,v in zip(bars, m_vals):
        ax.text(b.get_x()+b.get_width()/2, b.get_height()+1, f"{v:.1f}%", ha="center", fontsize=12, fontweight="bold")
    plt.tight_layout()
    plt.savefig(f"{OUTDIR}/04_metriques_globales{suf}.png", dpi=300); plt.close()
    # G5 convergence
    if has_conv:
        fig,(ax1,ax2)=plt.subplots(1,2,figsize=(13,5))
        ax1.plot(runs,precs,color=C_CYAN,alpha=0.30,linewidth=1,marker="o",markersize=3,label=T["cv_prec_run"])
        ax1.plot(runs,prec_cum,color=C_NAVY,linewidth=2.4,label=T["cv_cummean"])
        ax1.axhline(mean_p,color=C_RED,linestyle="--",label=f"Convergence = {mean_p:.1f}%")
        ax1.set_xlabel(T["cv_run"],fontsize=11,fontweight="bold")
        ax1.set_ylabel(T["cv_prec_ylabel"],fontsize=11,fontweight="bold")
        ax1.set_title(T["cv_prec_title"],fontsize=12,fontweight="bold",color=C_NAVY)
        ax1.legend(fontsize=9); ax1.grid(alpha=0.3)
        ax2.plot(runs,p99s,color=C_AMBER,alpha=0.30,linewidth=1,marker="s",markersize=3,label=T["cv_p99_run"])
        ax2.plot(runs,p99_cum,color=C_NAVY,linewidth=2.4,label=T["cv_cummean"])
        ax2.axhline(mean_l,color=C_RED,linestyle="--",label=f"Convergence = {mean_l:.1f}ms")
        ax2.set_xlabel(T["cv_run"],fontsize=11,fontweight="bold")
        ax2.set_ylabel(T["cv_p99_ylabel"],fontsize=11,fontweight="bold")
        ax2.set_title(T["cv_p99_title"],fontsize=12,fontweight="bold",color=C_NAVY)
        ax2.legend(fontsize=9); ax2.grid(alpha=0.3)
        plt.suptitle(T["cv_suptitle"],fontsize=14,fontweight="bold",color=C_NAVY)
        plt.tight_layout()
        plt.savefig(f"{OUTDIR}/05_convergence_50runs{suf}.png", dpi=300); plt.close()

for suf, T in TEXTS.items():
    lang = "FR" if suf=="" else "EN"
    print(f"[{lang}] generation des 5 graphes (suffixe '{suf or 'aucun'}')...")
    render(suf, T)

# ─── campaign_summary.json (independant de la langue) ────────────
_per_attack = {name: round(rate,1) for name,rate in zip(atk_names, atk_rates)}
_p99_mean=_prec_50=None
if has_conv:
    _p99_mean=round(sum(p99s)/len(p99s),1); _prec_50=round(sum(precs)/len(precs),1)
_summary = {
    "n":int(TP+TN+FP+FN),"tp":int(TP),"tn":int(TN),"fp":int(FP),"fn":int(FN),
    "precision_pct":round(precision*100,1),"detection_pct":round(recall*100,1),
    "f1_pct":round(f1*100,1),"accuracy_pct":round(accuracy*100,1),
    "fp_rate_pct":round(fp_rate*100,1),"auc":round(float(roc_auc),3),
    "per_attack":_per_attack,"p99_ms":_p99_mean,"precision_50runs_pct":_prec_50,
    "generated_at":_dt.now().isoformat(timespec="seconds"),
}
with open(os.path.expanduser("~/dsac/monitor/campaign_summary.json"),"w") as _f:
    json.dump(_summary,_f,indent=2,ensure_ascii=False)

print("\n"+"="*60)
print("GRAPHIQUES GENERES (FR sans suffixe, EN suffixe _en)")
print("="*60)
for f in sorted(os.listdir(OUTDIR)):
    if f.endswith(".png"): print(f"  - {f}")
print(f"\n  Precision {precision*100:.1f}% | Detection {recall*100:.1f}% | "
      f"FP {fp_rate*100:.1f}% | AUC {roc_auc:.3f}")
print("="*60)
