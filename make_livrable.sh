#!/bin/bash
DSAC="$HOME/dsac"; OUT="$DSAC/livrable_encadreur"; VENV="$HOME/dsac-env"
echo ">>> Preparation du livrable encadreur..."

# 1. Nettoyage des fichiers parasites
rm -f "$DSAC/0" "$DSAC/0.6" "$DSAC/text_monitor.pyQ" 2>/dev/null
find "$DSAC" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null

# 2. Dossier livrable
rm -rf "$OUT"; mkdir -p "$OUT/scripts_courbes"

# 3. Scripts de generation des courbes (copie ceux qui existent)
for f in monitor/generate_graphs.py monitor/metrics.py \
         tests/test_dsac.py tests/ablation_study.py \
         tests/compare_rbac.py tests/fuzzing_test.py \
         dataset/generate_dataset.py ; do
  if [ -f "$DSAC/$f" ]; then cp "$DSAC/$f" "$OUT/scripts_courbes/"; echo "   + $f"; fi
done

# 4. requirements.txt depuis le venv
if [ -x "$VENV/bin/pip" ]; then
  "$VENV/bin/pip" freeze > "$OUT/requirements.txt"
  echo "   + requirements.txt ($(wc -l < "$OUT/requirements.txt") paquets)"
fi

# 5. README bilingue FR / EN
cat > "$OUT/README.md" << 'MDEOF'
# DSAC — Controle d'Acces Dynamique Semantique / Dynamic Semantic Access Control

## (FR) Presentation
Framework de controle d'acces pour les API East-West SDN, deploye en sidecar
non-intrusif : PEP / PIP / PDP + Ledger.

## (FR) Prerequis
Ubuntu 22.04, Python 3.14, OpenJDK 21, Docker, Redis, ONOS 2.7 (Docker).
Installation : pip install -r requirements.txt

## (FR) Lancement (2 terminaux)
Terminal 1 : ./start_infra.sh   (Redis + ONOS + ODL mock + proxy PEP + dashboard)
Terminal 2 : ./run_tests.sh     (menu : tests, evaluation, demos, courbes)
Dashboard  : http://localhost:8000/dashboard

## (FR) Generation des courbes (dossier scripts_courbes/)
- generate_graphs.py : matrice de confusion, courbe ROC, detection par attaque, metriques, convergence
- ablation_study.py  : etude d'ablation
- compare_rbac.py    : comparaison RBAC vs DSAC
- fuzzing_test.py    : robustesse au fuzzing
- test_dsac.py       : campagne 50 runs

## (FR) Structure
proxy/ (PEP) · pip_dsac/ (PIP) · pdp/ (PDP) · ledger/ (journal append-only)
ontology/ (sdn_ew.owl) · dataset/ · monitor/ (courbes) · tests/

---

## (EN) Overview
Access-control framework for SDN East-West APIs, deployed as a non-intrusive
sidecar: PEP / PIP / PDP + Ledger.

## (EN) Requirements
Ubuntu 22.04, Python 3.14, OpenJDK 21, Docker, Redis, ONOS 2.7 (Docker).
Install: pip install -r requirements.txt

## (EN) Run (2 terminals)
Terminal 1: ./start_infra.sh   (Redis + ONOS + ODL mock + PEP proxy + dashboard)
Terminal 2: ./run_tests.sh     (menu: tests, evaluation, demos, curves)
Dashboard : http://localhost:8000/dashboard

## (EN) Curve generation (folder scripts_courbes/)
- generate_graphs.py : confusion matrix, ROC curve, per-attack detection, metrics, convergence
- ablation_study.py  : ablation study
- compare_rbac.py    : RBAC vs DSAC comparison
- fuzzing_test.py    : fuzzing robustness
- test_dsac.py       : 50-run campaign

## (EN) Layout
proxy/ (PEP) · pip_dsac/ (PIP) · pdp/ (PDP) · ledger/ (append-only log)
ontology/ (sdn_ew.owl) · dataset/ · monitor/ (curves) · tests/
MDEOF
echo "   + README.md (FR/EN)"

# 6. Archive complete du projet (le paquet lancable = "executable")
cd "$HOME"
tar --exclude='dsac/livrable_encadreur' --exclude='__pycache__' \
    --exclude='*.pyc' --exclude='*.log' \
    -czf "$OUT/dsac_complet.tar.gz" dsac
echo ">>> Archive : $OUT/dsac_complet.tar.gz"
ls -lh "$OUT/dsac_complet.tar.gz"
echo ">>> Termine. Dossier a remettre : $OUT"
