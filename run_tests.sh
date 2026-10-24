#!/bin/bash
# DSAC — TERMINAL 2 : Tests + Graphes
V='\033[0;32m'; R='\033[0;31m'; B='\033[0;34m'; J='\033[1;33m'; C='\033[0;36m'; N='\033[0m'
DSAC="$HOME/dsac"; export PATH="$HOME/.local/bin:$PATH"; cd "$DSAC"
source ~/dsac-env/bin/activate 2>/dev/null
if ! curl -s -o /dev/null http://localhost:8000/health 2>/dev/null; then
  echo -e "${R}[ERREUR] Infra absente. Lance ./start_infra.sh (attends PRETE).${N}"; exit 1; fi
menu(){ clear
  echo -e "${B}=== DSAC — TESTS & GRAPHES (Terminal 2) ===${N}"
  echo -e "${C} EVALUATION :${N}"
  echo -e "   1) Campagne 50 runs   2) Matrice+ROC+summary   3) Ablation"
  echo -e "   4) RBAC vs DSAC       5) Fuzzing"
  echo -e "${C} DEMOS ATTAQUES :${N}"
  echo -e "   6) MitM  7) Spoofing  8) Topology Poisoning  9) False Sync"
  echo -e "${C} GROUPES :${N}"
  echo -e "  10) TOUT l'eval (1->5) + graphes   11) Toutes les demos   0) Quitter"
  echo -ne "${J} Choix : ${N}"; }
run(){ case $1 in
  1) python3 tests/test_dsac.py;; 2) python3 monitor/generate_graphs.py;;
  3) python3 tests/ablation_study.py;; 4) python3 tests/compare_rbac.py;;
  5) python3 tests/fuzzing_test.py;; 6) python3 demo_mitm.py;;
  7) python3 demo_spoofing.py;; 8) python3 demo_topology_poisoning.py;;
  9) python3 demo_false_sync.py;; esac; }
while true; do menu; read choix; case $choix in
  1|2|3|4|5|6|7|8|9) run $choix;;
  10) echo -e "${V}>>> Evaluation complete${N}"
      python3 tests/test_dsac.py; python3 monitor/generate_graphs.py
      python3 tests/ablation_study.py; python3 tests/compare_rbac.py; python3 tests/fuzzing_test.py
      echo -e "${V}>>> Graphes: eog monitor/graphs/${N}";;
  11) for d in mitm spoofing topology_poisoning false_sync; do python3 demo_$d.py; echo; done;;
  0) exit 0;; *) echo -e "${R}Invalide${N}";; esac
  echo ""; echo -ne "${J}Entree pour le menu...${N}"; read; done
