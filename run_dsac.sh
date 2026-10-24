#!/bin/bash
# ============================================================
# DSAC — Script de lancement unifie
# Demarre tous les services dans un seul terminal
# Auteur : NECDEM Wilfried — Univ. Dschang — URIFIA — 2026
# ============================================================

# Couleurs
VERT='\033[0;32m'
ROUGE='\033[0;31m'
BLEU='\033[0;34m'
JAUNE='\033[1;33m'
NC='\033[0m'

DSAC_DIR="$HOME/dsac"
KARAF_DIR="$HOME/Téléchargements/karaf-0.22.2"
export PATH="$HOME/.local/bin:$PATH"

# Fichiers de log
mkdir -p "$DSAC_DIR/logs"
ODL_LOG="$DSAC_DIR/logs/odl_mock.log"
PROXY_LOG="$DSAC_DIR/logs/proxy.log"

# Tableau des PID pour le nettoyage
PIDS=()

# ── Fonction de nettoyage a l'arret (Ctrl+C) ───────────────
cleanup() {
    echo ""
    echo -e "${JAUNE}[DSAC] Arret des services...${NC}"
    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null
            echo -e "${JAUNE}[DSAC]   PID $pid arrete${NC}"
        fi
    done
    # Tuer les processus residuels
    pkill -f "odl_mock.py" 2>/dev/null
    pkill -f "uvicorn proxy.main" 2>/dev/null
    echo -e "${VERT}[DSAC] Tous les services arretes proprement.${NC}"
    exit 0
}
trap cleanup SIGINT SIGTERM

clear
echo -e "${BLEU}============================================================${NC}"
echo -e "${BLEU}   DSAC — Dynamic Semantic Access Control${NC}"
echo -e "${BLEU}   Lancement de l'infrastructure complete${NC}"
echo -e "${BLEU}============================================================${NC}"
echo ""

# ── ETAPE 1 : Redis ────────────────────────────────────────
echo -e "${BLEU}[1/5] Verification de Redis...${NC}"
if redis-cli ping >/dev/null 2>&1; then
    echo -e "${VERT}      Redis deja actif (PONG)${NC}"
else
    echo -e "${JAUNE}      Demarrage de Redis...${NC}"
    sudo systemctl start redis-server 2>/dev/null || redis-server --daemonize yes
    sleep 2
    if redis-cli ping >/dev/null 2>&1; then
        echo -e "${VERT}      Redis demarre${NC}"
    else
        echo -e "${ROUGE}      ECHEC Redis — verifie l'installation${NC}"
    fi
fi
# Vider le cache pour repartir propre
redis-cli flushdb >/dev/null 2>&1
echo ""

# ── ETAPE 2 : ONOS (Docker) ────────────────────────────────
echo -e "${BLEU}[2/5] Demarrage de ONOS (Docker)...${NC}"
if docker ps | grep -q onos; then
    echo -e "${VERT}      ONOS deja en cours${NC}"
else
    docker start onos >/dev/null 2>&1
    echo -e "${JAUNE}      ONOS demarre, attente de l'API REST...${NC}"
fi
# Attendre que l'API ONOS reponde (max 90s)
for i in $(seq 1 18); do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
        -u onos:rocks http://localhost:8181/onos/v1/devices 2>/dev/null)
    if [ "$STATUS" = "200" ]; then
        echo -e "${VERT}      ONOS pret (HTTP 200) apres $((i*5))s${NC}"
        break
    fi
    sleep 5
done
if [ "$STATUS" != "200" ]; then
    echo -e "${JAUNE}      ONOS lent a demarrer — on continue quand meme${NC}"
fi
echo ""

# ── ETAPE 3 : ODL Mock ─────────────────────────────────────
echo -e "${BLEU}[3/5] Demarrage du simulateur ODL (port 8182)...${NC}"
cd "$DSAC_DIR"
python3 odl_mock.py > "$ODL_LOG" 2>&1 &
ODL_PID=$!
PIDS+=($ODL_PID)
sleep 3
if curl -s http://localhost:8182/health >/dev/null 2>&1; then
    echo -e "${VERT}      ODL Mock pret (PID $ODL_PID)${NC}"
else
    echo -e "${ROUGE}      ECHEC ODL Mock — voir $ODL_LOG${NC}"
fi
echo ""

# ── ETAPE 4 : Proxy DSAC (PEP) ─────────────────────────────
echo -e "${BLEU}[4/5] Demarrage du Proxy DSAC PEP (port 8000)...${NC}"
cd "$DSAC_DIR"
python3 -m uvicorn proxy.main:app \
    --host 0.0.0.0 --port 8000 > "$PROXY_LOG" 2>&1 &
PROXY_PID=$!
PIDS+=($PROXY_PID)
echo -e "${JAUNE}      Chargement de l'ontologie + Pellet...${NC}"
sleep 6
if curl -s http://localhost:8000/health >/dev/null 2>&1; then
    echo -e "${VERT}      Proxy DSAC pret (PID $PROXY_PID)${NC}"
else
    echo -e "${ROUGE}      ECHEC Proxy — voir $PROXY_LOG${NC}"
    tail -5 "$PROXY_LOG"
fi
echo ""

# ── ETAPE 5 : Verification finale ──────────────────────────
echo -e "${BLEU}[5/5] Verification de l'infrastructure...${NC}"
HEALTH=$(curl -s http://localhost:8000/health 2>/dev/null)
echo "$HEALTH" | python3 -m json.tool 2>/dev/null || echo "$HEALTH"
echo ""

echo -e "${VERT}============================================================${NC}"
echo -e "${VERT}   DSAC OPERATIONNEL${NC}"
echo -e "${VERT}============================================================${NC}"
echo -e "   Redis      : ${VERT}actif${NC} (port 6379)"
echo -e "   ONOS       : ${VERT}Ctrl A${NC}   (port 8181)"
echo -e "   ODL Mock   : ${VERT}Ctrl B${NC}   (port 8182)  PID $ODL_PID"
echo -e "   Proxy PEP  : ${VERT}DSAC${NC}     (port 8000)  PID $PROXY_PID"
echo ""
echo -e "${JAUNE}   Endpoints utiles :${NC}"
echo -e "     Health    : curl http://localhost:8000/health"
echo -e "     Ledger    : curl http://localhost:8000/ledger"
echo -e "     Metriques : curl http://localhost:8000/metrics/live"
echo ""
echo -e "${JAUNE}   Logs en direct :${NC}"
echo -e "     Proxy : tail -f $PROXY_LOG"
echo -e "     ODL   : tail -f $ODL_LOG"
echo ""
echo -e "${JAUNE}   Tests disponibles :${NC}"
echo -e "     Campagne 50 runs : python3 tests/test_dsac.py"
echo -e "     Demo MitM        : python3 demo_mitm.py"
echo ""
echo -e "${ROUGE}   >>> Appuie sur Ctrl+C pour tout arreter proprement <<<${NC}"
echo -e "${BLEU}============================================================${NC}"
echo ""

# ── Affichage des logs du proxy en direct ──────────────────
echo -e "${BLEU}[LOGS PROXY EN DIRECT]${NC}"
tail -f "$PROXY_LOG" &
TAIL_PID=$!
PIDS+=($TAIL_PID)

# Attendre indefiniment (jusqu'a Ctrl+C)
wait $PROXY_PID
