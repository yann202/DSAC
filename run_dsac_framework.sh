#!/bin/bash

# ==============================================================================
#  PROJECT: DSAC Framework (Dynamic Security Access Control)
#  ROLE: Automated Multi-Component Deployment Orchestrator
#  ACADEMIC LEVEL: Master 2 - Software Defined Networks (SDN) & Security
# ==============================================================================

PROJ_DIR="$HOME/dsac"
ENV_ACTIVATE="$HOME/dsac-env/bin/activate"
KARAF_BIN="$HOME/Téléchargements/karaf-0.22.2/bin/karaf"

GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}====================================================================${NC}"
echo -e "${BLUE}    INITIALISATION DU FRAMEWORK DSAC - DÉPLOIEMENT AUTOMATIQUE      ${NC}"
echo -e "${BLUE}====================================================================${NC}"

# 1. PHASE DE NETTOYAGE
echo -e "\n${YELLOW}[1/6] Nettoyage de l'environnement précédent...${NC}"
sudo mn -c > /dev/null 2>&1
[ -f "$PROJ_DIR/monitor/dsac_metrics.csv" ] && rm -f "$PROJ_DIR/monitor/dsac_metrics.csv"
redis-cli FLUSHALL > /dev/null 2>&1
pkill -f "uvicorn proxy.main:app" > /dev/null 2>&1
pkill -f "live_monitor.py" > /dev/null 2>&1
echo -e "${GREEN}[✔] Environnement propre.${NC}"

# 2. ACTIVATION DE L'ENVIRONNEMENT PYTHON
echo -e "\n${YELLOW}[2/6] Activation de l'environnement virtuel...${NC}"
if [ -f "$ENV_ACTIVATE" ]; then
    source "$ENV_ACTIVATE"
    export PYTHONPATH=$PYTHONPATH:$PROJ_DIR
    echo -e "${GREEN}[✔] Environnement Python (dsac-env) activé.${NC}"
else
    echo -e "${RED}[✘] Erreur : Impossible de trouver l'environnement à l'adresse $ENV_ACTIVATE${NC}"
    exit 1
fi

# 3. LANCEMENT DES CONTRÔLEURS SDN (OpenDaylight & ONOS)
echo -e "\n${YELLOW}[3/6] Lancement du plan de contrôle hétérogène (East-West)...${NC}"
if [ -f "$KARAF_BIN" ]; then
    $KARAF_BIN server > /dev/null 2>&1 &
    ODL_PID=$!
    echo -e "${GREEN}[✔] OpenDaylight (ODL) démarré localement (PID: $ODL_PID) sur le port 6633.${NC}"
else
    echo -e "${RED}[✘] Erreur : Impossible de trouver Karaf dans $KARAF_BIN${NC}"
    exit 1
fi

if [ $(docker ps -q -f name=onos-m2) ]; then
    echo -e "${GREEN}[✔] Conteneur Docker ONOS déjà actif sur le port 6653.${NC}"
else
    echo "-> Démarrage du conteneur Docker ONOS..."
    docker start onos-m2 > /dev/null 2>&1
    echo -e "${GREEN}[✔] ONOS actif via Docker sur le port 6653.${NC}"
fi
echo "-> Temporisation de 12s pour l'initialisation des contrôleurs..."
sleep 12

# 4. LANCEMENT DU PROXY PEP
echo -e "\n${YELLOW}[4/6] Démarrage du Proxy PEP (FastAPI)...${NC}"
cd "$PROJ_DIR"
uvicorn proxy.main:app --host 0.0.0.0 --port 8000 --reload > proxy.log 2>&1 &
PROXY_PID=$!
echo -e "${GREEN}[✔] Proxy PEP actif sur le port 8000 (PID: $PROXY_PID).${NC}"

# 5. LANCEMENT DE L'INTERFACE DE MONITORING
echo -e "\n${YELLOW}[5/6] Initialisation du Dashboard Live...${NC}"
python3 monitor/live_monitor.py > monitor.log 2>&1 &
MONITOR_PID=$!
echo -e "${GREEN}[✔] Dashboard en écoute active (PID: $MONITOR_PID).${NC}"
sleep 2

# 6. DÉPLOIEMENT MININET
echo -e "\n${YELLOW}[6/6] Préparation du plan de données (Mininet) et de l'attaque...${NC}"
echo -e "${BLUE}--------------------------------------------------------------------${NC}"
echo -e "${YELLOW}Dès que le prompt 'mininet>' apparaît :${NC}"
echo -e "${GREEN}Ouvre un AUTRE terminal et lance le test avec :${NC}"
echo -e "   source ~/dsac-env/bin/activate && cd ~/dsac && python3 tests/test_dsac.py"${NC}
echo -e "${BLUE}--------------------------------------------------------------------${NC}"
sudo python3 topologie.py

# GESTION DE LA FERMETURE STRUCTURÉE
echo -e "\n${RED}Fermeture détectée. Arrêt sécurisé de tous les composants DSAC...${NC}"
kill $ODL_PID $PROXY_PID $MONITOR_PID > /dev/null 2>&1
docker stop onos-m2 > /dev/null 2>&1
sudo mn -c > /dev/null 2>&1
echo -e "${GREEN}[✔] Tous les processus ont été nettoyés avec succès. À bientôt !${NC}"
