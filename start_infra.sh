#!/bin/bash
# DSAC — TERMINAL 1 : Redis + ONOS + ODL mock + Proxy PEP + Dashboard
V='\033[0;32m'; R='\033[0;31m'; B='\033[0;34m'; J='\033[1;33m'; N='\033[0m'
DSAC="$HOME/dsac"; export PATH="$HOME/.local/bin:$PATH"; mkdir -p "$DSAC/logs"; PIDS=()
cleanup(){ echo -e "\n${J}[INFRA] Arret...${N}"; for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
  pkill -f "odl_mock.py" 2>/dev/null; pkill -f "uvicorn proxy.main" 2>/dev/null
  echo -e "${V}[INFRA] Arrete.${N}"; exit 0; }
trap cleanup SIGINT SIGTERM
clear
echo -e "${B}=== DSAC — INFRASTRUCTURE (Terminal 1) ===${N}\n"

echo -e "${B}[1/4] Redis...${N}"
if redis-cli ping >/dev/null 2>&1; then echo -e "${V}      actif${N}"
else sudo systemctl start redis-server 2>/dev/null || redis-server --daemonize yes; sleep 2
  redis-cli ping >/dev/null 2>&1 && echo -e "${V}      demarre${N}" || echo -e "${R}      ECHEC${N}"; fi
redis-cli flushdb >/dev/null 2>&1

echo -e "${B}[2/4] ONOS (Docker, 8181)...${N}"
if docker ps --format '{{.Names}}' | grep -q '^onos$'; then echo -e "${V}      deja en cours${N}"
elif docker ps -a --format '{{.Names}}' | grep -q '^onos$'; then docker start onos >/dev/null 2>&1
else echo -e "${J}      creation conteneur...${N}"; docker run -d --name onos -p 8181:8181 -p 6653:6653 onosproject/onos:2.7-latest >/dev/null 2>&1; fi
for i in $(seq 1 24); do ST=$(curl -s -o /dev/null -w "%{http_code}" -u onos:rocks http://localhost:8181/onos/v1/devices 2>/dev/null)
  [ "$ST" = "200" ] && { echo -e "${V}      pret${N}"; break; }; sleep 5; done
[ "$ST" != "200" ] && echo -e "${J}      lent, on continue${N}"

echo -e "${B}[3/4] ODL Mock (8182)...${N}"; cd "$DSAC"
python3 odl_mock.py > "$DSAC/logs/odl.log" 2>&1 & PIDS+=($!); sleep 3
curl -s http://localhost:8182/health >/dev/null 2>&1 && echo -e "${V}      pret${N}" || echo -e "${R}      ECHEC (logs/odl.log)${N}"

echo -e "${B}[4/4] Proxy PEP (8000)...${N}"
python3 -m uvicorn proxy.main:app --host 0.0.0.0 --port 8000 > "$DSAC/logs/proxy.log" 2>&1 & PIDS+=($!)
echo -e "${J}      chargement ontologie + Pellet...${N}"
for i in $(seq 1 30); do curl -s -o /dev/null http://localhost:8000/health 2>/dev/null && break; sleep 1; done
curl -s -o /dev/null http://localhost:8000/health 2>/dev/null && echo -e "${V}      pret${N}" \
  || { echo -e "${R}      ECHEC${N}"; tail -8 "$DSAC/logs/proxy.log"; }

echo -e "\n${V}=== INFRASTRUCTURE PRETE ===${N}"
xdg-open http://localhost:8000/dashboard >/dev/null 2>&1 &
echo -e "${J}   Dashboard : http://localhost:8000/dashboard${N}"
echo -e "${J}   2e terminal : ./run_tests.sh${N}"
echo -e "${R}   Ctrl+C ici pour tout arreter${N}\n"
echo -e "${B}[Logs proxy]${N}"
tail -f "$DSAC/logs/proxy.log"
