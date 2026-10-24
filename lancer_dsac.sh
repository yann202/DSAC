#!/bin/bash
V='\033[0;32m'; R='\033[0;31m'; J='\033[1;33m'; B='\033[0;34m'; N='\033[0m'
PROJET="$(cd "$(dirname "$0")" && pwd)"
echo -e "${B}=== DSAC — Lanceur ===${N}\n   Projet : $PROJET\n"
echo -e "${B}[1] Prerequis...${N}"; manque=0
check(){ if command -v "$1" >/dev/null 2>&1; then echo -e "   ${V}OK${N}  $2";
  else echo -e "   ${R}ABSENT${N}  $2 — $3"; manque=1; fi; }
check python3 "Python 3"       "sudo apt install python3 python3-venv"
check java    "Java (OpenJDK)" "sudo apt install openjdk-21-jre"
check docker  "Docker"         "https://docs.docker.com/engine/install/ubuntu/"
check redis-cli "Redis"        "sudo apt install redis-server"
[ "$manque" = "1" ] && { echo -e "\n${R}Installe les prerequis puis relance.${N}"; exit 1; }
docker info >/dev/null 2>&1 || { echo -e "${R}Docker non demarre : sudo systemctl start docker${N}"; exit 1; }
if [ "$PROJET" != "/home/wilf/dsac" ] && [ ! -e /home/wilf/dsac ]; then
  echo -e "${J}[2] Lien /home/wilf/dsac -> projet (sudo)...${N}"
  sudo mkdir -p /home/wilf && sudo ln -s "$PROJET" /home/wilf/dsac && echo -e "   ${V}OK${N}"
fi
echo -e "${B}[3] Environnement Python...${N}"; cd "$PROJET"
[ -d "$HOME/dsac-env" ] || python3 -m venv "$HOME/dsac-env"
source "$HOME/dsac-env/bin/activate"; pip install -q --upgrade pip
[ -f requirements.txt ] && pip install -q -r requirements.txt && echo -e "   ${V}OK${N}" || echo -e "   ${J}requirements.txt absent ou partiel${N}"
chmod +x "$PROJET"/*.sh 2>/dev/null
echo -e "\n${J}Quand 'INFRASTRUCTURE PRETE' s'affiche, 2e terminal : cd \"$PROJET\" && ./run_tests.sh${N}\n"
exec "$PROJET/start_infra.sh"
