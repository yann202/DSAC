# DSAC — Contrôle d'Accès Dynamique Sémantique pour API SDN East-West
# DSAC — Dynamic Semantic Access Control for SDN East-West APIs

NECDEM Wilfried — Master 2 Réseaux et Services Distribués — URIFIA, Université de Dschang — 2026
Encadreur : Dr YANKAM Yannick Florian

---

## (FR) Présentation
Framework de contrôle d'accès pour les API East-West SDN, déployé en sidecar non-intrusif : PEP / PIP / PDP + Ledger.

## (FR) Prérequis
Ubuntu 22.04, Python 3, OpenJDK 21, Docker, Redis.

## (FR) Lancement
    ./lancer_dsac.sh
Attendre "INFRASTRUCTURE PRETE", puis dans un 2e terminal :
    ./run_tests.sh
(option 10 = évaluation complète + génération des courbes FR et EN)
Dashboard : http://localhost:8000/dashboard

## (FR) Structure
proxy/ (PEP) · pip_dsac/ (PIP) · pdp/ (PDP) · ledger/ (journal append-only)
ontology/ (sdn_ew.owl) · dataset/ · monitor/ (courbes) · tests/

---

## (EN) Overview
Access-control framework for SDN East-West APIs, deployed as a non-intrusive sidecar: PEP / PIP / PDP + Ledger.

## (EN) Requirements
Ubuntu 22.04, Python 3, OpenJDK 21, Docker, Redis.

## (EN) Run
    ./lancer_dsac.sh
Wait for "INFRASTRUCTURE PRETE", then in a 2nd terminal:
    ./run_tests.sh
(option 10 = full evaluation + FR/EN curve generation)
Dashboard: http://localhost:8000/dashboard

## (EN) Layout
proxy/ (PEP) · pip_dsac/ (PIP) · pdp/ (PDP) · ledger/ (append-only log)
ontology/ (sdn_ew.owl) · dataset/ · monitor/ (curves) · tests/
