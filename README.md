# DSAC: Dynamic Semantic Access Control for SDN East-West APIs

[![DOI](https://zenodo.org/badge/1431959374.svg)](https://doi.org/10.5281/zenodo.24080191)
License: see the file `LICENSE`.

**Authors:** Yannick Florian YANKAM and Wilfried Cabrel NECDEM TSAFACK, Université de Dschang (URIFIA), Cameroun.

This repository contains the prototype, the ontology, the synthetic corpus and the evaluation scripts of the article
"DSAC: Dynamic Semantic Access Control for SDN East-West APIs". The DOI above designates all versions of the
archive. The DOI of the version cited in the article is given on the Zenodo page.

Ce dépôt contient le prototype, l'ontologie, le corpus synthétique et les scripts d'évaluation de l'article
« DSAC : contrôle d'accès dynamique et sémantique pour les API East-West des réseaux SDN ». Le README est donné en
anglais puis en français.

---

# English

## Overview

DSAC is an access-control framework for the East-West API of distributed SDN controllers. It is deployed as a
non-intrusive sidecar made of four components: a proxy that intercepts the requests (PEP), a collector that measures
the context (PIP), a decision engine that evaluates the rules (PDP), and a hash-chained ledger. Decisions follow a
deny-overrides policy with a default deny.

## Layout

| Directory | Content |
|---|---|
| `proxy/` | enforcement point (FastAPI) |
| `pip_dsac/` | context collector (load, request frequency, time of day, trust) |
| `pdp/` | rule evaluator (`reasoner.py`) and decision logic |
| `ledger/` | append-only SQLite ledger |
| `ontology/` | `sdn_ew.owl` and the script that builds it |
| `dataset/` | synthetic corpus (10,000 requests) and its generator |
| `tests/`, `monitor/` | evaluation campaigns and figures |
| `tools/` | validation on independently generated legitimate traffic |
| `docs/` | correspondence between the article and the code |

## Requirements

* Python 3.11 or later (`python3 --version`). Older versions cannot install the pinned dependencies.
* Redis (`sudo apt install redis-server`).
* For the full demonstration only: Docker (ONOS) and OpenJDK. They are not needed to reproduce the evaluation.

Clone the repository into `~/dsac` and create an environment:

    git clone https://github.com/yann202/DSAC.git ~/dsac
    cd ~/dsac
    python3 -m venv ~/dsac-env
    source ~/dsac-env/bin/activate
    pip install -r requirements.txt

## Minimal run (no Docker, no ONOS)

Start Redis, the OpenDaylight-equivalent service and the proxy, in three terminals or in the background:

    sudo systemctl start redis-server
    python3 odl_mock.py &
    python3 -m uvicorn proxy.main:app --host 0.0.0.0 --port 8000 &
    curl http://localhost:8000/health

The health check reports ONOS as unavailable when it is not started. This does not prevent the evaluation:
requests to ONOS are still decided by DSAC, and only their forwarding fails.

## Full run

    ./lancer_dsac.sh

Wait for "INFRASTRUCTURE PRETE", then in a second terminal:

    ./run_tests.sh

Option 10 runs the full evaluation and generates the figures. The dashboard is at http://localhost:8000/dashboard.

## Validation on independently generated legitimate traffic

The script `tools/benign_campaign.py` sends legitimate requests through the proxy, without injecting any contextual
attribute (the collector measures load, frequency and time of day), and reports the false-positive rate with its
95% Wilson interval. Example used in the article (10,000 requests over seven hours of the 08:00 to 18:00 UTC window):

    python3 tools/benign_campaign.py --requests 10000 --hours 7 --utc-window 8-18 --outdir results/benign_office

Use `--hours 0` only for a quick test, since requests sent without pause exceed the global-rate threshold. Outputs:
`requests.csv`, `summary.json`, `summary.txt` and the figures of the run.

## Rules and article

The identifiers of the rules follow Table 3 of the article. `docs/RULES_MAPPING.md` gives the correspondence with the
earlier identifiers and with the SWRL rules of the ontology. Three points should be kept in mind:

* The results of the article were produced by the rule evaluator of `pdp/reasoner.py`, not by the native Pellet
  reasoner.
* Rule R3 (maintenance violation) belongs to the design but is not implemented. The ontology file contains 17 SWRL
  rules; the default-deny rule R_DEF is applied by the evaluator.
* The evaluator is the reference when the evaluator and the ontology differ on a boundary.

## Citation

    Yannick Florian Yankam and Wilfried Cabrel Necdem Tsafack. DSAC: Dynamic Semantic Access Control for SDN
    East-West APIs. Software archive, Zenodo, https://doi.org/10.5281/zenodo.24080191

---

# Français

## Présentation

DSAC est un cadre de contrôle d'accès pour l'API East-West de contrôleurs SDN distribués. Il est déployé en sidecar
non intrusif et se compose de quatre éléments : un proxy qui intercepte les requêtes (PEP), un collecteur de contexte
(PIP), un moteur de décision qui évalue les règles (PDP) et un journal chaîné par hachage. Les décisions suivent une
politique où le refus l'emporte, avec un refus par défaut.

## Prérequis

* Python 3.11 ou plus récent (`python3 --version`). Les versions plus anciennes ne peuvent pas installer les
  dépendances.
* Redis (`sudo apt install redis-server`).
* Pour la démonstration complète seulement : Docker (ONOS) et OpenJDK. Ils ne sont pas nécessaires pour reproduire
  l'évaluation.

Clonez le dépôt dans `~/dsac`, puis créez l'environnement :

    git clone https://github.com/yann202/DSAC.git ~/dsac
    cd ~/dsac
    python3 -m venv ~/dsac-env
    source ~/dsac-env/bin/activate
    pip install -r requirements.txt

## Lancement minimal (sans Docker ni ONOS)

    sudo systemctl start redis-server
    python3 odl_mock.py &
    python3 -m uvicorn proxy.main:app --host 0.0.0.0 --port 8000 &
    curl http://localhost:8000/health

Le contrôle d'état indique ONOS comme indisponible tant qu'il n'est pas démarré. L'évaluation n'en est pas affectée :
les requêtes vers ONOS sont décidées par DSAC, et seule leur transmission échoue.

## Lancement complet

    ./lancer_dsac.sh

Attendre « INFRASTRUCTURE PRETE », puis, dans un second terminal :

    ./run_tests.sh

L'option 10 lance l'évaluation complète et génère les courbes. Le tableau de bord est à l'adresse
http://localhost:8000/dashboard.

## Validation sur trafic légitime généré indépendamment

Le script `tools/benign_campaign.py` envoie des requêtes légitimes au proxy sans injecter d'attribut de contexte (le
collecteur mesure la charge, la fréquence et l'heure) et donne le taux de faux positifs avec son intervalle de Wilson à
95 %. Exemple de l'article (10 000 requêtes sur sept heures de la fenêtre 8 h à 18 h UTC) :

    python3 tools/benign_campaign.py --requests 10000 --hours 7 --utc-window 8-18 --outdir results/benign_office

N'utilisez `--hours 0` que pour un test rapide : des requêtes envoyées sans pause dépassent le seuil de fréquence
globale.

## Règles et article

Les identifiants des règles suivent la Table 3 de l'article. Le fichier `docs/RULES_MAPPING.md` donne la correspondance
avec les anciens identifiants et avec les règles SWRL de l'ontologie. Les résultats de l'article ont été produits par
l'évaluateur de règles de `pdp/reasoner.py`, et non par le raisonneur Pellet natif. La règle R3 (violation de
maintenance) fait partie de la conception mais n'est pas implémentée. L'évaluateur fait foi en cas de différence avec
l'ontologie sur une borne.
