"""
DSAC — Demonstration False Synchronization
SyncRequest sans evenement declencheur dans la fenetre de 120s.
Reference : Alrashede (2025a) section 3.4 — State Exhaustion
Auteur : NECDEM Wilfried — Univ. Dschang — URIFIA — 2026
"""
import requests, time

PROXY = "http://localhost:8000"
ENDPOINT = "/restconf/operational/network-topology:network-topology"
V='\033[92m'; R='\033[91m'; J='\033[93m'; B='\033[94m'; N='\033[0m'; G='\033[1m'
def pause(s=1.5): time.sleep(s)

print(f"\n{B}{'='*64}{N}")
print(f"{B}{G}   DEMONSTRATION — FALSE SYNCHRONIZATION{N}")
print(f"{B}{G}   Detection sequentielle R_B2 (fenetre 120s){N}")
print(f"{B}{'='*64}{N}\n")
pause()

print(f"{G}[PHASE 1] L'attaque par fausse synchronisation{N}\n")
pause()
print(f"   {R}Principe : l'attaquant envoie des demandes de synchro{N}")
print(f"   {R}d'etat repetees pour saturer les controleurs (State{N}")
print(f"   {R}Exhaustion) et provoquer un deni de service.{N}\n")
print(f"   {J}Difference legitime vs malveillant :{N}")
print(f"   - Une SyncRequest LEGITIME suit un evenement reseau")
print(f"     (failover, perte de lien, montee en charge)")
print(f"   - Une SyncRequest MALVEILLANTE arrive {R}sans aucun{N}")
print(f"     {R}evenement declencheur{N} dans les 120 dernieres secondes\n")
pause(2)

print(f"{B}{'─'*64}{N}")
print(f"{B}{G}[PHASE 2] Comparaison Sync legitime vs malveillante{N}")
print(f"{B}{'─'*64}{N}\n")
pause()

# Sync legitime (avec evenement declencheur)
print(f"   {V}Sync LEGITIME (suite a un failover reel) :{N}")
r1 = requests.get(f"{PROXY}{ENDPOINT}", headers={
    "X-Action-Type":      "SynchronizationRequest",
    "X-Source-Controller":"odl",
    "X-Trust-Score":      "0.78",
    "X-Has-Triggering-Event": "true",
    "X-Elapsed-Since-Event":  "5",
}, timeout=5)
st1 = "PERMIT" if r1.status_code==200 else "DENY"
print(f"     evenement=oui, elapsed=5s -> {V}{st1}{N}\n")
pause()

# Sync malveillante (sans evenement)
print(f"   {R}Sync MALVEILLANTE (aucun evenement reseau) :{N}")
t0 = time.perf_counter()
resp = requests.get(f"{PROXY}{ENDPOINT}", headers={
    "X-Action-Type":      "SynchronizationRequest",
    "X-Source-Controller":"odl",
    "X-Trust-Score":      "0.75",
    "X-Has-Triggering-Event": "false",
    "X-Elapsed-Since-Event":  "45",
}, timeout=5)
lat = (time.perf_counter() - t0) * 1000
st = "PERMIT" if resp.status_code==200 else "DENY"
col = R if st=="DENY" else V
print(f"     evenement=NON, elapsed=45s -> {col}{G}{st}{N}\n")
pause(2)

print(f"{B}{'─'*64}{N}")
print(f"{B}{G}[PHASE 3] REACTION DE DSAC{N}")
print(f"{B}{'─'*64}{N}\n")

if resp.status_code == 403:
    body = resp.json()
    print(f"   {R}{G}>>> FALSE SYNC DETECTE ET BLOQUE <<<{N}\n")
    print(f"   Code HTTP        : {R}{resp.status_code} Forbidden{N}")
    print(f"   Verdict          : {R}{G}{body.get('verdict')}{N}")
    print(f"   Regle declenchee : {R}{G}{body.get('rule')}{N}")
    print(f"   Latence          : {V}{lat:.2f} ms{N}")
    print(f"\n   {J}Mecanisme de detection :{N}")
    print(f"   1. SyncRequest detectee")
    print(f"   2. Aucun evenement declencheur (has_triggering_event=false)")
    print(f"   3. elapsed=45s < fenetre 120s (Alrashede 2025a)")
    print(f"   4. Regle R_B2 => FalseSyncIndicator => DENY")
else:
    print(f"   {R}Status {resp.status_code} - non bloque{N}")

print(f"\n{B}{'='*64}{N}")
print(f"{G}CONCLUSION{N}")
print(f"{B}{'='*64}{N}")
print(f"""
   {V}Ce que DSAC apporte :{N}
   - Correlation temporelle : une synchro doit suivre un evenement
   - Detection de la saturation d'etat (State Exhaustion)
   - Premier systeme a couvrir ce vecteur par regle OWL-SWRL

   {J}Reference : Alrashede (2025a) section 3.4{N}
""")
print(f"{B}{'='*64}{N}\n")
