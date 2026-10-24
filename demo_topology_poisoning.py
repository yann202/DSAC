"""
DSAC — Demonstration Topology Poisoning (attaque Marionette)
Injection de fausses TopologyUpdate pour manipuler le routage.
Reference : Cai et al. (2021) Marionette + Skowyra (2018) IEEE DSN
Auteur : NECDEM Wilfried — Univ. Dschang — URIFIA — 2026
"""
import requests, time

PROXY = "http://localhost:8000"
ENDPOINT = "/restconf/operational/network-topology:network-topology"
V='\033[92m'; R='\033[91m'; J='\033[93m'; B='\033[94m'; N='\033[0m'; G='\033[1m'
def pause(s=1.5): time.sleep(s)

print(f"\n{B}{'='*64}{N}")
print(f"{B}{G}   DEMONSTRATION — TOPOLOGY POISONING (Marionette){N}")
print(f"{B}{G}   Detection sequentielle R_B1 (fenetre 60s){N}")
print(f"{B}{'='*64}{N}\n")
pause()

print(f"{G}[PHASE 1] L'attaque Marionette (Cai et al., 2021){N}\n")
pause()
print(f"   {R}Principe : l'attaquant injecte de fausses mises a jour{N}")
print(f"   {R}de topologie pour manipuler les tables de routage des{N}")
print(f"   {R}controleurs SDN distants et detourner le trafic.{N}\n")
print(f"   {J}Signature de l'attaque :{N}")
print(f"   - Type : TopologyUpdateRequest")
print(f"   - Frequence : {R}15 updates/min{N} (normal = 3/min)")
print(f"   - Evenement reseau justificatif : {R}AUCUN{N}")
print(f"   - Heure : 10h (discret, pendant l'activite normale)\n")
pause(2)

print(f"{B}{'─'*64}{N}")
print(f"{B}{G}[PHASE 2] Simulation d'une rafale de TopologyUpdate{N}")
print(f"{B}{'─'*64}{N}\n")
pause()

# Simuler quelques updates legitimes d'abord
print(f"   {V}Updates legitimes (freq normale, avec evenement) :{N}")
for i in range(3):
    r = requests.get(f"{PROXY}{ENDPOINT}", headers={
        "X-Action-Type":      "TopologyUpdateRequest",
        "X-Source-Controller":"onos",
        "X-Trust-Score":      "0.80",
        "X-Update-Freq":      "2",
        "X-Has-Justifying-Event": "true",
    }, timeout=5)
    st = "PERMIT" if r.status_code==200 else "DENY"
    print(f"     Update {i+1} (freq=2, evenement=oui) -> {V}{st}{N}")
    time.sleep(0.3)

print(f"\n   {R}Rafale d'injection Marionette (freq anormale, sans evenement) :{N}")
t0 = time.perf_counter()
resp = requests.get(f"{PROXY}{ENDPOINT}", headers={
    "X-Action-Type":      "TopologyUpdateRequest",
    "X-Source-Controller":"onos",
    "X-Trust-Score":      "0.80",
    "X-Update-Freq":      "15",
    "X-Has-Justifying-Event": "false",
}, timeout=5)
lat = (time.perf_counter() - t0) * 1000
st = "PERMIT" if resp.status_code==200 else "DENY"
col = R if st=="DENY" else V
print(f"     Injection (freq=15, evenement=NON) -> {col}{G}{st}{N}\n")
pause(2)

print(f"{B}{'─'*64}{N}")
print(f"{B}{G}[PHASE 3] REACTION DE DSAC{N}")
print(f"{B}{'─'*64}{N}\n")

if resp.status_code == 403:
    body = resp.json()
    print(f"   {R}{G}>>> TOPOLOGY POISONING DETECTE ET BLOQUE <<<{N}\n")
    print(f"   Code HTTP        : {R}{resp.status_code} Forbidden{N}")
    print(f"   Verdict          : {R}{G}{body.get('verdict')}{N}")
    print(f"   Regle declenchee : {R}{G}{body.get('rule')}{N}")
    print(f"   Latence          : {V}{lat:.2f} ms{N}")
    print(f"\n   {J}Mecanisme de detection :{N}")
    print(f"   1. Frequence 15/min > F_norm = 3/min (Skowyra 2018)")
    print(f"   2. Aucun evenement reseau ne justifie ces updates")
    print(f"   3. Regle R_B1 => TopologyPoisoningIndicator")
    print(f"   4. DENY : la fausse topologie est rejetee")
else:
    print(f"   {R}Status {resp.status_code} - non bloque{N}")

print(f"\n{B}{'='*64}{N}")
print(f"{G}CONCLUSION{N}")
print(f"{B}{'='*64}{N}")
print(f"""
   {V}Ce que DSAC apporte :{N}
   - Detection SEQUENTIELLE : analyse la frequence sur 60s
   - Correlation avec les evenements reseau reels
   - Une rafale sans justification = signature d'empoisonnement

   {J}References : Cai et al. (2021) Marionette{N}
   {J}             Skowyra et al. (2018) IEEE DSN (fenetre 60s){N}
""")
print(f"{B}{'='*64}{N}\n")
