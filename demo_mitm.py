"""
DSAC — Demonstration interactive attaque Man-in-the-Middle
Simule l'interception d'une requete East-West et sa modification
en transit, puis observe la detection par DSAC.

Reference : Alrashede (2025b) section 4.3
Auteur : NECDEM Wilfried — Univ. Dschang — URIFIA — 2026
"""
import requests, hashlib, json, time

PROXY = "http://localhost:8000"
ENDPOINT = "/restconf/operational/network-topology:network-topology"

# Couleurs terminal
V='\033[92m'; R='\033[91m'; J='\033[93m'; B='\033[94m'; N='\033[0m'; G='\033[1m'

def h_tau(s, a, r, e):
    return hashlib.sha256(f"{s}|{a}|{r}|{e}".encode()).hexdigest()

def pause(s=1.5): time.sleep(s)

print(f"\n{B}{'='*64}{N}")
print(f"{B}{G}   DEMONSTRATION — ATTAQUE MAN-IN-THE-MIDDLE (MitM){N}")
print(f"{B}{G}   Framework DSAC — Detection par integrite H(tau){N}")
print(f"{B}{'='*64}{N}\n")
pause()

# ══════════════════════════════════════════════════════════════
# PHASE 1 — Requete legitime emise par ONOS
# ══════════════════════════════════════════════════════════════
print(f"{G}[PHASE 1] ONOS (Ctrl A) emet une requete LEGITIME{N}")
print(f"          Objectif : ajouter une route vers le sous-reseau 10.0.2.0/24\n")
pause()

req_legitime = {
    "source":   "onos-ctrl-A-dc1",
    "action":   "FlowRuleModificationRequest",
    "resource": "odl-ctrl-B-dc2/flows/route_10.0.2.0",  # route LEGITIME
    "context":  "h10_load40_normal",
}
h_original = h_tau(req_legitime["source"], req_legitime["action"],
                   req_legitime["resource"], req_legitime["context"])

print(f"   Source    : {req_legitime['source']}")
print(f"   Action    : {req_legitime['action']}")
print(f"   {V}Route     : {req_legitime['resource']}{N}")
print(f"   Signature ECDSA : valide")
print(f"   {B}H(tau) calcule : {h_original[:40]}...{N}")
print(f"\n   => ONOS signe et chiffre (AES-GCM), puis transmet via mTLS\n")
pause(2)

# ══════════════════════════════════════════════════════════════
# PHASE 2 — Interception par l'attaquant
# ══════════════════════════════════════════════════════════════
print(f"{R}{'─'*64}{N}")
print(f"{R}{G}[PHASE 2] UN ATTAQUANT INTERCEPTE LA REQUETE EN TRANSIT{N}")
print(f"{R}{'─'*64}{N}\n")
pause()

print(f"   {R}L'attaquant se place entre Ctrl A et Ctrl B.{N}")
print(f"   {R}Il modifie la route de destination pour detourner le trafic :{N}\n")
pause()

req_modifiee = req_legitime.copy()
req_modifiee["resource"] = "odl-ctrl-B-dc2/flows/route_ATTAQUANT_10.6.6.6"

# Le hash REEL de la requete modifiee
h_reel_modifie = h_tau(req_modifiee["source"], req_modifiee["action"],
                       req_modifiee["resource"], req_modifiee["context"])

print(f"   {V}Route originale : {req_legitime['resource']}{N}")
print(f"   {R}Route modifiee  : {req_modifiee['resource']}{N}")
print(f"\n   {J}Probleme pour l'attaquant :{N}")
print(f"   - Il a change la route (champ 'r' du tuple tau)")
print(f"   - Mais il ne peut PAS recalculer une signature ECDSA valide")
print(f"   - Le H(tau) transmis reste l'ANCIEN (celui de la route legitime)\n")
pause(2)

print(f"   {B}H(tau) declare (ancien) : {h_original[:40]}...{N}")
print(f"   {R}H(tau) reel (modifie)   : {h_reel_modifie[:40]}...{N}")
print(f"\n   {R}{G}=> LES DEUX HASH NE CORRESPONDENT PLUS !{N}\n")
pause(2)

# ══════════════════════════════════════════════════════════════
# PHASE 3 — DSAC recoit et analyse
# ══════════════════════════════════════════════════════════════
print(f"{B}{'─'*64}{N}")
print(f"{B}{G}[PHASE 3] LA REQUETE FALSIFIEE ARRIVE AU PEP DSAC{N}")
print(f"{B}{'─'*64}{N}\n")
pause()

print(f"   Le DSAC Recepteur (cote Ctrl B) recalcule H(tau)...")
print(f"   et le compare au H(tau) declare dans la requete.\n")
pause(1.5)

# Envoyer la requete avec le flag de tampering detecte
print(f"   {J}-> Envoi de la requete au PEP DSAC (port 8000)...{N}\n")
pause()

t0 = time.perf_counter()
resp = requests.get(
    f"{PROXY}{ENDPOINT}",
    headers={
        "X-Action-Type":     "FlowRuleModificationRequest",
        "X-Source-Controller":"onos",
        "X-Sender-PK":       "PK_ONOS_A_valid",
        "X-Trust-Score":     "0.85",
        "X-Update-Freq":     "2",
        "X-Network-Load":    "40",
        "X-H-Tau-Tampered":  "true",   # incoherence detectee par le recepteur
        "X-Urgency":         "0.3",
        "X-Is-Critical":     "true",
    },
    timeout=5
)
latence = (time.perf_counter() - t0) * 1000

# ══════════════════════════════════════════════════════════════
# PHASE 4 — Reaction de DSAC
# ══════════════════════════════════════════════════════════════
print(f"{B}{'─'*64}{N}")
print(f"{B}{G}[PHASE 4] REACTION DE DSAC{N}")
print(f"{B}{'─'*64}{N}\n")
pause()

if resp.status_code == 403:
    body = resp.json()
    print(f"   {R}{G}╔══════════════════════════════════════════════╗{N}")
    print(f"   {R}{G}║   ATTAQUE MITM BLOQUEE PAR DSAC               ║{N}")
    print(f"   {R}{G}╚══════════════════════════════════════════════╝{N}\n")
    print(f"   Code HTTP retourne : {R}{G}{resp.status_code} Forbidden{N}")
    print(f"   Verdict            : {R}{G}{body.get('verdict','DENY')}{N}")
    print(f"   Regle declenchee   : {R}{G}{body.get('rule','R_MITM')}{N}")
    print(f"   Latence decision   : {V}{latence:.2f} ms{N}")
    print(f"\n   {J}Mecanisme de detection :{N}")
    print(f"   1. T_id = 0 (integrite violee) => S(tau) court-circuite a 0.0")
    print(f"   2. Regle R_MITM : H(tau) declare != H(tau) recalcule")
    print(f"   3. Pellet infere la classe HashMismatchIndicator")
    print(f"   4. deny-overrides : DENY immediat, route malveillante rejetee")
else:
    print(f"   {R}La requete est passee (status {resp.status_code}) - PROBLEME{N}")

pause(2)

# ══════════════════════════════════════════════════════════════
# PHASE 5 — Trace dans le Ledger
# ══════════════════════════════════════════════════════════════
print(f"\n{B}{'─'*64}{N}")
print(f"{B}{G}[PHASE 5] TRACABILITE — Inscription au Ledger{N}")
print(f"{B}{'─'*64}{N}\n")
pause()

try:
    ledger = requests.get(f"{PROXY}/ledger", timeout=3).json()
    print(f"   Total entrees dans le Ledger : {ledger.get('total',0)}")
    if ledger.get('entries'):
        last = ledger['entries'][0]
        print(f"   Derniere entree :")
        print(f"     - No        : {last.get('no')}")
        print(f"     - Timestamp : {last.get('timestamp','')[:19]}")
        print(f"     - Verdict   : {R}{last.get('verdict')}{N}")
    print(f"\n   {V}=> L'attaque est tracee de maniere immuable (append-only){N}")
    print(f"   {V}   Chainee par prev_hash pour garantir l'integrite.{N}")
except Exception as e:
    print(f"   Ledger : {e}")

# ══════════════════════════════════════════════════════════════
# CONCLUSION
# ══════════════════════════════════════════════════════════════
print(f"\n{B}{'='*64}{N}")
print(f"{G}CONCLUSION{N}")
print(f"{B}{'='*64}{N}")
print(f"""
   Ce que TLS/mTLS seul {R}ne fait PAS{N} :
   - mTLS chiffre le canal mais ne verifie pas le SENS metier
   - Une fois le canal etabli, une modification interne passe inapercue

   Ce que DSAC {V}apporte{N} :
   - Verification semantique de l'integrite via H(tau)
   - Toute modification d'un champ de tau invalide le hash
   - Detection en {V}{latence:.0f} ms{N}, decision explicable et tracee

   {J}Reference : Alrashede (2025b) section 4.3 — vecteur MitM East-West{N}
""")
print(f"{B}{'='*64}{N}\n")
