"""
DSAC — Demonstration attaque Spoofing (usurpation d'identite)
Cle ECDSA valide (copiee) mais comportement anormal.
Reference : Alrashede (2025b) section 4.2
Auteur : NECDEM Wilfried — Univ. Dschang — URIFIA — 2026
"""
import requests, time

PROXY = "http://localhost:8000"
ENDPOINT = "/restconf/operational/network-topology:network-topology"
V='\033[92m'; R='\033[91m'; J='\033[93m'; B='\033[94m'; N='\033[0m'; G='\033[1m'
def pause(s=1.5): time.sleep(s)

print(f"\n{B}{'='*64}{N}")
print(f"{B}{G}   DEMONSTRATION — ATTAQUE SPOOFING (usurpation){N}")
print(f"{B}{G}   Detection comportementale R_B3{N}")
print(f"{B}{'='*64}{N}\n")
pause()

print(f"{G}[PHASE 1] Un attaquant a VOLE la cle ECDSA de Ctrl A{N}\n")
pause()
print(f"   {R}L'attaquant possede une cle ECDSA techniquement VALIDE.{N}")
print(f"   {R}La verification cryptographique classique le laisserait passer.{N}\n")
print(f"   {J}Mais son comportement trahit l'usurpation :{N}")
print(f"   - Zone geographique : {R}UNKNOWN{N} (jamais vue dans le Ledger)")
print(f"   - Frequence requetes : {R}20/min{N} (anormalement elevee)")
print(f"   - Heure : {R}2h du matin{N} (hors activite normale)")
print(f"   - Score de confiance historique : {R}0.45{N} (degrade)\n")
pause(2)

print(f"{B}{'─'*64}{N}")
print(f"{B}{G}[PHASE 2] DSAC analyse au-dela de la cryptographie{N}")
print(f"{B}{'─'*64}{N}\n")
pause()
print(f"   {J}-> Envoi de la requete au PEP DSAC...{N}\n")

t0 = time.perf_counter()
resp = requests.get(f"{PROXY}{ENDPOINT}", headers={
    "X-Action-Type":      "FlowRuleModificationRequest",
    "X-Source-Controller":"onos",
    "X-Sender-PK":        "PK_ONOS_A_valid",   # cle VOLEE mais valide
    "X-Trust-Score":      "0.45",
    "X-Zone":             "UNKNOWN",
    "X-Update-Freq":      "20",
    "X-Urgency":          "0.2",
}, timeout=5)
lat = (time.perf_counter() - t0) * 1000

print(f"{B}{'─'*64}{N}")
print(f"{B}{G}[PHASE 3] REACTION DE DSAC{N}")
print(f"{B}{'─'*64}{N}\n")
pause()

if resp.status_code == 403:
    body = resp.json()
    print(f"   {R}{G}>>> SPOOFING DETECTE ET BLOQUE <<<{N}\n")
    print(f"   Code HTTP        : {R}{resp.status_code} Forbidden{N}")
    print(f"   Verdict          : {R}{G}{body.get('verdict')}{N}")
    print(f"   Regle declenchee : {R}{G}{body.get('rule')}{N}")
    print(f"   Latence          : {V}{lat:.2f} ms{N}")
    print(f"\n   {J}Mecanisme de detection :{N}")
    print(f"   1. La cle ECDSA est valide => T_id passe")
    print(f"   2. MAIS zone UNKNOWN + frequence 20/min > seuil 10")
    print(f"   3. Regle R_B3 => BehavioralSpoofingIndicator")
    print(f"   4. T_comp s'effondre => S(tau) < 0.6 => DENY")
else:
    print(f"   {R}Status {resp.status_code} - non bloque{N}")

print(f"\n{B}{'='*64}{N}")
print(f"{G}CONCLUSION{N}")
print(f"{B}{'='*64}{N}")
print(f"""
   {R}Ce qu'une defense cryptographique seule rate :{N}
   - La cle volee est valide => signature acceptee
   - L'attaquant passe la verification ECDSA classique

   {V}Ce que DSAC apporte :{N}
   - Analyse COMPORTEMENTALE au-dela de la cle
   - Zone + frequence + historique = profil de l'usurpateur
   - Detection meme avec une cle techniquement valide

   {J}Reference : Alrashede (2025b) section 4.2{N}
""")
print(f"{B}{'='*64}{N}\n")
