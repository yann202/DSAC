"""
DSAC — Raisonneur semantique PDP
Charge sdn_ew.owl, evalue les 18 regles SWRL,
retourne (verdict, rule_id).

Auteur : NECDEM Wilfried — Univ. Dschang — URIFIA — 2026
"""
import os, hashlib
from owlready2 import get_ontology, sync_reasoner_pellet, destroy_entity

OWL_PATH = os.path.expanduser("~/dsac/ontology/sdn_ew.owl")

print("[REASONER] Chargement sdn_ew.owl...")
_onto = get_ontology(f"file://{OWL_PATH}").load()
print(f"[REASONER] {len(list(_onto.classes()))} classes, "
      f"{len(list(_onto.rules()))} regles SWRL chargees.")

# Constantes calibrees sur la litterature
F_NORM       = 3.0    # freq normale TopologyUpdate/min (Skowyra 2018)
LOAD_CRIT    = 85.0   # seuil charge critique % (Benamrane 2017)
TRUST_THRESH = 0.6    # seuil confiance (Li et al. 2024)
SYNC_WINDOW  = 120.0  # fenetre False Sync en secondes (Alrashede 2025a)


def _compute_score(env: dict) -> float:
    """
    S(tau) = w1*T_id + w2*T_comp + w3*T_ctx + w4*T_hist
    w1=0.30, w2=0.25, w3=0.25, w4=0.20
    Li et al. (2024) + Yan et al. (2014)
    """
    t_id = 1.0 if (env.get("signature_valid", True)
                   and not env.get("h_tau_tampered", False)) else 0.0
    if t_id == 0.0:
        return 0.0

    freq   = env.get("update_freq_60s", 1.0)
    t_comp = max(0.0, 1.0 - (freq - F_NORM) / F_NORM) if freq > F_NORM else 1.0
    if env.get("zone", "DC1") == "UNKNOWN":
        t_comp = min(t_comp, 0.2)

    h    = env.get("hour", 12)
    sc_h = 1.0 if 8 <= h <= 18 else 0.1
    load = env.get("network_load_pct", 50.0)
    sc_l = 1.0 if load < 70 else (0.5 if load < LOAD_CRIT else 0.1)
    sc_a = 0.0 if env.get("siem_alert", False) else 1.0
    t_ctx = (sc_h + sc_l + sc_a) / 3.0

    t_hist = env.get("trust_score", 0.75)
    if not env.get("has_triggering_event", True):
        t_hist = min(t_hist, 0.5)

    return round(0.30*t_id + 0.25*t_comp + 0.25*t_ctx + 0.20*t_hist, 4)


def _eval_rules(env: dict, score: float, action: str) -> tuple:
    """
    Evaluation directe des 18 regles SWRL.
    Ordre strict : Syntaxiques -> DENY -> PERMIT -> Default DENY.
    Retourne (verdict, rule_id, justification).
    """
    # ── Categorie 1 : Syntaxiques ─────────────────────────────
    if env.get("is_malformed", False):
        return "DENY", "R0", "Requete non conforme au format API East-West (NIST SP 800-53 AC-3)."

    # ── Hash tampere -> MitM ──────────────────────────────────
    if env.get("h_tau_tampered", False):
        return "DENY", "R_MITM", "H(tau) declare != H(tau) recalcule -> HashMismatchIndicator (Alrashede 2025b §4.3)."

    # ── Categorie 2 : Contextuelles DENY ─────────────────────
    if env.get("siem_alert", False):
        return "DENY", "R1", "Alerte SIEM active sur le controleur emetteur -> SIEMThreatIndicator."

    if env.get("is_compromised", False):
        return "DENY", "R6", "Controleur marque CompromisedController (incoherence Ledger detectee)."

    if env.get("trust_score", 1.0) < 0.4:
        return "DENY", "R3", f"Score de confiance {env.get('trust_score'):.3f} < seuil critique 0.4 -> UntrustedController."

    load = env.get("network_load_pct", 50.0)
    if load > LOAD_CRIT and env.get("is_critical", False):
        return "DENY", "R5", f"Charge {load}% > seuil critique {LOAD_CRIT}% + operation critique (Benamrane 2017)."

    h = env.get("hour", 12)
    if h > 22 and env.get("is_critical", False):
        return "DENY", "R11", f"Operation critique hors heures autorisees (heure={h}h > 22h)."

    if env.get("zone", "DC1") == "UNKNOWN" and env.get("update_freq_60s", 1) > 10:
        return "DENY", "R_B3", "Zone inconnue + frequence anormale > 10/min -> BehavioralSpoofingIndicator (Alrashede 2025b §4.2)."

    if env.get("update_freq_60s", 1) > 50:
        return "DENY", "R14", f"Frequence globale {env.get('update_freq_60s')}/min > 50 -> AnomalousFrequency."

    # ── Categorie 3 : Comportementales DENY ──────────────────
    # R_B1 : Topology Poisoning (Cai 2021 Marionette / Skowyra 2018)
    freq = env.get("update_freq_60s", 1.0)
    if ("topology" in action.lower()
            and freq > F_NORM
            and not env.get("has_justifying_event", True)):
        return ("DENY", "R_B1",
                f"TopologyUpdate freq={freq:.1f}/min > F_norm={F_NORM} "
                f"sans evenement reseau justificatif -> TopologyPoisoningIndicator "
                f"(Cai et al. 2021 Marionette + Skowyra 2018 IEEE DSN, fenetre 60s).")

    # R_B2 : False Synchronization (Alrashede 2025a §3.4)
    elapsed = env.get("elapsed_since_event_s", 999.0)
    if ("sync" in action.lower()
            and not env.get("has_triggering_event", True)
            and elapsed < SYNC_WINDOW):
        return ("DENY", "R_B2",
                f"SynchronizationRequest sans evenement declencheur "
                f"dans les {SYNC_WINDOW}s (elapsed={elapsed:.0f}s) "
                f"-> FalseSyncIndicator (Alrashede 2025a §3.4).")

    # ── Categorie 2 : Contextuelles PERMIT ───────────────────
    urgency = env.get("urgency", 0.3)
    trust   = env.get("trust_score", 0.75)

    if urgency >= 0.8 and trust >= 0.7:
        return "PERMIT", "R9", f"Urgence {urgency:.2f} >= 0.8 + confiance {trust:.3f} >= 0.7 -> PERMIT."

    if env.get("is_readonly", False) and trust >= 0.5:
        return "PERMIT", "R8", f"Operation lecture seule + confiance {trust:.3f} >= 0.5 -> PERMIT."

    if "policy" in action.lower() and trust >= 0.65:
        return "PERMIT", "R13", f"PolicyDistribution + confiance {trust:.3f} >= 0.65 -> PERMIT."

    if 8 <= h <= 18 and score >= TRUST_THRESH:
        return "PERMIT", "R7", f"Heure ouvrée ({h}h) + S(tau)={score:.4f} >= {TRUST_THRESH} -> PERMIT."

    # ── Default Deny ──────────────────────────────────────────
    return ("DENY", "R0_DEFAULT",
            f"Aucune regle PERMIT satisfaite. S(tau)={score:.4f} < seuil={TRUST_THRESH}. Default Deny applique.")


def _eval_with_pellet(env: dict, action: str, onto) -> tuple:
    """
    Instancie tau dans l'ontologie OWL et invoque Pellet.
    Retourne (verdict, rule_id, justif) ou (None, None, None) si echec.
    """
    uid = hashlib.md5(action.encode()).hexdigest()[:8]
    req  = None
    ctrl = None
    ctx  = None

    try:
        with onto:
            # Choisir la sous-classe EWRequest selon l'action
            op = action.lower()
            if "topology" in op:
                req = onto.TopologyUpdateRequest(f"req_{uid}")
            elif "sync"   in op:
                req = onto.SynchronizationRequest(f"req_{uid}")
            elif "policy" in op:
                req = onto.PolicyDistributionRequest(f"req_{uid}")
            else:
                req = onto.FlowRuleModificationRequest(f"req_{uid}")

            ctrl = onto.SDNController(f"ctrl_{uid}")
            ctx  = onto.SecurityContext(f"ctx_{uid}")

            # Assigner les proprietes de donnees
            ctrl.hasTrustScore        = [env.get("trust_score", 0.75)]
            ctrl.requestFrequency     = [float(env.get("update_freq_60s", 1))]
            ctrl.hasSIEMAlert         = [env.get("siem_alert", False)]
            ctrl.isInUnknownZone      = [env.get("zone", "DC1") == "UNKNOWN"]
            ctrl.isCompromised        = [env.get("is_compromised", False)]

            req.hasHour               = [int(env.get("hour", 12))]
            req.hasUrgencyLevel       = [float(env.get("urgency", 0.3))]
            req.isMalformed           = [env.get("is_malformed", False)]
            req.isCriticalOperation   = [env.get("is_critical", False)]
            req.isReadOnlyOperation   = [env.get("is_readonly", False)]
            req.hTauTampered          = [env.get("h_tau_tampered", False)]
            req.elapsedSinceLastEvent = [float(env.get("elapsed_since_event_s", 999))]
            req.issuedBy              = [ctrl]

            ctx.networkLoad = [float(env.get("network_load_pct", 50))]
            req.hasContext  = [ctx]

            if "topology" in op and hasattr(req, "hasNoJustifyingEvent"):
                req.hasNoJustifyingEvent = [not env.get("has_justifying_event", True)]
            if "sync" in op and hasattr(req, "hasNoTriggeringEvent"):
                req.hasNoTriggeringEvent = [not env.get("has_triggering_event", True)]

            # Invoquer Pellet
            sync_reasoner_pellet(
                ontology=onto,
                infer_property_values=True,
                debug=0
            )

            # Lire les classes inferees
            ctrl_types = [type(ctrl).__name__] + \
                         [c.__name__ for c in type(ctrl).__mro__
                          if c.__name__ != "object"]
            req_types  = [type(req).__name__] + \
                         [c.__name__ for c in type(req).__mro__
                          if c.__name__ != "object"]

            # Anomalies detectees
            anomaly_map = {
                "TopologyPoisoningIndicator": "R_B1",
                "FalseSyncIndicator":         "R_B2",
                "BehavioralSpoofingIndicator":"R_B3",
                "HashMismatchIndicator":      "R_MITM",
                "SIEMThreatIndicator":        "R1",
                "AnomalousFrequency":         "R14",
                "MaintenanceViolation":       "R4",
            }
            for anom, rule_id in anomaly_map.items():
                if anom in req_types:
                    return ("DENY", f"PELLET:{rule_id}:{anom}",
                            f"Pellet a infere {anom} via {rule_id}.")

            if "CompromisedController" in ctrl_types:
                return ("DENY", "PELLET:R6:CompromisedController",
                        "Pellet a infere CompromisedController.")

            if "UntrustedController" in ctrl_types:
                return ("DENY", "PELLET:R3/R10:UntrustedController",
                        "Pellet a infere UntrustedController.")

            if "TrustedController" in ctrl_types:
                return ("PERMIT", "PELLET:R7/R8/R9:TrustedController",
                        "Pellet a infere TrustedController.")

            return None, None, None

    except Exception as e:
        print(f"[REASONER][PELLET] Erreur : {e}")
        return None, None, None

    finally:
        # Nettoyer les individus temporaires
        try:
            if req:  destroy_entity(req)
            if ctrl: destroy_entity(ctrl)
            if ctx:  destroy_entity(ctx)
        except Exception:
            pass


def run_inference(tuple_abac: dict) -> tuple:
    """
    Point d'entree principal.
    1. Calcul S(tau)
    2. Tentative Pellet sur OWL
    3. Fallback : evaluation directe des 18 regles
    Retourne (verdict, rule_id)
    """
    env    = tuple_abac.get("environment", {})
    action = tuple_abac.get("action", "")
    score  = _compute_score(env)

    print(f"[REASONER] S(tau)={score:.4f} | action={action[:40]}")

    # Tentative Pellet
    verdict, rule, justif = _eval_with_pellet(env, action, _onto)

    if verdict is None:
        print("[REASONER] Pellet indecis -> evaluation directe")
        verdict, rule, justif = _eval_rules(env, score, action)

    print(f"[REASONER] -> {verdict} ({rule})")
    print(f"[REASONER]    {justif[:80]}")
    return verdict, rule
