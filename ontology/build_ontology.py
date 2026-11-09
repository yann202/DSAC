import os
from owlready2 import (
    get_ontology, Thing, ObjectProperty, DataProperty,
    FunctionalProperty, Imp
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OWL_PATH = os.path.join(BASE_DIR, "sdn_ew.owl")
OWL_IRI  = "http://www.urifia.univ-dschang.cm/dsac/sdn_ew.owl"

onto = get_ontology(OWL_IRI)

with onto:
    # MODULE 1 : ACTEURS
    class SDNController(Thing): pass
    class TrustedController(SDNController): pass
    class UntrustedController(SDNController): pass
    class CompromisedController(SDNController): pass

    # MODULE 2 : MESSAGES
    class EWRequest(Thing): pass
    class TopologyUpdateRequest(EWRequest): pass
    class SynchronizationRequest(EWRequest): pass
    class FlowRuleModificationRequest(EWRequest): pass
    class PolicyDistributionRequest(EWRequest): pass

    # MODULE 3 : CONTEXTE
    class SecurityContext(Thing): pass
    class LegitimeSyncWindow(Thing): pass

    # MODULE 4 : ANOMALIES (inférées par Pellet)
    class DetectedAnomaly(Thing): pass
    class TopologyPoisoningIndicator(DetectedAnomaly): pass
    class FalseSyncIndicator(DetectedAnomaly): pass
    class BehavioralSpoofingIndicator(DetectedAnomaly): pass
    class HashMismatchIndicator(DetectedAnomaly): pass
    class SIEMThreatIndicator(DetectedAnomaly): pass
    class AnomalousFrequency(DetectedAnomaly): pass
    class MaintenanceViolation(DetectedAnomaly): pass

    # MODULE 5 : DECISIONS
    class AccessDecision(Thing): pass

    # PROPRIETES D'OBJET (13)
    class issuedBy(ObjectProperty):
        domain = [EWRequest]; range = [SDNController]
    class targetedAt(ObjectProperty):
        domain = [EWRequest]; range = [SDNController]
    class hasContext(ObjectProperty):
        domain = [EWRequest]; range = [SecurityContext]
    class triggersAnomaly(ObjectProperty):
        domain = [EWRequest]; range = [DetectedAnomaly]
    class producesDecision(ObjectProperty):
        domain = [EWRequest]; range = [AccessDecision]
    class locatedIn(ObjectProperty):
        domain = [SDNController]
    class hasPolicy(ObjectProperty):
        domain = [SDNController]
    class causedBy(ObjectProperty):
        domain = [AccessDecision]; range = [DetectedAnomaly]
    class hasTriggeringRule(ObjectProperty):
        domain = [DetectedAnomaly]
    class affectsService(ObjectProperty):
        domain = [EWRequest]
    class monitoredBy(ObjectProperty):
        domain = [SDNController]
    class hasJustifyingWindow(ObjectProperty):
        domain = [SynchronizationRequest]; range = [LegitimeSyncWindow]
    class operatesIn(ObjectProperty):
        domain = [SDNController]

    # PROPRIETES DE DONNEES (16)
    class hasTrustScore(DataProperty, FunctionalProperty):
        domain = [SDNController]; range = [float]
    class requestFrequency(DataProperty, FunctionalProperty):
        domain = [SDNController]; range = [float]
    class networkLoad(DataProperty, FunctionalProperty):
        domain = [SecurityContext]; range = [float]
    class hasSIEMAlert(DataProperty, FunctionalProperty):
        domain = [SDNController]; range = [bool]
    class requestTimestamp(DataProperty, FunctionalProperty):
        domain = [EWRequest]; range = [str]
    class hasHour(DataProperty, FunctionalProperty):
        domain = [EWRequest]; range = [int]
    class hasUrgencyLevel(DataProperty, FunctionalProperty):
        domain = [EWRequest]; range = [float]
    class hasNoJustifyingEvent(DataProperty, FunctionalProperty):
        domain = [TopologyUpdateRequest]; range = [bool]
    class hasNoTriggeringEvent(DataProperty, FunctionalProperty):
        domain = [SynchronizationRequest]; range = [bool]
    class elapsedSinceLastEvent(DataProperty, FunctionalProperty):
        domain = [EWRequest]; range = [float]
    class isInUnknownZone(DataProperty, FunctionalProperty):
        domain = [SDNController]; range = [bool]
    class isCompromised(DataProperty, FunctionalProperty):
        domain = [SDNController]; range = [bool]
    class isMalformed(DataProperty, FunctionalProperty):
        domain = [EWRequest]; range = [bool]
    class isCriticalOperation(DataProperty, FunctionalProperty):
        domain = [EWRequest]; range = [bool]
    class isReadOnlyOperation(DataProperty, FunctionalProperty):
        domain = [EWRequest]; range = [bool]
    class hTauTampered(DataProperty, FunctionalProperty):
        domain = [EWRequest]; range = [bool]

    # REGLES SWRL - Categorie 1 : Syntaxiques
    # Tableau 3 de l'article : R0
    r0 = Imp()
    r0.set_as_rule(
        "EWRequest(?r), isMalformed(?r, true)"
        " -> isMalformed(?r, true)"
    )

    # REGLES SWRL - Categorie 2 : Contextuelles
    # Tableau 3 de l'article : R1
    r1 = Imp()
    r1.set_as_rule(
        "EWRequest(?r), issuedBy(?r, ?c), hasSIEMAlert(?c, true)"
        " -> SIEMThreatIndicator(?r)"
    )
    # Tableau 3 de l'article : R5 (forme EWRequest ; meme concept que r6)
    r2 = Imp()
    r2.set_as_rule(
        "EWRequest(?r), issuedBy(?r, ?c), isCompromised(?c, true)"
        " -> CompromisedController(?c)"
    )
    # Tableau 3 de l'article : R2
    r3 = Imp()
    r3.set_as_rule(
        "EWRequest(?r), issuedBy(?r, ?c),"
        " hasTrustScore(?c, ?sc), lessThan(?sc, 0.4)"
        " -> UntrustedController(?c)"
    )
    # Tableau 3 de l'article : R4
    r5 = Imp()
    r5.set_as_rule(
        "EWRequest(?r), hasContext(?r, ?ctx),"
        " networkLoad(?ctx, ?l), greaterThan(?l, 85.0),"
        " isCriticalOperation(?r, true)"
        " -> isCriticalOperation(?r, true)"
    )
    # Tableau 3 de l'article : R5
    r6 = Imp()
    r6.set_as_rule(
        "SDNController(?c), isCompromised(?c, true)"
        " -> CompromisedController(?c)"
    )
    # Tableau 3 de l'article : R6
    r7 = Imp()
    r7.set_as_rule(
        "EWRequest(?r), issuedBy(?r, ?c),"
        " hasTrustScore(?c, ?sc), greaterThan(?sc, 0.6),"
        " hasHour(?r, ?h),"
        " greaterThan(?h, 8), lessThan(?h, 18)"
        " -> TrustedController(?c)"
    )
    # Tableau 3 de l'article : R7
    r8 = Imp()
    r8.set_as_rule(
        "EWRequest(?r), issuedBy(?r, ?c),"
        " hasTrustScore(?c, ?sc), greaterThan(?sc, 0.5),"
        " isReadOnlyOperation(?r, true)"
        " -> TrustedController(?c)"
    )
    # Tableau 3 de l'article : R8
    r9 = Imp()
    r9.set_as_rule(
        "EWRequest(?r), hasUrgencyLevel(?r, ?u),"
        " greaterThan(?u, 0.8),"
        " issuedBy(?r, ?c),"
        " hasTrustScore(?c, ?sc), greaterThan(?sc, 0.7)"
        " -> TrustedController(?c)"
    )
    # Tableau 3 de l'article : R9
    r10 = Imp()
    r10.set_as_rule(
        "SDNController(?c), isInUnknownZone(?c, true)"
        " -> UntrustedController(?c)"
    )
    # Tableau 3 de l'article : R10
    r11 = Imp()
    r11.set_as_rule(
        "EWRequest(?r), hasHour(?r, ?h),"
        " greaterThan(?h, 22),"
        " isCriticalOperation(?r, true)"
        " -> isCriticalOperation(?r, true)"
    )
    # Tableau 3 de l'article : R11
    r13 = Imp()
    r13.set_as_rule(
        "PolicyDistributionRequest(?r), issuedBy(?r, ?c),"
        " hasTrustScore(?c, ?sc), greaterThan(?sc, 0.65)"
        " -> TrustedController(?c)"
    )
    # Tableau 3 de l'article : R12
    r14 = Imp()
    r14.set_as_rule(
        "EWRequest(?r), issuedBy(?r, ?c),"
        " requestFrequency(?c, ?f), greaterThan(?f, 50.0)"
        " -> AnomalousFrequency(?r)"
    )

    # REGLES SWRL - Categorie 3 : Comportementales
    # Tableau 3 de l'article : R_B1
    r_b1 = Imp()
    r_b1.set_as_rule(
        "TopologyUpdateRequest(?r), issuedBy(?r, ?c),"
        " requestFrequency(?c, ?f), greaterThan(?f, 3.0),"
        " hasNoJustifyingEvent(?r, true)"
        " -> TopologyPoisoningIndicator(?r)"
    )
    # Tableau 3 de l'article : R_B2
    r_b2 = Imp()
    r_b2.set_as_rule(
        "SynchronizationRequest(?r), issuedBy(?r, ?c),"
        " hasNoTriggeringEvent(?r, true),"
        " elapsedSinceLastEvent(?r, ?e), lessThan(?e, 120.0)"
        " -> FalseSyncIndicator(?r)"
    )
    # Tableau 3 de l'article : R_B3
    r_b3 = Imp()
    r_b3.set_as_rule(
        "EWRequest(?r), issuedBy(?r, ?c),"
        " isInUnknownZone(?c, true),"
        " requestFrequency(?c, ?f), greaterThan(?f, 10.0)"
        " -> BehavioralSpoofingIndicator(?r)"
    )
    # Tableau 3 de l'article : R_MITM
    r_mitm = Imp()
    r_mitm.set_as_rule(
        "EWRequest(?r), hTauTampered(?r, true)"
        " -> HashMismatchIndicator(?r)"
    )

onto.save(file=OWL_PATH, format="rdfxml")
print(f"OK : {OWL_PATH}")
print(f"  Classes    : {len(list(onto.classes()))}")
print(f"  Obj.Props  : {len(list(onto.object_properties()))}")
print(f"  Data.Props : {len(list(onto.data_properties()))}")
print(f"  SWRL Rules : {len(list(onto.rules()))}")

onto2 = get_ontology(f"file://{OWL_PATH}").load()
print(f"  Rechargement OK : {len(list(onto2.classes()))} classes")
