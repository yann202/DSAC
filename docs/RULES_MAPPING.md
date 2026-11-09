# Correspondance des regles : Tableau 3 de l'article et code

Les identifiants du code suivent desormais ceux du Tableau 3 de l'article. Les anciens
identifiants figurent encore dans les journaux d'execution anterieurs (`monitor/dsac_metrics.csv`).

| Article | Verdict | Condition | Ancien identifiant | Ou dans le code |
|---|---|---|---|---|
| R0 | DENY | requete malformee | R0 | `pdp/reasoner.py` (`_eval_rules`) ; OWL `r0` |
| R1 | DENY | alerte SIEM sur l'expediteur | R1 | evaluateur ; OWL `r1` |
| R2 | DENY | theta < 0.4 | R3 | evaluateur ; OWL `r3` |
| R3 | DENY | MaintenanceViolation | R4 (Pellet seulement) | prevue dans la conception, non implementee ; classe presente dans l'ontologie |
| R4 | DENY | charge > 85 %, operation critique | R5 | evaluateur ; OWL `r5` |
| R5 | DENY | expediteur compromis | R6 | evaluateur ; OWL `r2` et `r6` |
| R6 | PERMIT | heures ouvrees, S(tau) >= 0.6 | R7 | evaluateur ; OWL `r7` |
| R7 | PERMIT | lecture seule, theta >= 0.5 | R8 | evaluateur ; OWL `r8` |
| R8 | PERMIT | urgence >= 0.8, theta >= 0.7 | R9 | evaluateur ; OWL `r9` |
| R9 | DENY | UntrustedController infere | (OWL r10) | OWL `r10` ; l'evaluateur refuse une zone inconnue uniquement via R_B3 |
| R10 | DENY | operation critique apres 22 h | R11 | evaluateur ; OWL `r11` |
| R11 | PERMIT | distribution de politique, theta >= 0.65 | R13 | evaluateur ; OWL `r13` |
| R12 | DENY | frequence globale > 50 req/min | R14 | evaluateur ; OWL `r14` |
| R_B1 | DENY | > 3 mises a jour de topologie/min sans justification | R_B1 | evaluateur ; OWL `r_b1` |
| R_B2 | DENY | synchronisation sans declencheur (< 120 s) | R_B2 | evaluateur ; OWL `r_b2` |
| R_B3 | DENY | zone inconnue, frequence > 10/min | R_B3 | evaluateur ; OWL `r_b3` |
| R_MITM | DENY | H(tau) different a l'arrivee | R_MITM | evaluateur ; OWL `r_mitm` |
| R_DEF | DENY | aucune regle PERMIT satisfaite | R0_DEFAULT | evaluateur uniquement |

## Notes

* Le fichier OWL contient 17 regles SWRL : seize regles distinctes du Tableau 3 (la regle R5 y est ecrite
  deux fois, `r2` et `r6`) plus la regle `r0`. Les dix-huit regles du Tableau 3 s'obtiennent en ajoutant R3
  (non implementee) et R_DEF (evaluateur).
* Le theta des regles R2, R7, R8 et R11 correspond a l'entree `trust_score` de l'evaluateur ; seule R6 utilise
  le score agrege S(tau).
* Les evaluations de l'article ont ete produites par l'evaluateur de regles de `pdp/reasoner.py`, pas par
  Pellet (voir l'article, section 7.1). Les bornes horaires et les comparaisons de l'OWL (par exemple
  `greaterThan` strict) peuvent differer de celles de l'evaluateur ; l'evaluateur fait foi.
* Les etiquettes de regles du corpus (`dataset/`) ont ete renommees de la meme facon (R3-LOW-TRUST devient
  R2-LOW-TRUST, R7-BUSINESS-HOURS devient R6-BUSINESS-HOURS, R8-READONLY devient R7-READONLY) ; les
  decisions et les valeurs des requetes sont inchangees.
