import os
import time
import sys

FILE_PATH = os.path.expanduser("~/dsac/monitor/dsac_metrics.csv")

def draw_interface():
    if not os.path.exists(FILE_PATH) or os.stat(FILE_PATH).st_size == 0:
        print("\033[H\033[J")
        print("==========================================================")
        print("    📊 DSAC METRICS LIVE DASHBOARD (MODE ANALYSE)        ")
        print("==========================================================")
        print("\n [i] En attente du flux de données East-West...")
        return

    try:
        with open(FILE_PATH, "r", encoding="utf-8", errors="ignore") as f:
            lines = [line.strip() for line in f.readlines() if line.strip()]

        if not lines:
            return

        valid_lines = []
        permits = 0
        denies = 0

        for line in lines:
            parts = line.split(',')
            if len(parts) >= 12:  # S'assurer que la ligne est complète
                try:
                    score = float(parts[5].strip())  # Index du trust score dans ton CSV brut
                    action = parts[11].strip()       # Index de l'action (PERMIT/DENY)
                    valid_lines.append((score, action))
                    if action == "PERMIT":
                        permits += 1
                    elif action == "DENY":
                        denies += 1
                except ValueError:
                    continue

        if not valid_lines:
            return

        total = len(valid_lines)
        last_score, last_action = valid_lines[-1]

        # Calcul des barres pour le graphique de répartition
        permit_pct = (permits / total) * 100 if total > 0 else 0
        deny_pct = (denies / total) * 100 if total > 0 else 0
        
        bar_permit = "█" * int(permit_pct / 4)
        bar_deny = "█" * int(deny_pct / 4)

        # Jauge pour le tout dernier Trust Score
        num_bars_score = int(max(0.0, min(last_score, 1.0)) * 20)
        bar_score = "█" * num_bars_score + "░" * (20 - num_bars_score)

        # Couleurs
        c_permit = "\033[92m"
        c_deny = "\033[91m"
        c_reset = "\033[0m"
        c_score = c_permit if last_score > 0.6 else c_deny

        # Rendu graphique dans le terminal
        print("\033[H\033[J")
        print("==========================================================")
        print("    📊 DSAC METRICS LIVE DASHBOARD (MODE ANALYSE)        ")
        print("==========================================================")
        print(f" Total Trafic Analysé : {total} requêtes")
        print(f" Dernière Action PEP  : {c_permit if last_action == 'PERMIT' else c_deny}{last_action}{c_reset}")
        print(f" Trust Score Actuel   : {c_score}{last_score:.2f}{c_reset} [{c_score}{bar_score}{c_reset}]")
        print("----------------------------------------------------------")
        print(" 📈 RÉPARTITION DU TRAFIC EN TEMPS RÉEL :")
        print(f"  {c_permit}PERMIT (Sain){c_reset}  : {permit_pct:6.1f}% {c_permit}{bar_permit}{c_reset}")
        print(f"  {c_deny}DENY (Bloqué){c_reset} : {deny_pct:6.1f}% {c_deny}{bar_deny}{c_reset}")
        print("==========================================================")
        print(" Historique des alertes (Flux East-West) :")
        
        # Afficher les 4 dernières lignes de manière condensée
        with open(FILE_PATH, "r", encoding="utf-8", errors="ignore") as f:
            raw_lines = f.readlines()
        for r_line in raw_lines[-4:]:
            p = r_line.strip().split(',')
            if len(p) >= 12:
                act = p[11].strip()
                col = c_permit if act == "PERMIT" else c_deny
                print(f" -> [{p[0][:19]}] {p[2]}➔{p[3]} | Action: {col}{act}{c_reset} | Score: {p[5]}")
        print("==========================================================")

    except Exception:
        pass

if __name__ == "__main__":
    while True:
        draw_interface()
        time.sleep(0.3) # Très réactif (3 fois par seconde)	
