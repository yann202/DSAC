import os
import time

FILE_PATH = os.path.expanduser("~/dsac/monitor/dsac_metrics.csv")

def parse_last_line():
    if not os.path.exists(FILE_PATH) or os.stat(FILE_PATH).st_size == 0:
        print("\033[H\033[J")
        print("====================================================")
        print("      MONITORING SÉCURITÉ DSAC (MODE TERMINAL)      ")
        print("====================================================")
        print("\n[i] En attente de trafic East-West (Lancez les tests)...")
        return

    try:
        # Ouverture sécurisée avec gestion d'encodage et flux continu
        with open(FILE_PATH, "r", encoding="utf-8", errors="ignore") as f:
            lines = [line.strip() for line in f.readlines() if line.strip()]
            
        if not lines:
            return

        # Filtrer pour ne garder que les lignes valides contenant un score numérique
        valid_lines = []
        for line in lines:
            parts = line.split(',')
            if len(parts) >= 3:
                try:
                    float(parts[2].strip()) # Test de conversion du Trust Score
                    valid_lines.append(parts)
                except ValueError:
                    continue # Ignore les en-têtes ou lignes de texte parasites

        if not valid_lines:
            return

        total_req = len(valid_lines)
        last_line = valid_lines[-1]
        
        timestamp = last_line[0]
        action = last_line[1].strip()
        trust_score = float(last_line[2].strip())
        
        # Détermination dynamique des couleurs ANSI
        act_color = "\033[92m" if action == "PERMIT" else "\033[91m"
        trust_color = "\033[92m" if trust_score > 0.6 else "\033[91m"

        # Génération de la jauge graphique en mode texte [████░░░░]
        num_bars = int(max(0.0, min(trust_score, 1.0)) * 10)
        bar_graph = "█" * num_bars + "░" * (10 - num_bars)

        # Rendu de l'interface dans le terminal
        print("\033[H\033[J") # Efface l'écran proprement à chaque rafraîchissement
        print("====================================================")
        print("      MONITORING SÉCURITÉ DSAC (MODE TERMINAL)      ")
        print("====================================================")
        print(f" Total Requêtes Valides        : {total_req}")
        print(f" Dernière Action PEP           : {act_color}{action}\033[0m")
        print(f" Trust Score Actuel            : {trust_color}{trust_score:.2f}\033[0m")
        print(f" Graphique de Confiance        : {trust_color}[{bar_graph}]\033[0m")
        print("----------------------------------------------------")
        print(" Historique récent du flux (5 derniers événements) :")
        
        # Affichage des 5 dernières lignes de logs
        for parts in valid_lines[-5:]:
            c = "\033[92m" if "PERMIT" in parts[1] else "\033[91m"
            print(f" -> [{parts[0].strip()}] {c}{parts[1].strip()}\033[0m | Score: {parts[2].strip()}")
        print("====================================================")

    except Exception as e:
        # Ignore silencieusement les micro-erreurs d'accès concurrent au fichier
        pass

if __name__ == '__main__':
    while True:
        parse_last_line()
        time.sleep(0.5) # Fréquence de rafraîchissement (2 fois par seconde)
