# ~/dsac/monitor/metrics.py
import time
import csv
import os
from datetime import datetime

METRICS_FILE = os.path.expanduser(
    "~/dsac/monitor/dsac_metrics.csv")

def init_metrics_file():
    """Crée le fichier CSV avec les en-têtes"""
    os.makedirs(os.path.dirname(METRICS_FILE),
                exist_ok=True)
    if not os.path.exists(METRICS_FILE):
        with open(METRICS_FILE, 'w',
                  newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp",
                "request_id",
                "source",
                "target",
                "operation",
                "urgency",
                "t_pip_ms",
                "t_cache_ms",
                "t_inference_ms",
                "t_forward_ms",
                "t_total_ms",
                "verdict",
                "rule",
                "cache_hit",
                "http_status"
            ])
    print(f"[METRICS] Fichier : {METRICS_FILE}")

def save_metric(data: dict):
    """Sauvegarde une ligne de métrique"""
    with open(METRICS_FILE, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.utcnow().isoformat(),
            data.get("request_id", ""),
            data.get("source", ""),
            data.get("target", ""),
            data.get("operation", ""),
            data.get("urgency", 0.0),
            round(data.get("t_pip_ms", 0), 2),
            round(data.get("t_cache_ms", 0), 2),
            round(data.get("t_inference_ms", 0), 2),
            round(data.get("t_forward_ms", 0), 2),
            round(data.get("t_total_ms", 0), 2),
            data.get("verdict", ""),
            data.get("rule", ""),
            data.get("cache_hit", False),
            data.get("http_status", 0)
        ])
