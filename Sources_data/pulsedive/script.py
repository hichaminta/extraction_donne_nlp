import requests
import json
import os
import time
import csv
from dotenv import load_dotenv, find_dotenv
from datetime import datetime, timezone

# Charger .env depuis le dossier parent si nécessaire
load_dotenv(find_dotenv())

API_KEY = os.getenv("PULSEDIVE_API_KEY")

BASE_URL = "https://pulsedive.com/api/explore.php"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "pulsedive_iocs.json")
TRACKING_CSV = os.path.join(SCRIPT_DIR, "last_run.csv")


def get_last_run():
    if not os.path.exists(TRACKING_CSV):
        return None

    try:
        with open(TRACKING_CSV, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            rows = list(reader)
            if len(rows) > 1 and rows[1]:
                return rows[1][0]  # Return the date from the second row
    except Exception:
        return None

    return None

def update_last_run(dt_iso):
    with open(TRACKING_CSV, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["date_extraction"])
        writer.writerow([dt_iso])


def fetch_iocs(limit=50):
    """
    Récupère des IOC depuis Pulsedive en maximisant les résultats
    """
    all_results = []
    
    # Itérer sur différents niveaux de risque pour maximiser l'extraction (limite API stricte = 50 par requête)
    risk_levels = ["critical", "high", "medium", "low", "none", "unknown"]

    for risk in risk_levels:
        print(f"Extraction des IOC avec risque: {risk}...")
        params = {
            "limit": limit,
            "pretty": 1,
            "key": API_KEY,
            "q": f"risk={risk}"
        }

        try:
            response = requests.get(BASE_URL, params=params)

            if response.status_code != 200:
                print(f"Erreur API pour risk={risk}:", response.status_code)
                continue

            data = response.json()

            results_list = data.get("results", [])
            print(f" - {len(results_list)} résultats trouvés pour {risk}")

            for item in results_list:
                record = {
                    "indicator": item.get("indicator"),
                    "type": item.get("type"),
                    "risk": item.get("risk"),
                    "threat": item.get("threat"),
                    "category": item.get("category"),
                    "first_seen": item.get("stamp_added"),
                    "last_seen": item.get("stamp_updated"),
                    "source": "pulsedive",
                    "collected_at": datetime.now(timezone.utc).isoformat()
                }

                all_results.append(record)
                
            time.sleep(1) # Pause pour éviter le rate limit
            
        except Exception as e:
            print(f"Erreur lors de la requête pour risk={risk}: {e}")

    # Déduplication basée sur l'indicateur
    unique_items = {}
    for item in all_results:
        unique_items[item["indicator"]] = item
        
    return list(unique_items.values())


def save_json(data):
    if os.path.exists(OUTPUT_FILE):
        with open(OUTPUT_FILE, "r") as f:
            existing = json.load(f)
    else:
        existing = []

    # Extraire les indicateurs existants pour éviter les doublons au niveau global
    existing_indicators = {item['indicator'] for item in existing}
    
    # Filtrer les nouvelles données
    new_data = [item for item in data if item['indicator'] not in existing_indicators]

    if not new_data:
        return 0

    combined = existing + new_data

    with open(OUTPUT_FILE, "w") as f:
        json.dump(combined, f, indent=4)
        
    return len(new_data)


def main():
    print("Extraction Pulsedive IOC (Maximisée)...")
    last_run = get_last_run()
    print(f"[i] Dernière exécution: {last_run}")

    iocs = fetch_iocs()

    if not iocs:
        print("Aucune donnée récupérée")
    else:
        added = save_json(iocs)
        print(f"{added} nouveaux IOC ajoutés (Total unique extrait : {len(iocs)})")

    current_run = datetime.now(timezone.utc).isoformat()
    update_last_run(current_run)
    print(f"[+] last_run.csv mis à jour: {current_run}")


if __name__ == "__main__":
    main()