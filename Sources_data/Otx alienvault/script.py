import json
import time
import os
import csv
from datetime import datetime, timedelta, timezone
from OTXv2 import OTXv2
from dotenv import load_dotenv, find_dotenv

# Configuration
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_JSON = os.path.join(SCRIPT_DIR, "otx_pulses.json")
TRACKING_FILE = os.path.join(SCRIPT_DIR, "last_run.csv")

load_dotenv(find_dotenv())

def get_api_key():
    """Charge la clé API depuis les variables d'environnement."""
    return os.getenv("OTX_API_KEY")

def get_last_run_date():
    """Récupère la date de la dernière extraction depuis le fichier CSV."""
    if os.path.exists(TRACKING_FILE):
        with open(TRACKING_FILE, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader, None)  # Sauter l'en-tête
            rows = [row for row in reader if row]
            if rows:
                return rows[-1][0]
    return None

def save_last_run_date(date_str):
    """Sauvegarde la date de l'extraction actuelle."""
    file_exists = os.path.exists(TRACKING_FILE)
    with open(TRACKING_FILE, "a", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["date_extraction"])
        writer.writerow([date_str])

def load_existing_data():
    """Charge les données existantes pour éviter les doublons."""
    if os.path.exists(OUTPUT_JSON):
        try:
            with open(OUTPUT_JSON, "r", encoding="utf-8") as f:
                return json.load(f)
        except:
            pass
    return []

def main():
    api_key = get_api_key()
    if not api_key or "YOUR_OTX_API_KEY" in api_key:
        print("Erreur : Veuillez configurer votre clé API OTX dans le fichier .env")
        return

    otx = OTXv2(api_key)
    last_run = get_last_run_date()
    start_time = datetime.now(timezone.utc)
    start_time_str = start_time.strftime("%Y-%m-%dT%H:%M:%S")

    print(f"Dernière extraction réussie : {last_run if last_run else 'Jamais'}")
    
    print("Récupération et traitement des pulses auxquels vous êtes abonné...")
    
    existing_data = load_existing_data()
    existing_ids = {p["id"] for p in existing_data}
    added_count = 0
    total_processed = 0

    try:
        # getall_iter est un itérateur, on le parcourt directement pour éviter de bloquer
        pulses_iter = otx.getall_iter(modified_since=last_run)
        
        for pulse in pulses_iter:
            total_processed += 1
            pulse_id = pulse.get("id")
            pulse_modified = pulse.get("modified")
            pulse_name = pulse.get('name', 'Sans nom')

            # Protection contre les doublons et filtres de date restants
            if pulse_id in existing_ids:
                continue
            if last_run and pulse_modified and pulse_modified <= last_run:
                continue

            print(f"[{total_processed}] Extraction en cours...")
            
            try:
                # otx.get_pulse_indicators récupère TOUS les indicateurs (IoCs)
                indicators = otx.get_pulse_indicators(pulse_id)
                
                cleaned_pulse = {
                    "id": pulse_id,
                    "name": pulse_name,
                    "description": pulse.get("description"),
                    "modified": pulse_modified,
                    "created": pulse.get("created"),
                    "tags": pulse.get("tags", []),
                    "references": pulse.get("references", []),
                    "indicator_count": len(indicators),
                    "indicators": indicators # Liste complète des IoCs
                }
                
                existing_data.append(cleaned_pulse)
                existing_ids.add(pulse_id)
                added_count += 1
                
                # Sauvegarde incrémentale tous les 5 nouveaux pulses
                if added_count % 5 == 0:
                    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
                        json.dump(existing_data, f, indent=4, ensure_ascii=False)
                        
            except KeyboardInterrupt:
                raise
            except Exception as e:
                print(f"Erreur sur le pulse {pulse_id} : {e}")
                continue

    except KeyboardInterrupt:
        print("\nInterruption par l'utilisateur. Sauvegarde de la progression...")
    except Exception as e:
        print(f"Erreur critique lors de la récupération : {e}")
    
    # Sauvegarde finale
    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(existing_data, f, indent=4, ensure_ascii=False)
    
    save_last_run_date(start_time_str)
    print(f"Extraction terminée. {added_count} nouveaux pulses ajoutés. Total : {len(existing_data)}")

if __name__ == "__main__":
    main()
