import json
import time
import os
import csv
from datetime import datetime, timezone
from OTXv2 import OTXv2
from dotenv import load_dotenv, find_dotenv

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_JSON = os.path.join(SCRIPT_DIR, "otx_pulses.json")
TRACKING_FILE = os.path.join(SCRIPT_DIR, "last_run.csv")

load_dotenv(find_dotenv())


def get_api_key():
    return os.getenv("OTX_API_KEY")


def parse_dt(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


def get_last_run_date():
    if os.path.exists(TRACKING_FILE):
        with open(TRACKING_FILE, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader, None)
            rows = [row for row in reader if row]
            if rows:
                return rows[-1][0]
    return None


def save_last_run_date(date_str):
    file_exists = os.path.exists(TRACKING_FILE)
    with open(TRACKING_FILE, "a", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["date_extraction"])
        writer.writerow([date_str])


def load_existing_data():
    if os.path.exists(OUTPUT_JSON):
        try:
            with open(OUTPUT_JSON, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return []


def save_json(data):
    tmp_file = OUTPUT_JSON + ".tmp"
    with open(tmp_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp_file, OUTPUT_JSON)


def main():
    api_key = get_api_key()
    if not api_key or "YOUR_OTX_API_KEY" in api_key:
        print("Erreur : Veuillez configurer votre clé API OTX dans le fichier .env")
        return

    otx = OTXv2(api_key)
    last_run = get_last_run_date()
    last_run_dt = parse_dt(last_run)

    start_time = datetime.now(timezone.utc)
    start_time_str = start_time.isoformat()

    print(f"Dernière extraction réussie : {last_run if last_run else 'Jamais'}")
    print("Récupération et traitement des pulses auxquels vous êtes abonné...")

    existing_data = load_existing_data()
    existing_ids = {p.get("id") for p in existing_data if p.get("id")}

    added_count = 0
    total_processed = 0
    last_save_time = time.time()

    try:
        pulses_iter = otx.getall_iter(modified_since=last_run)

        for pulse in pulses_iter:
            total_processed += 1

            pulse_id = pulse.get("id")
            pulse_modified = pulse.get("modified")
            pulse_modified_dt = parse_dt(pulse_modified)
            pulse_name = pulse.get("name", "Sans nom")

            if pulse_id in existing_ids:
                continue

            if last_run_dt and pulse_modified_dt and pulse_modified_dt <= last_run_dt:
                continue

            print(f"[{total_processed}] Pulse: {pulse_name} ({pulse_id})")

            indicators = []
            try:
                print(f"    -> récupération des indicateurs...")
                indicators = otx.get_pulse_indicators(pulse_id)
                print(f"    -> {len(indicators)} indicateurs récupérés")
            except KeyboardInterrupt:
                raise
            except Exception as e:
                print(f"    -> erreur indicateurs pour {pulse_id}: {e}")

            cleaned_pulse = {
                "id": pulse_id,
                "name": pulse_name,
                "description": pulse.get("description"),
                "modified": pulse_modified,
                "created": pulse.get("created"),
                "tags": pulse.get("tags", []),
                "references": pulse.get("references", []),
                "indicator_count": len(indicators),
                "indicators": indicators,
            }

            existing_data.append(cleaned_pulse)
            existing_ids.add(pulse_id)
            added_count += 1

            # sauvegarde moins fréquente
            if added_count % 20 == 0 or (time.time() - last_save_time) > 60:
                save_json(existing_data)
                last_save_time = time.time()
                print(f"    -> sauvegarde intermédiaire ({added_count} nouveaux)")

            # petite pause pour éviter de marteler l’API
            time.sleep(0.2)

    except KeyboardInterrupt:
        print("\nInterruption par l'utilisateur. Sauvegarde de la progression...")
    except Exception as e:
        print(f"Erreur critique lors de la récupération : {e}")

    save_json(existing_data)
    save_last_run_date(start_time_str)
    print(f"Extraction terminée. {added_count} nouveaux pulses ajoutés. Total : {len(existing_data)}")


if __name__ == "__main__":
    main()