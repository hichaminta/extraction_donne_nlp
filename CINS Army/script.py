import os
import json
import hashlib
import csv
from datetime import datetime, timezone

import requests

# Base directory setup
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

CINS_URL = "https://cinsarmy.com/list/ci-badguys.txt"
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "cins_army.json")
TRACKING_CSV = os.path.join(SCRIPT_DIR, "last_run.csv")
TIMEOUT = 30


def is_valid_ip(line: str) -> bool:
    parts = line.split(".")
    if len(parts) != 4:
        return False

    for part in parts:
        if not part.isdigit():
            return False
        value = int(part)
        if value < 0 or value > 255:
            return False

    return True


def fetch_cins_list(url: str) -> list[str]:
    if not url:
        raise ValueError("CINS_URL est vide dans le fichier .env")

    response = requests.get(url, timeout=TIMEOUT)
    response.raise_for_status()

    ips = []
    for raw_line in response.text.splitlines():
        line = raw_line.strip()

        if not line:
            continue
        if line.startswith("#"):
            continue

        if is_valid_ip(line):
            ips.append(line)

    return ips


def normalize_records(ips: list[str]) -> list[dict]:
    collected_at = datetime.now(timezone.utc).isoformat()

    records = []
    for ip in ips:
        record = {
            "indicator": ip,
            "type": "ip",
            "source": "cins_army",
            "threat": "malicious_ip",
            "collected_at": collected_at,
            "hash": hashlib.sha256(f"cins_army:{ip}".encode("utf-8")).hexdigest()
        }
        records.append(record)

    return records


def deduplicate_records(records: list[dict]) -> list[dict]:
    seen = set()
    unique = []

    for record in records:
        key = (record["source"], record["indicator"])
        if key not in seen:
            seen.add(key)
            unique.append(record)

    return unique


def save_json(records: list[dict], output_file: str) -> None:
    # Optionnel: On pourrait charger l'existant ici pour ne pas tout écraser, mais on garde la logique initiale.
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(records, f, ensure_ascii=False, indent=2)


def get_last_run():
    if not os.path.exists(TRACKING_CSV):
        return None
    try:
        with open(TRACKING_CSV, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            rows = list(reader)
            if len(rows) > 1 and rows[1]:
                return rows[1][0]
    except Exception:
        return None
    return None


def update_last_run(dt_iso):
    with open(TRACKING_CSV, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["date_extraction"])
        writer.writerow([dt_iso])


def main():
    try:
        print("[+] Téléchargement de la liste CINS Army...")
        last_run = get_last_run()
        print(f"[i] Dernière exécution: {last_run}")
        
        ips = fetch_cins_list(CINS_URL)
        print(f"[+] {len(ips)} IP récupérées")

        records = normalize_records(ips)
        records = deduplicate_records(records)

        save_json(records, OUTPUT_FILE)
        print(f"[+] Fichier JSON créé : {OUTPUT_FILE}")

        current_run = datetime.now(timezone.utc).isoformat()
        update_last_run(current_run)
        print(f"[+] last_run.csv mis à jour: {current_run}")

    except requests.HTTPError as e:
        print(f"[ERREUR HTTP] {e}")
    except requests.RequestException as e:
        print(f"[ERREUR RESEAU] {e}")
    except Exception as e:
        print(f"[ERREUR] {e}")


if __name__ == "__main__":
    main()