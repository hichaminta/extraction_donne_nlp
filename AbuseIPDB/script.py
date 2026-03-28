import requests
import json
import os
import csv
from datetime import datetime, timezone
from dotenv import load_dotenv

# Configuration
# Charge le .env racine (dossier parent) ou le .env local en fallback
_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(_root, ".env"))
API_KEY = os.getenv("ABUSEIPDB_API_KEY")
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_JSON = os.path.join(SCRIPT_DIR, "abuseipdb_data.json")
TRACKING_FILE = os.path.join(SCRIPT_DIR, "last_run.csv")
URL = "https://api.abuseipdb.com/api/v2/blacklist"

def load_existing_data():
    """Charge les données existantes depuis le fichier JSON."""
    if os.path.exists(OUTPUT_JSON):
        try:
            with open(OUTPUT_JSON, "r", encoding="utf-8") as f:
                return json.load(f)
        except:
            pass
    return []

def get_last_run_date():
    """Récupère la date de la dernière extraction depuis le fichier CSV."""
    if os.path.exists(TRACKING_FILE):
        with open(TRACKING_FILE, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            rows = [row for row in reader if row and len(row) > 0]
            if rows:
                if rows[0][0] == "date_extraction":
                    if len(rows) > 1:
                        return rows[-1][0]
                    else:
                        return None
                return rows[-1][0]
    return None

def save_last_run_date(date_str=None):
    """Enregistre la date de l'exécution actuelle."""
    if not date_str:
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")
        
    file_exists = os.path.exists(TRACKING_FILE)
    with open(TRACKING_FILE, "a", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["date_extraction"])
        writer.writerow([date_str])

def main():
    headers = {
        "Key": API_KEY,
        "Accept": "application/json"
    }
    params = {}

    print("Récupération de la blacklist AbuseIPDB (seuil par défaut)...")
    try:
        response = requests.get(URL, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        print(f"Erreur lors de la requête API : {e}")
        return

    last_run_str = get_last_run_date()
    last_run_dt = None
    if last_run_str:
        print(f"Extraction incrémentale à partir de : {last_run_str}")
        try:
            if "T" in last_run_str:
                last_run_dt = datetime.fromisoformat(last_run_str.replace("Z", "+00:00"))
            else:
                last_run_dt = datetime.strptime(last_run_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except ValueError:
            pass

    existing_data = load_existing_data()
    existing_ips = {item["ipAddress"]: item for item in existing_data}
    
    new_entries_count = 0
    updated_entries_count = 0
    announced_count = 0
    
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    
    for ip in data.get("data", []):
        ip_addr = ip["ipAddress"]
        score = ip["abuseConfidenceScore"]
        last_reported_str = ip.get("lastReportedAt")
        
        if last_run_dt and last_reported_str:
            try:
                last_reported = datetime.fromisoformat(last_reported_str.replace("Z", "+00:00"))
                if last_reported <= last_run_dt:
                    continue
            except ValueError:
                pass
        
        if ip_addr in existing_ips:
            existing_item = existing_ips[ip_addr]
            if last_reported_str and existing_item.get("lastReportedAt") != last_reported_str:
                existing_item["abuseConfidenceScore"] = score
                existing_item["lastReportedAt"] = last_reported_str
                existing_item["updated_at"] = now_str
                updated_entries_count += 1
        else:
            new_item = {
                "ipAddress": ip_addr,
                "abuseConfidenceScore": score,
                "lastReportedAt": last_reported_str,
                "extracted_at": now_str
            }
            existing_ips[ip_addr] = new_item
            new_entries_count += 1
            
            # N'annonce que les IPs avec un score >= 90
            if score >= 90:
                print(f"ALERTE : {ip_addr} (Confidence: {score})")
                announced_count += 1

    if new_entries_count > 0 or updated_entries_count > 0:
        updated_data = list(existing_ips.values())
        with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
            json.dump(updated_data, f, indent=4, ensure_ascii=False)
        print(f"Extraction terminée. {new_entries_count} nouvelles IPs, {updated_entries_count} mises à jour.")
        if announced_count > 0:
            print(f"{announced_count} IPs à haute confiance annoncées.")
    else:
        print("Aucune nouvelle IP ou mise à jour trouvée.")

    save_last_run_date(now_str)

if __name__ == "__main__":
    main()
