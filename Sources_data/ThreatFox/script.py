import requests
import json
import os
import csv
from datetime import datetime, timedelta
from dotenv import load_dotenv, find_dotenv

# ── Configuration ──────────────────────────────────────────────────────────────
load_dotenv(find_dotenv(), override=False)

API_KEY      = os.getenv("THREATFOX_API_KEY", "")
API_URL      = "https://threatfox-api.abuse.ch/api/v1/"
OUTPUT_JSON  = os.path.join(SCRIPT_DIR, "threatfox_data.json")
TRACKING_CSV = os.path.join(SCRIPT_DIR, "last_run.csv")

# Nombre de jours d'IOCs à récupérer lors de la première exécution
DAYS_FIRST_RUN = 90


# ── Helpers ────────────────────────────────────────────────────────────────────

def load_existing_data() -> list:
    """Charge les IOCs déjà sauvegardés."""
    if os.path.exists(OUTPUT_JSON):
        try:
            with open(OUTPUT_JSON, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return []


def save_data(data: list):
    """Sauvegarde la liste complète des IOCs en JSON."""
    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)


def get_last_run_date() -> datetime | None:
    """Lit la dernière date d'exécution depuis le CSV de suivi."""
    if not os.path.exists(TRACKING_CSV):
        return None
    try:
        with open(TRACKING_CSV, "r", encoding="utf-8") as f:
            rows = list(csv.reader(f))
        # Ignore l'en-tête, prend la dernière ligne
        data_rows = [r for r in rows if r and r[0] != "date_extraction"]
        if data_rows:
            return datetime.strptime(data_rows[-1][0], "%Y-%m-%d %H:%M:%S")
    except Exception:
        pass
    return None


def save_last_run():
    """Enregistre la date/heure de l'exécution dans le CSV de suivi."""
    file_exists = os.path.exists(TRACKING_CSV)
    with open(TRACKING_CSV, "a", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["date_extraction"])
        writer.writerow([datetime.now().strftime("%Y-%m-%d %H:%M:%S")])


def build_headers() -> dict:
    """Construit les en-têtes HTTP (auth si clé présente)."""
    headers = {"Content-Type": "application/json"}
    if API_KEY and API_KEY != "your_threatfox_api_key_here":
        headers["Auth-Key"] = API_KEY
    return headers


def fetch_iocs(days: int) -> list:
    """
    Interroge l'API ThreatFox pour obtenir les IOCs des N derniers jours.
    Retourne la liste brute d'IOCs ou [] en cas d'erreur.
    """
    payload = {"query": "get_iocs", "days": days}
    print(f"  → Requête ThreatFox : IOCs des {days} derniers jours...")
    try:
        response = requests.post(
            API_URL,
            headers=build_headers(),
            json=payload,
            timeout=60
        )
        response.raise_for_status()
        result = response.json()
    except Exception as e:
        print(f"  ✗ Erreur lors de la requête API : {e}")
        return []

    status = result.get("query_status", "")
    if status != "ok":
        print(f"  ✗ Statut API inattendu : {status}")
        # DEBUG: print full response if it fails
        print(f"  ✗ Raw response: {response.text}")
        return []

    data_iocs = result.get("data", [])
    if not data_iocs:
        print(f"  ✗ Attention, 0 données dans 'data'. Raw: {response.text[:200]}")
    return data_iocs or []


def normalize_ioc(raw: dict) -> dict:
    """Normalise un IOC brut en un dictionnaire uniforme."""
    return {
        "id":            raw.get("id"),
        "ioc":           raw.get("ioc"),
        "ioc_type":      raw.get("ioc_type"),
        "ioc_type_desc": raw.get("ioc_type_desc"),
        "threat_type":   raw.get("threat_type"),
        "threat_type_desc": raw.get("threat_type_desc"),
        "malware":       raw.get("malware"),
        "malware_alias": raw.get("malware_alias"),
        "malware_printable": raw.get("malware_printable"),
        "confidence_level": raw.get("confidence_level"),
        "first_seen":    raw.get("first_seen"),
        "last_seen":     raw.get("last_seen"),
        "reporter":      raw.get("reporter"),
        "reference":     raw.get("reference"),
        "tags":          raw.get("tags"),
        "extracted_at":  datetime.now().isoformat(),
    }


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("ThreatFox IOC Extraction")
    print("=" * 60)

    if not API_KEY or API_KEY == "your_threatfox_api_key_here":
        print("[AVERTISSEMENT] Aucune clé API configurée dans .env")
        print("  Les requêtes publiques (sans auth) sont limitées.")

    # Détermine combien de jours récupérer d'après le last_run.csv
    existing   = load_existing_data()
    last_run   = get_last_run_date()

    if last_run is None:
        days = DAYS_FIRST_RUN
        print(f"  Première exécution → récupération des {days} derniers jours")
    else:
        delta = datetime.now() - last_run
        days  = max(1, delta.days + 1)   # +1 pour ne pas rater la dernière journée
        print(f"  Dernière exécution : {last_run.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Intervalle         : {delta.days} jour(s) → récupération des {days} derniers jours")

    print(f"\n[1/3] Chargement des données existantes : {len(existing)} IOCs")

    # Récupère les nouveaux IOCs
    print(f"\n[2/3] Extraction des IOCs...")
    raw_iocs = fetch_iocs(days)
    print(f"  → {len(raw_iocs)} IOCs reçus de l'API")

    if not raw_iocs:
        print("\nAucun IOC récupéré. Vérifiez votre clé API ou réessayez plus tard.")
        save_last_run()
        return

    # Fusion incrémentale (dédoublonnage par 'id')
    print(f"\n[3/3] Fusion et dédoublonnage...")
    existing_ids = {item["id"] for item in existing if item.get("id")}
    new_entries = []

    for raw in raw_iocs:
        ioc_id = raw.get("id")
        if ioc_id not in existing_ids:
            new_entries.append(normalize_ioc(raw))
            existing_ids.add(ioc_id)

    if new_entries:
        existing.extend(new_entries)
        save_data(existing)
        print(f"  ✓ {len(new_entries)} nouveaux IOCs ajoutés.")
        print(f"  ✓ Total en base : {len(existing)} IOCs")

        # Résumé par type
        types = {}
        for ioc in new_entries:
            t = ioc.get("ioc_type", "unknown")
            types[t] = types.get(t, 0) + 1
        print("\n  Répartition des nouveaux IOCs par type :")
        for t, count in sorted(types.items(), key=lambda x: -x[1]):
            print(f"    {t:<30} {count}")
    else:
        print("  ✓ Aucun nouvel IOC (tout est déjà en base).")

    save_last_run()
    print(f"\nDonnées sauvegardées dans : {OUTPUT_JSON}")
    print("=" * 60)


if __name__ == "__main__":
    main()
