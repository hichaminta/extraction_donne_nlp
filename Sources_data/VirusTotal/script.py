import base64
import csv
import json
import os
import re
import time
from datetime import datetime, timezone
from urllib.parse import quote

import requests
from dotenv import load_dotenv, find_dotenv


load_dotenv(find_dotenv(), override=False)

API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
OUTPUT_JSON = os.path.join(SCRIPT_DIR, "virustotal_enrichment.json")
TRACKING_CSV = os.path.join(SCRIPT_DIR, "last_run.csv")
API_BASE_URL = "https://www.virustotal.com/api/v3"
TIMEOUT = 60
MIN_INTERVAL_SECONDS = 15
DEFAULT_MAX_INDICATORS = int(os.getenv("VIRUSTOTAL_MAX_INDICATORS", "20"))

COMMON_KEYS = {
    "indicator",
    "ioc",
    "ip",
    "ipaddress",
    "domain",
    "hostname",
    "host",
    "url",
    "md5",
    "sha1",
    "sha256",
}

IP_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
MD5_PATTERN = re.compile(r"^[A-Fa-f0-9]{32}$")
SHA1_PATTERN = re.compile(r"^[A-Fa-f0-9]{40}$")
SHA256_PATTERN = re.compile(r"^[A-Fa-f0-9]{64}$")
DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$"
)


def load_existing_output() -> list[dict]:
    if not os.path.exists(OUTPUT_JSON):
        return []

    try:
        with open(OUTPUT_JSON, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return []


def save_output(records: list[dict]) -> None:
    with open(OUTPUT_JSON, "w", encoding="utf-8") as handle:
        json.dump(records, handle, ensure_ascii=False, indent=2)


def save_last_run() -> None:
    file_exists = os.path.exists(TRACKING_CSV)
    with open(TRACKING_CSV, "a", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        if not file_exists:
            writer.writerow(["date_extraction"])
        writer.writerow([datetime.now().strftime("%Y-%m-%d %H:%M:%S")])


def is_valid_ipv4(value: str) -> bool:
    if not IP_PATTERN.match(value):
        return False

    parts = value.split(".")
    return all(0 <= int(part) <= 255 for part in parts)


def detect_indicator_type(value: str) -> str | None:
    candidate = value.strip()
    if not candidate:
        return None

    lowered = candidate.lower()

    if lowered.startswith(("http://", "https://")):
        return "url"
    if is_valid_ipv4(candidate):
        return "ip"
    if SHA256_PATTERN.match(candidate):
        return "file"
    if SHA1_PATTERN.match(candidate):
        return "file"
    if MD5_PATTERN.match(candidate):
        return "file"
    if DOMAIN_PATTERN.match(lowered):
        return "domain"

    return None


def iter_json_files(root_dir: str) -> list[str]:
    json_files = []
    for current_root, dirs, files in os.walk(root_dir):
        relative_root = os.path.relpath(current_root, root_dir)
        parts = {part.lower() for part in relative_root.split(os.sep)}

        if "virustotal" in parts or "dashboard" in parts or ".git" in parts:
            continue

        dirs[:] = [d for d in dirs if d.lower() not in {"virustotal", "dashboard", ".git"}]

        for name in files:
            if not name.lower().endswith(".json"):
                continue
            json_files.append(os.path.join(current_root, name))

    return sorted(json_files)


def extract_from_object(obj, file_path: str, results: list[dict]) -> None:
    if isinstance(obj, dict):
        for key, value in obj.items():
            normalized_key = str(key).strip().lower()
            if normalized_key in COMMON_KEYS and isinstance(value, str):
                indicator_type = detect_indicator_type(value)
                if indicator_type:
                    results.append(
                        {
                            "indicator": value.strip(),
                            "indicator_type": indicator_type,
                            "source_file": os.path.relpath(file_path, ROOT_DIR),
                        }
                    )

            extract_from_object(value, file_path, results)
        return

    if isinstance(obj, list):
        for item in obj:
            extract_from_object(item, file_path, results)


def collect_indicators() -> list[dict]:
    candidates = []
    for file_path in iter_json_files(ROOT_DIR):
        try:
            with open(file_path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except Exception:
            continue

        extract_from_object(payload, file_path, candidates)

    unique = []
    seen = set()
    for item in candidates:
        key = (item["indicator_type"], item["indicator"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)

    return unique


def vt_headers() -> dict:
    return {
        "x-apikey": API_KEY,
        "accept": "application/json",
    }


def build_lookup(indicator: str, indicator_type: str) -> tuple[str, str]:
    if indicator_type == "ip":
        return f"{API_BASE_URL}/ip_addresses/{indicator}", indicator
    if indicator_type == "domain":
        return f"{API_BASE_URL}/domains/{indicator}", indicator
    if indicator_type == "file":
        return f"{API_BASE_URL}/files/{indicator}", indicator
    if indicator_type == "url":
        encoded = base64.urlsafe_b64encode(indicator.encode("utf-8")).decode("utf-8").strip("=")
        return f"{API_BASE_URL}/urls/{encoded}", encoded

    raise ValueError(f"Type d'indicateur non supporte: {indicator_type}")


def wait_for_rate_limit(last_request_time: float | None) -> None:
    if last_request_time is None:
        return

    elapsed = time.time() - last_request_time
    remaining = MIN_INTERVAL_SECONDS - elapsed
    if remaining > 0:
        print(f"  -> Attente {remaining:.1f}s pour respecter la limite publique VirusTotal...")
        time.sleep(remaining)


def extract_stats(attributes: dict) -> dict:
    stats = attributes.get("last_analysis_stats", {}) or {}
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "timeout": stats.get("timeout", 0),
    }


def build_gui_url(indicator: str, indicator_type: str, lookup_id: str) -> str:
    if indicator_type == "ip":
        return f"https://www.virustotal.com/gui/ip-address/{quote(indicator, safe='')}"
    if indicator_type == "domain":
        return f"https://www.virustotal.com/gui/domain/{quote(indicator, safe='')}"
    if indicator_type == "file":
        return f"https://www.virustotal.com/gui/file/{quote(indicator, safe='')}"
    if indicator_type == "url":
        return f"https://www.virustotal.com/gui/url/{lookup_id}"
    return "https://www.virustotal.com/gui/home/search"


def normalize_response(candidate: dict, response_json: dict, lookup_id: str) -> dict:
    data = response_json.get("data", {})
    attributes = data.get("attributes", {})

    return {
        "indicator": candidate["indicator"],
        "indicator_type": candidate["indicator_type"],
        "source_file": candidate["source_file"],
        "vt_id": data.get("id"),
        "vt_type": data.get("type"),
        "stats": extract_stats(attributes),
        "reputation": attributes.get("reputation"),
        "last_analysis_date": attributes.get("last_analysis_date"),
        "last_modification_date": attributes.get("last_modification_date"),
        "country": attributes.get("country"),
        "as_owner": attributes.get("as_owner"),
        "tags": attributes.get("tags", []),
        "meaningful_name": attributes.get("meaningful_name"),
        "title": attributes.get("title"),
        "gui_url": build_gui_url(candidate["indicator"], candidate["indicator_type"], lookup_id),
        "enriched_at": datetime.now(timezone.utc).isoformat(),
    }


def enrich_candidates(candidates: list[dict], existing_records: list[dict]) -> list[dict]:
    existing_keys = {
        (record.get("indicator_type"), record.get("indicator"))
        for record in existing_records
    }
    pending = [
        candidate
        for candidate in candidates
        if (candidate["indicator_type"], candidate["indicator"]) not in existing_keys
    ]

    if not pending:
        print("Aucun nouvel indicateur a enrichir.")
        return existing_records

    batch = pending[:DEFAULT_MAX_INDICATORS]
    print(f"{len(batch)} indicateur(s) seront envoyes a VirusTotal sur {len(pending)} en attente.")

    enriched = list(existing_records)
    last_request_time = None

    for index, candidate in enumerate(batch, start=1):
        wait_for_rate_limit(last_request_time)
        url, lookup_id = build_lookup(candidate["indicator"], candidate["indicator_type"])

        print(
            f"[{index}/{len(batch)}] Enrichissement {candidate['indicator_type']} : {candidate['indicator']}"
        )
        try:
            response = requests.get(url, headers=vt_headers(), timeout=TIMEOUT)
            last_request_time = time.time()

            if response.status_code == 401:
                raise RuntimeError("Cle API VirusTotal invalide ou absente.")
            if response.status_code == 429:
                raise RuntimeError(
                    "Limite VirusTotal atteinte. Relancez le script dans quelques minutes."
                )

            response.raise_for_status()
            enriched.append(normalize_response(candidate, response.json(), lookup_id))
        except Exception as exc:
            print(f"  x Echec pour {candidate['indicator']}: {exc}")

    return enriched


def main() -> None:
    print("=" * 60)
    print("VirusTotal Enrichment")
    print("=" * 60)

    if not API_KEY:
        print("[ERREUR] VIRUSTOTAL_API_KEY est vide dans le .env racine.")
        print("Ajoutez votre cle puis relancez ce script.")
        return

    existing_records = load_existing_output()
    print(f"Donnees VirusTotal deja sauvegardees : {len(existing_records)}")

    candidates = collect_indicators()
    print(f"Indicateurs detectes dans les JSON du projet : {len(candidates)}")

    if not candidates:
        print("Aucun indicateur compatible trouve dans les sorties JSON existantes.")
        return

    updated_records = enrich_candidates(candidates, existing_records)
    save_output(updated_records)
    save_last_run()

    print(f"\nSortie sauvegardee dans : {OUTPUT_JSON}")
    print("Conseil: laissez VIRUSTOTAL_MAX_INDICATORS a une valeur basse avec l'API publique.")
    print("=" * 60)


if __name__ == "__main__":
    main()