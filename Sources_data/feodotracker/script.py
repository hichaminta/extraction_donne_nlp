import os
import csv
import json
import ipaddress
from io import StringIO
from datetime import datetime, timezone

import requests

# =========================================================
# CONFIG
# =========================================================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

OUTPUT_JSON = os.path.join(SCRIPT_DIR, "feodo_data.json")
TRACKING_FILE = os.path.join(SCRIPT_DIR, "last_run.csv")

FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; CTI-Collector/1.0)"
}
TIMEOUT = 30


# =========================================================
# UTILS
# =========================================================
def ensure_dirs():
    pass


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def save_text(path, text):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def is_valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


# =========================================================
# DOWNLOAD
# =========================================================
def download_feed():
    print(f"[+] Download: {FEODO_URL}")
    r = requests.get(FEODO_URL, headers=HEADERS, timeout=TIMEOUT)
    r.raise_for_status()

    return {
        "url": FEODO_URL,
        "downloaded_at": utc_now_iso(),
        "http_status": r.status_code,
        "content_type": r.headers.get("Content-Type"),
        "last_modified": r.headers.get("Last-Modified"),
        "etag": r.headers.get("ETag"),
        "text": r.text
    }


# =========================================================
# PARSE JSON
# =========================================================
def parse_feodo_json(raw_text):
    data = json.loads(raw_text)
    items = []

    if not isinstance(data, list):
        return items

    for idx, row in enumerate(data, start=1):
        first_seen = (row.get("first_seen") or "").strip()
        dst_ip = (row.get("ip_address") or "").strip()
        dst_port = row.get("port")
        c2_status = (row.get("status") or "").strip()
        last_online = (row.get("last_online") or "").strip()
        malware = (row.get("malware") or "").strip()
        
        hostname = (row.get("hostname") or "").strip()
        as_number = row.get("as_number")
        as_name = (row.get("as_name") or "").strip()
        country = (row.get("country") or "").strip()

        if not dst_ip or not is_valid_ip(dst_ip):
            continue

        try:
            ip_obj = ipaddress.ip_address(dst_ip)
            ip_version = ip_obj.version
        except ValueError:
            continue

        try:
            port_value = int(dst_port) if dst_port else None
        except (ValueError, TypeError):
            port_value = None

        item = {
            "source": "feodotracker",
            "source_provider": "abuse.ch",
            "feed_name": "ipblocklist",
            "ioc_type": "ip",
            "ioc_value": dst_ip,
            "ip_version": ip_version,
            "port": port_value,
            "c2_status": c2_status,
            "malware_family": malware,
            "hostname": hostname if hostname else None,
            "as_number": as_number,
            "as_name": as_name if as_name else None,
            "country": country if country else None,
            "first_seen_utc": first_seen if first_seen else None,
            "last_online": last_online if last_online else None,
            "source_url": FEODO_URL,
            "collected_at": utc_now_iso(),
            "raw_row_number": idx
        }
        items.append(item)

    return items


# =========================================================
# DEDUP
# =========================================================
def deduplicate(items):
    seen = set()
    out = []

    for item in items:
        key = (
            item.get("ioc_value"),
            item.get("port"),
            item.get("malware_family"),
            item.get("c2_status")
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(item)

    return out


# =========================================================
# SUMMARY
# =========================================================
def build_summary(items):
    summary = {
        "generated_at": utc_now_iso(),
        "total_items": len(items),
        "online_count": 0,
        "offline_count": 0,
        "by_malware_family": {}
    }

    for item in items:
        status = (item.get("c2_status") or "").lower()
        fam = item.get("malware_family") or "unknown"

        if status == "online":
            summary["online_count"] += 1
        elif status == "offline":
            summary["offline_count"] += 1

        summary["by_malware_family"][fam] = summary["by_malware_family"].get(fam, 0) + 1

    return summary


# =========================================================
# MAIN
# =========================================================
def main():
    ensure_dirs()

    try:
        raw = download_feed()

        # parse + normalize
        items = parse_feodo_json(raw["text"])
        items = deduplicate(items)
        summary = build_summary(items)

        save_json(OUTPUT_JSON, items)

        print(f"[OK] IOC extraits: {len(items)}")
        print(f"Fichier sauvegardé : {OUTPUT_JSON}")
        print(json.dumps(summary, ensure_ascii=False, indent=2))

    except requests.HTTPError as e:
        print(f"[ERROR] HTTP: {e}")
    except requests.RequestException as e:
        print(f"[ERROR] Réseau: {e}")
    except Exception as e:
        print(f"[ERROR] Inattendu: {e}")


if __name__ == "__main__":
    main()