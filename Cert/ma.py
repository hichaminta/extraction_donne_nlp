# dgssi_scraper.py
# Usage: python dgssi_scraper.py
# Output: dgssi_bulletins.jsonl

import os
import re
import csv
import json
import time
from datetime import datetime
from urllib.parse import urljoin, urlparse

import requests
import feedparser
from bs4 import BeautifulSoup


# ---------------------------
# CONFIG
# ---------------------------
DOMAIN = "dgssi.gov.ma"
BASE = f"https://{DOMAIN}"

RSS_URL = f"{BASE}/fr/rss.xml"
LIST_URL = f"{BASE}/fr/bulletins"

OUT_JSONL      = "dgssi_bulletins.jsonl"
OUT_CSV        = "last_run.csv"   # 1 ligne : date du dernier run


UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CTI-PFE"
TIMEOUT = (10, 45)  # (connect, read)
SLEEP_BETWEEN = 0.35

MAX_ITEMS = 0  # 0 = no limit, else set e.g. 200


# ---------------------------
# REGEX
# ---------------------------
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

FR_DATE_RE = re.compile(
    r"\b(\d{1,2})\s+(janvier|février|fevrier|mars|avril|mai|juin|juillet|août|aout|septembre|octobre|novembre|décembre|decembre)\s+(\d{4})\b",
    re.IGNORECASE,
)
SLASH_DATE_RE = re.compile(r"\b(\d{1,2})/(\d{1,2})/(\d{4})\b")

MONTHS = {
    "janvier": 1,
    "février": 2, "fevrier": 2,
    "mars": 3,
    "avril": 4,
    "mai": 5,
    "juin": 6,
    "juillet": 7,
    "août": 8, "aout": 8,
    "septembre": 9,
    "octobre": 10,
    "novembre": 11,
    "décembre": 12, "decembre": 12,
}


# ---------------------------
# HTTP HELPERS
# ---------------------------
def get_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.7",
        "Connection": "keep-alive",
    })
    return s


def _force_https(url: str) -> str:
    return url.replace("http://", "https://")


def fetch_html(session: requests.Session, url: str, max_redirects: int = 5) -> str:
    """
    Fetch HTML robustly:
    - Force HTTPS
    - Disable auto-redirect
    - Follow redirects manually, upgrading any http:// to https://
    """
    url = _force_https(url)

    for _ in range(max_redirects + 1):
        r = session.get(url, timeout=TIMEOUT, allow_redirects=False)

        # manual redirects
        if 300 <= r.status_code < 400 and "Location" in r.headers:
            loc = r.headers["Location"].strip()
            url = urljoin(url, loc)
            url = _force_https(url)
            continue

        r.raise_for_status()
        return r.text

    raise RuntimeError(f"Too many redirects for: {url}")


def is_same_domain(url: str) -> bool:
    try:
        host = urlparse(url).netloc.lower()
        return host == DOMAIN or host == f"www.{DOMAIN}"
    except Exception:
        return False


# ---------------------------
# PARSING
# ---------------------------
def parse_date_iso(text: str) -> str | None:
    m = FR_DATE_RE.search(text)
    if m:
        day = int(m.group(1))
        month = MONTHS[m.group(2).lower()]
        year = int(m.group(3))
        return datetime(year, month, day).date().isoformat()

    m2 = SLASH_DATE_RE.search(text)
    if m2:
        day = int(m2.group(1))
        month = int(m2.group(2))
        year = int(m2.group(3))
        return datetime(year, month, day).date().isoformat()

    return None


def extract_links_from_list(list_html: str) -> list[str]:
    soup = BeautifulSoup(list_html, "lxml")
    seen = set()
    links = []

    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if "/bulletins/" not in href:
            continue

        full = urljoin(BASE, href)
        full = _force_https(full)

        # Keep only DGSSI domain
        if not is_same_domain(full):
            continue

        if full in seen:
            continue
        seen.add(full)
        links.append(full)

    return links


def parse_bulletin(url: str, html: str) -> dict:
    soup = BeautifulSoup(html, "lxml")
    h1 = soup.find("h1")
    title = h1.get_text(" ", strip=True) if h1 else None

    text = soup.get_text("\n", strip=True)

    # Date best-effort from page text
    date_iso = parse_date_iso(text)

    cves = sorted(set(x.upper() for x in CVE_RE.findall(text)))

    pdfs = []
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if href.lower().endswith(".pdf"):
            pdfs.append(_force_https(urljoin(BASE, href)))
    pdfs = sorted(set(pdfs))

    return {
        "source": "DGSSI",
        "url": url,
        "title": title,
        "date": date_iso,
        "cves": cves,
        "pdfs": pdfs,
        "raw_text_sample": text[:1500],
        "fetched_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
    }


# ---------------------------
# DISCOVERY STRATEGY
# ---------------------------
def discover_urls_via_rss(session: requests.Session) -> list[str]:
    print(f"[+] Try RSS: {RSS_URL}")
    rss_text = fetch_html(session, RSS_URL)  # rss is also text/xml
    feed = feedparser.parse(rss_text)

    urls = []
    seen = set()

    for e in feed.entries:
        link = getattr(e, "link", None)
        if not link:
            continue
        link = _force_https(link)
        if "/bulletins/" not in link:
            continue
        if not is_same_domain(link):
            continue
        if link in seen:
            continue
        seen.add(link)
        urls.append(link)

    print(f"[+] RSS URLs: {len(urls)}")
    return urls


def discover_urls_via_list(session: requests.Session) -> list[str]:
    print(f"[+] Try LIST: {LIST_URL}")
    list_html = fetch_html(session, LIST_URL)
    urls = extract_links_from_list(list_html)
    print(f"[+] LIST URLs: {len(urls)}")
    return urls


def read_last_run_date() -> str | None:
    """Lit last_run.csv et retourne la date du dernier run (YYYY-MM-DD) ou None."""
    if not os.path.exists(OUT_CSV):
        return None
    with open(OUT_CSV, "r", encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if line:
                return line  # première ligne non vide = la date
    return None


def write_last_run_date(date_str: str):
    """Sauvegarde la date du run dans last_run.csv (écrase)."""
    with open(OUT_CSV, "w", encoding="utf-8-sig") as f:
        f.write(date_str + "\n")


# ---------------------------
# MAIN
# ---------------------------
def main():
    session = get_session()

    # --- Lire la date du dernier run ---
    last_run = read_last_run_date()
    today    = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")  # YYYY-MM-DDTHH:MM:SS

    if last_run:
        print(f"[+] Dernier run : {last_run}  → cherche bulletins publiés >= {last_run}")
    else:
        print("[+] Premier run : téléchargement de tous les bulletins disponibles")

    # --- Découverte des URLs ---
    urls = []
    try:
        urls = discover_urls_via_rss(session)
    except Exception as e:
        print(f"[!] RSS failed: {e}")

    if not urls:
        try:
            urls = discover_urls_via_list(session)
        except Exception as e:
            print(f"[!] LIST failed: {e}")

    if not urls:
        print("[!] Aucune URL trouvée. Vérifiez le réseau/TLS/Firewall.")
        return

    if MAX_ITEMS and len(urls) > MAX_ITEMS:
        urls = urls[:MAX_ITEMS]

    print(f"[+] URLs trouvées : {len(urls)}")

    jsonl_file = open(OUT_JSONL, "a", encoding="utf-8")

    new_count = 0
    skipped   = 0

    try:
        for i, url in enumerate(urls, 1):
            try:
                html = fetch_html(session, url)
                data = parse_bulletin(url, html)

                if not data["title"]:
                    data["title"] = url.rsplit("/", 1)[-1]

                bulletin_date = data.get("date") or ""

                # Filtrer par date du dernier run
                if last_run and bulletin_date and bulletin_date < last_run:
                    skipped += 1
                    if skipped >= 5:
                        print(f"[+] 5 bulletins anciens consécutifs → arrêt anticipé")
                        break
                    continue
                else:
                    skipped = 0

                # Écrire dans JSONL (données complètes)
                jsonl_file.write(json.dumps(data, ensure_ascii=False) + "\n")
                jsonl_file.flush()

                new_count += 1
                if new_count % 25 == 0:
                    print(f"    ... {new_count} bulletins sauvegardés")

                time.sleep(SLEEP_BETWEEN)

            except Exception as e:
                print(f"[!] Échec {url}: {e}")
    finally:
        jsonl_file.close()

    # --- Mettre à jour last_run.csv avec la date d'aujourd'hui ---
    write_last_run_date(today)

    print(f"\n[+] Bulletins nouveaux   : {new_count}")
    print(f"[+] JSONL                 : {OUT_JSONL}  ← toutes les données")
    print(f"[+] Dernier run mis à jour: {OUT_CSV}  ({today})")


if __name__ == "__main__":
    main()