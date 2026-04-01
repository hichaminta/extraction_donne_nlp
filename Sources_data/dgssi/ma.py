# dgssi_scraper.py
# Usage:
#   python ma.py          → récupère seulement les nouveaux bulletins (depuis last run)
#   python ma.py --all    → récupère TOUS les bulletins (historique complet)
# Output: dgssi_bulletins.jsonl

import os
import re
import csv
import json
import time
import argparse
from datetime import datetime
from urllib.parse import urljoin, urlparse, urlencode

import requests
import feedparser
from bs4 import BeautifulSoup


# ---------------------------
# CONFIG
# ---------------------------
DOMAIN   = "dgssi.gov.ma"
BASE     = f"https://{DOMAIN}"

RSS_URL  = f"{BASE}/fr/rss.xml"
LIST_URL = f"{BASE}/fr/bulletins"

# Chemins absolus pour que les fichiers soient dans le même dossier que le script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_JSONL  = os.path.join(SCRIPT_DIR, "dgssi_bulletins.jsonl")
OUT_CSV    = os.path.join(SCRIPT_DIR, "lastrun.csv")   # date du dernier run

UA      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CTI-PFE"
TIMEOUT = (10, 45)   # (connect, read)
SLEEP_BETWEEN = 0.35

# Pagination : nombre de bulletins par page sur dgssi.gov.ma (Joomla par défaut = variable)
# Le script détecte automatiquement la fin de pagination
PAGE_PARAM   = "start"   # paramètre Joomla  ex: ?start=0, ?start=10 ...
PAGE_STEP    = 10        # incrément par page (à ajuster si besoin)
MAX_PAGES    = 500       # sécurité anti-boucle infinie


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
        "Accept":     "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.7",
        "Connection": "keep-alive",
    })
    return s


def _force_https(url: str) -> str:
    return url.replace("http://", "https://")


def fetch_html(session: requests.Session, url: str, max_redirects: int = 5) -> str:
    """
    Fetch HTML robustement :
    - Force HTTPS
    - Désactive auto-redirect
    - Suit les redirects manuellement en upgradant http → https
    """
    url = _force_https(url)

    for _ in range(max_redirects + 1):
        r = session.get(url, timeout=TIMEOUT, allow_redirects=False)

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
        day   = int(m.group(1))
        month = MONTHS[m.group(2).lower()]
        year  = int(m.group(3))
        return datetime(year, month, day).date().isoformat()

    m2 = SLASH_DATE_RE.search(text)
    if m2:
        day   = int(m2.group(1))
        month = int(m2.group(2))
        year  = int(m2.group(3))
        return datetime(year, month, day).date().isoformat()

    return None


def extract_bulletin_links(html: str) -> list[str]:
    """Extrait tous les liens /bulletins/... d'une page de listing."""
    soup = BeautifulSoup(html, "lxml")
    seen  = set()
    links = []

    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if "/bulletins/" not in href:
            continue

        full = urljoin(BASE, href)
        full = _force_https(full)

        if not is_same_domain(full):
            continue
        if full in seen:
            continue

        seen.add(full)
        links.append(full)

    return links


def has_next_page(html: str, current_start: int) -> bool:
    """
    Détecte s'il existe une page suivante dans la pagination Joomla.
    Cherche un lien contenant start=<current_start + PAGE_STEP>.
    """
    next_start = current_start + PAGE_STEP
    return f"start={next_start}" in html


def parse_bulletin(url: str, html: str) -> dict:
    soup  = BeautifulSoup(html, "lxml")
    h1    = soup.find("h1")
    title = h1.get_text(" ", strip=True) if h1 else None

    text     = soup.get_text("\n", strip=True)
    date_iso = parse_date_iso(text)
    cves     = sorted(set(x.upper() for x in CVE_RE.findall(text)))

    pdfs = []
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if href.lower().endswith(".pdf"):
            pdfs.append(_force_https(urljoin(BASE, href)))
    pdfs = sorted(set(pdfs))

    return {
        "source":       "DGSSI",
        "url":          url,
        "title":        title,
        "date":         date_iso,
        "cves":         cves,
        "pdfs":         pdfs,
        "description":  text,           # texte complet (plus de troncature)
        "fetched_at":   datetime.utcnow().isoformat(timespec="seconds") + "Z",
    }


# ---------------------------
# DISCOVERY STRATEGY
# ---------------------------
def discover_urls_via_rss(session: requests.Session) -> list[str]:
    print(f"[+] Try RSS: {RSS_URL}")
    rss_text = fetch_html(session, RSS_URL)
    feed     = feedparser.parse(rss_text)

    urls = []
    seen = set()
    for e in feed.entries:
        link = getattr(e, "link", None)
        if not link:
            continue
        link = _force_https(link)
        if "/bulletins/" not in link or not is_same_domain(link):
            continue
        if link not in seen:
            seen.add(link)
            urls.append(link)

    print(f"[+] RSS URLs: {len(urls)}")
    return urls


def discover_all_urls_via_pagination(session: requests.Session) -> list[str]:
    """
    Parcourt TOUTES les pages du listing /fr/bulletins en utilisant la pagination
    Joomla (?start=0, ?start=10, ?start=20 ...) jusqu'à trouver aucun nouveau lien.
    """
    print(f"[+] Découverte complète via pagination : {LIST_URL}")
    all_links = set()
    page      = 0

    for page_num in range(MAX_PAGES):
        start = page_num * PAGE_STEP
        url   = f"{LIST_URL}?{PAGE_PARAM}={start}" if start > 0 else LIST_URL

        print(f"    Page {page_num + 1:>4}  (start={start:>5})  …", end=" ", flush=True)
        try:
            html  = fetch_html(session, url)
            links = extract_bulletin_links(html)

            # Ne garder que les liens pas encore vus
            new = [l for l in links if l not in all_links]
            print(f"{len(new)} nouveaux liens  (total={len(all_links) + len(new)})")

            if not new:
                # Aucun nouveau lien → fin de pagination
                print(f"[+] Fin de pagination détectée à la page {page_num + 1} (start={start})")
                break

            all_links.update(new)

            # Vérification explicite du lien "page suivante"
            if not has_next_page(html, start):
                print(f"[+] Pas de page suivante détectée → arrêt à page {page_num + 1}")
                break

            time.sleep(SLEEP_BETWEEN)

        except Exception as e:
            print(f"\n[!] Erreur page {page_num + 1} (start={start}): {e}")
            break

    result = sorted(all_links)
    print(f"[+] Total URLs découvertes : {len(result)}")
    return result


# ---------------------------
# LAST RUN HELPERS
# ---------------------------
def read_last_run_date() -> str | None:
    if not os.path.exists(OUT_CSV):
        return None
    with open(OUT_CSV, "r", encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if line:
                return line
    return None


def write_last_run_date(date_str: str):
    with open(OUT_CSV, "w", encoding="utf-8-sig") as f:
        f.write(date_str + "\n")


def load_existing_urls() -> set[str]:
    """Charge les URLs déjà présentes dans le JSONL pour dédupliquer."""
    existing = set()
    if not os.path.exists(OUT_JSONL):
        return existing
    with open(OUT_JSONL, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                url = obj.get("url")
                if url:
                    existing.add(url)
            except Exception:
                pass
    return existing


# ---------------------------
# MAIN
# ---------------------------
def main():
    parser = argparse.ArgumentParser(description="Scraper bulletins DGSSI")
    parser.add_argument(
        "--all", action="store_true",
        help="Récupère TOUS les bulletins (ignore last run, parcourt toutes les pages)"
    )
    args = parser.parse_args()

    session  = get_session()
    today    = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")

    # --- Mode : tout ou incrémental ---
    if args.all:
        print("=" * 60)
        print("[MODE] --all : récupération de TOUS les bulletins DGSSI")
        print("=" * 60)
        last_run = None
    else:
        last_run = read_last_run_date()
        if last_run:
            print(f"[+] Dernier run : {last_run}  → cherche bulletins publiés >= {last_run}")
        else:
            print("[+] Premier run : téléchargement de tous les bulletins disponibles")

    # --- Découverte des URLs ---
    urls = []

    if args.all:
        # Mode complet : pagination entière
        try:
            urls = discover_all_urls_via_pagination(session)
        except Exception as e:
            print(f"[!] Pagination failed: {e}")
    else:
        # Mode incrémental : RSS d'abord, puis liste page 1
        try:
            urls = discover_urls_via_rss(session)
        except Exception as e:
            print(f"[!] RSS failed: {e}")

        if not urls:
            try:
                urls = discover_all_urls_via_pagination(session)
            except Exception as e:
                print(f"[!] Pagination failed: {e}")

    if not urls:
        print("[!] Aucune URL trouvée. Vérifiez le réseau/TLS/Firewall.")
        return

    print(f"[+] URLs à traiter : {len(urls)}")

    # --- Déduplication contre le JSONL existant ---
    existing_urls = load_existing_urls()
    before_dedup  = len(urls)
    urls          = [u for u in urls if u not in existing_urls]
    print(f"[+] Après déduplication : {len(urls)} nouvelles URLs ({before_dedup - len(urls)} déjà présentes)")

    if not urls:
        print("[+] Aucun nouveau bulletin à télécharger.")
        write_last_run_date(today)
        return

    # --- Téléchargement et parsing ---
    jsonl_file = open(OUT_JSONL, "a", encoding="utf-8")
    new_count  = 0
    skipped    = 0

    try:
        for i, url in enumerate(urls, 1):
            try:
                html = fetch_html(session, url)
                data = parse_bulletin(url, html)

                if not data["title"]:
                    data["title"] = url.rsplit("/", 1)[-1]

                bulletin_date = data.get("date") or ""

                # Filtrer par date du dernier run (seulement en mode incrémental)
                if not args.all and last_run and bulletin_date and bulletin_date < last_run:
                    skipped += 1
                    if skipped >= 5:
                        print(f"[+] 5 bulletins anciens consécutifs → arrêt anticipé")
                        break
                    continue
                else:
                    skipped = 0

                jsonl_file.write(json.dumps(data, ensure_ascii=False) + "\n")
                jsonl_file.flush()

                new_count += 1
                if i % 25 == 0 or i == len(urls):
                    print(f"    [{i}/{len(urls)}] {new_count} bulletins sauvegardés")

                time.sleep(SLEEP_BETWEEN)

            except Exception as e:
                print(f"[!] Échec {url}: {e}")
    finally:
        jsonl_file.close()

    write_last_run_date(today)

    print(f"\n{'=' * 60}")
    print(f"[+] Bulletins téléchargés : {new_count}")
    print(f"[+] Fichier JSONL         : {OUT_JSONL}")
    print(f"[+] Dernier run mis à jour: {today}")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()