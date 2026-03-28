import os
import json
import csv
import requests
from datetime import datetime, timezone

# ── Configuration ──────────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

OUTPUT_JSON = os.path.join(SCRIPT_DIR, "openphish_data.json")
TRACKING_CSV = os.path.join(SCRIPT_DIR, "last_run.csv")

# Le flux communautaire d'OpenPhish est un simple fichier texte de plus de 500 URLs bloquées.
FEED_URL = "https://openphish.com/feed.txt"

# ── Helpers ────────────────────────────────────────────────────────────────────
def now_utc_iso():
    return datetime.now(timezone.utc).isoformat()


def load_existing_data():
    if os.path.exists(OUTPUT_JSON):
        try:
            with open(OUTPUT_JSON, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except Exception:
            return []
    return []


def save_data(data):
    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def get_last_run():
    """
    Récupère la date de la dernière extraction depuis last_run.csv.
    """
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
    """
    Puisque OpenPhish n'expose pas de métadonnées temporelles explicites dans le fichier de base,
    on sauvegarde la date à laquelle notre script a été exécuté.
    """
    with open(TRACKING_CSV, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["date_extraction"])
        writer.writerow([dt_iso])


def fetch_openphish_feed():
    """
    Télécharge et parse le flux brut (une URL par ligne).
    """
    response = requests.get(FEED_URL, timeout=30)
    response.raise_for_status()
    urls = []
    
    for line in response.text.splitlines():
        url = line.strip()
        if url:
            urls.append(url)
            
    return urls


def deduplicate_urls(new_urls, existing_items):
    """
    Traite la déduplication et formate les nouvelles entrées (avec OpenPhish on n'a que des URLs).
    Pour un historique complet, s'assure qu'on ne stocke pas la même URL deux fois.
    """
    # Récupérer les URLs qu'on a déjà pour éviter les doublons
    existing_urls = {
        item.get("url")
        for item in existing_items
        if item.get("url")
    }

    filtered = []
    collected_time = now_utc_iso()
    
    for url in new_urls:
        if url not in existing_urls:
            filtered.append({
                "source": "openphish",
                "url": url,
                "first_seen": None,  # OpenPhish ne le fournit pas ici
                "collected_at": collected_time,
                "raw": {}  # pas de données raw supplémentaires
            })

    return filtered


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    print(f"[+] Chargement des données existantes...")
    existing_data = load_existing_data()
    last_run = get_last_run()
    
    if last_run:
        print(f"[i] Extraction incrémentale à partir de : {last_run}")
    else:
        print(f"[i] Aucune exécution précédente (Ou last_run manquant).")

    print(f"[+] Téléchargement du feed depuis {FEED_URL}...")
    try:
        raw_urls = fetch_openphish_feed()
        print(f"[i] {len(raw_urls)} URL(s) récupérées du feed brut.")
    except Exception as e:
        print(f"[-] Erreur de téléchargement : {e}")
        return

    print("[+] Déduplication et filtrage des doublons...")
    new_items = deduplicate_urls(raw_urls, existing_data)

    if len(new_items) > 0:
        print(f"[i] {len(new_items)} nouvelle(s) URL(s) trouvée(s).")
        merged = existing_data + new_items
        save_data(merged)
        print(f"[+] Données ajoutées au fichier: {OUTPUT_JSON}")
        
    else:
        print("[i] Aucun nouvel élément à récupérer.")

    # On met tout de même à jour le last_run (date_extraction) à chaque fois qu'on a checké.
    current_run = now_utc_iso()
    update_last_run(current_run)
    print(f"[+] last_run.csv mis à jour: {current_run}")


if __name__ == "__main__":
    main()
