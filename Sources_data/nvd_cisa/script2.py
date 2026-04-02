import requests
import json
import time
import os
import csv
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv, find_dotenv

BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
load_dotenv(find_dotenv())
API_KEY = os.getenv("NVD_API_KEY")
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TRACKING_FILE = os.path.join(SCRIPT_DIR, "last_run.csv")
OUTPUT_JSON = os.path.join(SCRIPT_DIR, "cve_data.json")

def get_last_run_date():
    """Récupère la date de la dernière extraction depuis le fichier CSV."""
    if os.path.exists(TRACKING_FILE):
        with open(TRACKING_FILE, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            # Récupérer les lignes non vides, en ignorant un potentiel en-tête
            rows = [row for row in reader if row and len(row) > 0]
            if rows:
                if rows[0][0] == "date_extraction":
                    if len(rows) > 1:
                        return rows[-1][0]
                    else:
                        return None
                return rows[-1][0]
    return None

def save_last_run_date(date_str):
    """Sauvegarde la date de l'extraction actuelle dans le fichier CSV."""
    with open(TRACKING_FILE, "a", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([date_str])

def fetch_cves(params, retries=3):
    headers = {"apiKey": API_KEY} if API_KEY else {}
    for i in range(retries):
        try:
            r = requests.get(BASE, params=params, headers=headers, timeout=60)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            if i == retries - 1:
                raise e
            print(f"Erreur lors de la requête, tentative {i+1}/{retries}... ({e})")
            time.sleep(2)

def extract_cvss_list(vulnerability):
    """Extrait toutes les métriques CVSS de la vulnérabilité."""
    metrics = vulnerability.get("cve", {}).get("metrics", {})
    cvss_list = []
    
    # Récupérer CVSS 3.1 ou 3.0
    if "cvssMetricV31" in metrics:
        cvss = metrics["cvssMetricV31"][0].get("cvssData", {})
        cvss_list.append({
            "version": "3.1",
            "score": cvss.get("baseScore", "N/A"),
            "vector": cvss.get("vectorString", "N/A")
        })
    elif "cvssMetricV30" in metrics:
        cvss = metrics["cvssMetricV30"][0].get("cvssData", {})
        cvss_list.append({
            "version": "3.0",
            "score": cvss.get("baseScore", "N/A"),
            "vector": cvss.get("vectorString", "N/A")
        })
    
    # Récupérer CVSS 2.0
    if "cvssMetricV2" in metrics:
        cvss = metrics["cvssMetricV2"][0].get("cvssData", {})
        cvss_list.append({
            "version": "2.0",
            "score": cvss.get("baseScore", "N/A"),
            "vector": cvss.get("vectorString", "N/A")
        })
        
    return cvss_list

def load_existing_json():
    """Charge les résultats existants si le fichier JSON existe, sinon retourne la structure de base."""
    if os.path.exists(OUTPUT_JSON):
        try:
            with open(OUTPUT_JSON, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict) and "cves" in data:
                    return data
        except Exception as e:
            print(f"Erreur lors du chargement de {OUTPUT_JSON} : {e}")
            
    return {"metadata": {"total_cves": 0, "generated_at": "", "source_file": OUTPUT_JSON}, "cves": {}}

def extract_all(limit=None):
    new_extracted_data = []
    start_index = 0
    results_per_page = 500
    
    last_date = get_last_run_date()
    # Utilisation du paramètre UTC recommandé par l'API NVD
    now = datetime.now(timezone.utc)
    now_str = now.strftime("%Y-%m-%dT%H:%M:%S.000")
    
    params = {
        "resultsPerPage": results_per_page,
        "startIndex": start_index
    }
    
    if last_date:
        print(f"Extraction incrémentale à partir de : {last_date}")
        params["lastModStartDate"] = last_date
        params["lastModEndDate"] = now_str
    else:
        print("Aucune date précédente trouvée dans last_run.csv.")
        print("Pour éviter d'extraire toutes les données depuis le début, on utilise une date par défaut (les 7 derniers jours).")
        default_start = now - timedelta(days=7)
        params["lastModStartDate"] = default_start.strftime("%Y-%m-%dT%H:%M:%S.000")
        params["lastModEndDate"] = now_str

    print("Début de l'extraction...")
    
    total_processed = 0
    while True:
        params["startIndex"] = start_index
        try:
            data = fetch_cves(params)
        except Exception as e:
            print(f"Échec critique : {e}")
            break
            
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            break
            
        for vuln in vulnerabilities:
            cve = vuln.get("cve", {})
            cve_id = cve.get("id")
            published = cve.get("published")
            source = cve.get("sourceIdentifier", "N/A")
            
            # Extraction de la description en anglais
            description = "N/A"
            descriptions = cve.get("descriptions", [])
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "N/A")
                    break
            
            cvss_info = extract_cvss_list(vuln)
            
            if cvss_info:
                new_extracted_data.append({
                    "cve_id": cve_id,
                    "published": published,
                    "source": source,
                    "description": description,
                    "cvss": cvss_info
                })
            
            total_processed += 1
            if limit and total_processed >= limit:
                break
        
        total_results = data.get("totalResults", 0)
        print(f"Processed: {total_processed} / {total_results} | New CVSS Extracted: {len(new_extracted_data)}")
        
        if total_processed >= total_results or (limit and total_processed >= limit):
            break
            
        start_index += results_per_page
        time.sleep(0.6)
        
    # Fusion avec les données existantes
    existing_data_dict = load_existing_json()
    cves_dict = existing_data_dict.get("cves", {})
    
    for new_item in new_extracted_data:
        # Met à jour ou ajoute le CVE
        cves_dict[new_item["cve_id"]] = new_item
        
    # Mise à jour des métadonnées
    existing_data_dict["cves"] = cves_dict
    existing_data_dict["metadata"]["total_cves"] = len(cves_dict)
    existing_data_dict["metadata"]["generated_at"] = now_str
    
    # Sauvegarde finale en JSON
    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(existing_data_dict, f, indent=2, ensure_ascii=False)
    
    # Sauvegarde de la date pour la prochaine fois
    save_last_run_date(now_str)
    
    print(f"\nExtraction terminée ! Total {len(cves_dict)} entrées CVSS sauvegardées dans {OUTPUT_JSON}")

if __name__ == "__main__":
    try:
        # Extraction complète sans limite
        extract_all() 
    except Exception as e:
        print(f"Erreur globale : {e}")
