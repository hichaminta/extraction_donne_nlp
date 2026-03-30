"""
run_regex_extractor.py
======================
Script d'orchestration optimisé du module RegexExtractor.

Traite les fichiers un par un pour limiter la consommation de mémoire.
Fournit une barre de progression textuelle.
"""

import os
import json
import logging
from regex_extractor import RegexExtractor

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

INPUT_DIR = "output_adapters"
OUTPUT_DIR = "output_regex"

def process_file(extractor, input_path):
    """Charge un fichier et le traite directement."""
    try:
        with open(input_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        items = data if isinstance(data, list) else [data]
        if not items:
            return {"iocs": [], "cves": []}
        
        # Le filtrage des sources est fait à l'intérieur de extractor.process
        return extractor.process(items)
    except Exception as e:
        logging.error("Erreur lors du traitement de %s : %s", input_path, e)
        return {"iocs": [], "cves": []}

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    extractor = RegexExtractor()
    
    all_iocs = []
    all_cves = []
    total_input_count = 0
    
    # Statistiques par source
    ioc_by_source = {}
    cve_by_source = {}
    
    files = sorted([f for f in os.listdir(INPUT_DIR) if f.endswith("_adapter.json")])
    total_files = len(files)
    
    logging.info("Démarrage du traitement de %d fichiers...", total_files)
    
    for i, filename in enumerate(files, 1):
        path = os.path.join(INPUT_DIR, filename)
        logging.info("[%d/%d] Traitement de '%s'...", i, total_files, filename)
        
        results = process_file(extractor, path)
        
        iocs = results["iocs"]
        cves = results["cves"]
        
        all_iocs.extend(iocs)
        all_cves.extend(cves)
        
        # On pourrait compter les inputs ici mais process_file ne les retourne pas.
        # On va juste recharger rapidement la longueur pour les stats.
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                count = len(data) if isinstance(data, list) else 1
                total_input_count += count
        except:
            pass

        # Mise à jour des stats par source pour ce fichier
        for ioc in iocs:
            src = ioc.get("source", "unknown")
            ioc_by_source[src] = ioc_by_source.get(src, 0) + 1
        for cve in cves:
            src = cve.get("source", "unknown")
            cve_by_source[src] = cve_by_source.get(src, 0) + 1
            
        logging.info("   -> %d IOC et %d CVE extraits de ce fichier.", len(iocs), len(cves))

    # Sauvegarder les résultats globaux
    ioc_path = os.path.join(OUTPUT_DIR, "iocs_extracted.json")
    cve_path = os.path.join(OUTPUT_DIR, "cves_extracted.json")
    summary_path = os.path.join(OUTPUT_DIR, "summary.json")

    logging.info("Sauvegarde des résultats finaux (%d IOC, %d CVE)...", len(all_iocs), len(all_cves))
    
    with open(ioc_path, "w", encoding="utf-8") as f:
        json.dump(all_iocs, f, ensure_ascii=False, indent=2)

    with open(cve_path, "w", encoding="utf-8") as f:
        json.dump(all_cves, f, ensure_ascii=False, indent=2)

    summary = {
        "total_input_objects": total_input_count,
        "total_iocs_extracted": len(all_iocs),
        "total_cves_extracted": len(all_cves),
        "iocs_by_source": ioc_by_source,
        "cves_by_source": cve_by_source,
    }

    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    logging.info("Traitement terminé.")
    logging.info("  → IOC : %d (%s)", len(all_iocs), ioc_path)
    logging.info("  → CVE : %d (%s)", len(all_cves), cve_path)
    logging.info("  → Résumé : %s", summary_path)

if __name__ == "__main__":
    main()
