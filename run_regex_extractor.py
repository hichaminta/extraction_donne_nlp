"""
run_regex_extractor.py
======================
Script d'orchestration pour RegexExtractor avec dédoublonnage global unifié.
"""

import os
import json
import logging
from regex_extractor import RegexExtractor

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

INPUT_DIR = "output_adapters"
OUTPUT_DIR = "output_regex"

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    extractor = RegexExtractor()
    
    # Dictionnaires pour déduplication et fusion globale
    # Clé IOC : (value, ioc_type)
    # Clé CVE : cve_id
    all_iocs_dict = {}
    all_cves_dict = {}
    total_input_count = 0
    
    files = sorted([f for f in os.listdir(INPUT_DIR) if f.endswith("_adapter.json")])
    total_files = len(files)
    
    logging.info("Démarrage de l'extraction unifiée pour %d fichiers...", total_files)
    
    for i, filename in enumerate(files, 1):
        path = os.path.join(INPUT_DIR, filename)
        logging.info("[%d/%d] Traitement de '%s'...", i, total_files, filename)
        
        try:
            with open(path, "r", encoding="utf-8") as f:
                items = json.load(f)
            
            if not isinstance(items, list): items = [items]
            total_items = len(items)
            total_input_count += total_items
            for j, item in enumerate(items, 1):
                if j % 1000 == 0:
                    logging.info("  ... %d/%d items traités", j, total_items)
                
                res = extractor.process_single_item(item)
                
                # Fusion des IOC : par 'value' (indépendamment du type)
                for ioc in res["iocs"]:
                    key = ioc["value"]
                    if key in all_iocs_dict:
                        all_iocs_dict[key] = extractor.merge_two_iocs(all_iocs_dict[key], ioc)
                    else:
                        all_iocs_dict[key] = ioc

                # Fusion des CVE : cve_id
                for cve in res["cves"]:
                    cid = cve["cve_id"]
                    if cid in all_cves_dict:
                        all_cves_dict[cid] = extractor.merge_two_cves(all_cves_dict[cid], cve)
                    else:
                        all_cves_dict[cid] = cve
            
            del items
            extractor.extract_iocs_from_text_cached.cache_clear()
            extractor.extract_cves_from_text_cached.cache_clear()
            
        except Exception as e:
            logging.error("Erreur lors du traitement de %s : %s", filename, e)

    # Conversion en listes finales
    all_iocs = list(all_iocs_dict.values())
    all_cves = list(all_cves_dict.values())
    all_iocs_dict.clear()
    all_cves_dict.clear()

    # Sauvegarde
    logging.info("Sauvegarde de %d IOC uniques...", len(all_iocs))
    with open(os.path.join(OUTPUT_DIR, "iocs_extracted.json"), "w", encoding="utf-8") as f:
        json.dump(all_iocs, f, ensure_ascii=False, indent=2)

    logging.info("Sauvegarde de %d CVE uniques...", len(all_cves))
    with open(os.path.join(OUTPUT_DIR, "cves_extracted.json"), "w", encoding="utf-8") as f:
        json.dump(all_cves, f, ensure_ascii=False, indent=2)

    # Summary
    ioc_by_source = {}; cve_by_source = {}
    for ioc in all_iocs:
        for s in ioc.get("sources", []): ioc_by_source[s] = ioc_by_source.get(s, 0) + 1
    for cve in all_cves:
        for s in cve.get("sources", []): cve_by_source[s] = cve_by_source.get(s, 0) + 1

    summary = {
        "total_input_objects": total_input_count,
        "total_unique_iocs": len(all_iocs),
        "total_unique_cves": len(all_cves),
        "iocs_by_source": ioc_by_source,
        "cves_by_source": cve_by_source
    }
    with open(os.path.join(OUTPUT_DIR, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    logging.info("Extraction terminée.")

if __name__ == "__main__":
    main()
