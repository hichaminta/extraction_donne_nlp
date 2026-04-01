import os
import sys
import json
import logging
from adapters import (
    DgssiAdapter, ThreatfoxAdapter, AbuseipdbAdapter, CinsAdapter,
    MalwarebazaarAdapter, OpenphishAdapter, PhishtankAdapter,
    VirustotalAdapter, NvdAdapter, PulsediveAdapter,
    FeodotrackerAdapter, SpamhausAdapter, OtxAdapter, UrlhausAdapter
)

# Configuration du logging pour voir ce qui se passe
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def load_data(file_path):
    """Charge les données depuis un fichier JSON ou JSONL."""
    if not os.path.exists(file_path):
        logging.warning(f"Fichier non trouvé : {file_path}")
        return []
    
    try:
        if file_path.endswith('.jsonl'):
            with open(file_path, 'r', encoding='utf-8') as f:
                return [json.loads(line) for line in f if line.strip()]
        else:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
                # Gestion des structures par source
                if isinstance(data, dict):
                    if 'iocs' in data:
                        return data['iocs']
                    if 'cves' in data:
                        return list(data['cves'].values())
                    
                    # Cas général d'id mapping (ex: URLHaus)
                    # Si toutes les valeurs sont des listes, on les aplatit
                    first_value = next(iter(data.values())) if data else None
                    if isinstance(first_value, list):
                        all_items = []
                        for val in data.values():
                            if isinstance(val, list):
                                all_items.extend(val)
                            else:
                                all_items.append(val)
                        return all_items
                    
                    return [data]
                
                return data if isinstance(data, list) else [data]
    except Exception as e:
        logging.error(f"Erreur lors du chargement de {file_path} : {e}")
        return []

def run_all_adapters(target_source=None):
    """Exécute tous les adapters sur les sources disponibles."""
    
    # Mapping entre fichiers sources et classes d'adapters
    sources_config = [
        {"path": "Sources_data/dgssi/dgssi_bulletins.jsonl", "adapter": DgssiAdapter(), "name": "dgssi"},
        {"path": "Sources_data/ThreatFox/threatfox_data.json", "adapter": ThreatfoxAdapter(), "name": "threatfox"},
        {"path": "Sources_data/AbuseIPDB/abuseipdb_data.json", "adapter": AbuseipdbAdapter(), "name": "abuseipdb"},
        {"path": "Sources_data/CINS Army/cins_army.json", "adapter": CinsAdapter(), "name": "cins_army"},
        {"path": "Sources_data/MalwareBazaar Community API/malwarebazaar_data.json", "adapter": MalwarebazaarAdapter(), "name": "malwarebazaar"},
        {"path": "Sources_data/OpenPhish/openphish_data.json", "adapter": OpenphishAdapter(), "name": "openphish"},
        {"path": "Sources_data/PhishTank/verified_online.json", "adapter": PhishtankAdapter(), "name": "phishtank"},
        {"path": "Sources_data/VirusTotal/virustotal_enrichment.json", "adapter": VirustotalAdapter(), "name": "virustotal"},
        {"path": "Sources_data/feodotracker/feodo_data.json", "adapter": FeodotrackerAdapter(), "name": "feodotracker"},
        {"path": "Sources_data/pulsedive/pulsedive_iocs.json", "adapter": PulsediveAdapter(), "name": "pulsedive"},
        {"path": "Sources_data/Spamhaus/spamhaus_data.json", "adapter": SpamhausAdapter(), "name": "spamhaus"},
        {"path": "Sources_data/url/urlhaus_full.json", "adapter": UrlhausAdapter(), "name": "urlhaus"},
        # {"path": "Sources_data/Otx alienvault/otx_pulses.json", "adapter": OtxAdapter(), "name": "otx_alienvault"},
        {"path": "Sources_data/nvd_cisa/cve_data_exploited.json", "adapter": NvdAdapter(), "name": "nvd"},
    ]

    # Filtrage si une source spécifique est demandée
    if target_source:
        sources_config = [s for s in sources_config if s["name"] == target_source]
        if not sources_config:
            logging.error(f"Adapter '{target_source}' non trouvé dans la configuration.")
            return

    # Dossier de sortie
    output_dir = "output_adapters"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    for config in sources_config:
        path = config["path"]
        adapter = config["adapter"]
        source_name = config["name"]
        
        logging.info(f"Traitement de {path}...")
        raw_records = load_data(path)
        
        source_data = []
        count_raw = 0
        count_entities = 0
        for record in raw_records:
            count_raw += 1
            try:
                processed_list = adapter.process(record)
                if isinstance(processed_list, list):
                    source_data.extend(processed_list)
                    count_entities += len(processed_list)
            except Exception as e:
                logging.error(f"Erreur adapter sur un record de {path} : {e}")
        
        # Sauvegarde d'un fichier par source
        if source_data:
            output_file = os.path.join(output_dir, f"{source_name}_adapter.json")
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(source_data, f, ensure_ascii=False, indent=2)
            
            logging.info(f"-> {count_raw} records bruts traités | {count_entities} entités sauvegardées dans {output_file}")
        else:
            logging.warning(f"-> Aucune donnée extraite pour {path}")

    logging.info(f"TERMINE : Tous les adapters ont été exécutés. Résultats dans {output_dir}/")

if __name__ == "__main__":
    import sys
    source_to_run = sys.argv[1] if len(sys.argv) > 1 else None
    run_all_adapters(source_to_run)
