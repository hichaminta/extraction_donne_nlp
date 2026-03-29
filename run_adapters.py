import os
import json
import logging
from adapters import (
    DgssiAdapter, ThreatfoxAdapter, AbuseipdbAdapter, CinsAdapter,
    MalwarebazaarAdapter, OpenphishAdapter, PhishtankAdapter,
    VirustotalAdapter, NvdAdapter, PulsediveAdapter,
    FeodotrackerAdapter, SpamhausAdapter, OtxAdapter
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
                    # Spamhaus a ses données dans 'iocs'
                    if 'iocs' in data:
                        return data['iocs']
                    # Notre nouveau fichier NVD a ses données dans 'cves'
                    if 'cves' in data:
                        # On retourne la liste des valeurs du dictionnaire
                        return list(data['cves'].values())
                    return [data]
                
                return data if isinstance(data, list) else [data]
    except Exception as e:
        logging.error(f"Erreur lors du chargement de {file_path} : {e}")
        return []

def run_all_adapters():
    """Exécute tous les adapters sur les sources disponibles."""
    
    # Mapping entre fichiers sources et classes d'adapters
    sources_config = [
        {"path": "Cert/dgssi_bulletins.jsonl", "adapter": DgssiAdapter(), "name": "dgssi"},
        {"path": "ThreatFox/threatfox_data.json", "adapter": ThreatfoxAdapter(), "name": "threatfox"},
        {"path": "AbuseIPDB/abuseipdb_data.json", "adapter": AbuseipdbAdapter(), "name": "abuseipdb"},
        {"path": "CINS Army/cins_army.json", "adapter": CinsAdapter(), "name": "cins_army"},
        {"path": "MalwareBazaar Community API/malwarebazaar_data.json", "adapter": MalwarebazaarAdapter(), "name": "malwarebazaar"},
        {"path": "OpenPhish/openphish_data.json", "adapter": OpenphishAdapter(), "name": "openphish"},
        {"path": "PhishTank/verified_online.json", "adapter": PhishtankAdapter(), "name": "phishtank"},
        {"path": "VirusTotal/virustotal_enrichment.json", "adapter": VirustotalAdapter(), "name": "virustotal"},
        {"path": "feodotracker/feodo_data.json", "adapter": FeodotrackerAdapter(), "name": "feodotracker"},
        {"path": "pulsedive/pulsedive_iocs.json", "adapter": PulsediveAdapter(), "name": "pulsedive"},
        {"path": "Spamhaus/spamhaus_data.json", "adapter": SpamhausAdapter(), "name": "spamhaus"},
        {"path": "OTX/pulse_data.json", "adapter": OtxAdapter(), "name": "otx_alienvault"},
        {"path": "Otx alienvault/otx_pulses.json", "adapter": OtxAdapter(), "name": "otx_alienvault"},
        {"path": "nvd_cisa/cve_data_exploited.json", "adapter": NvdAdapter(), "name": "nvd"},
    ]

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
    run_all_adapters()
