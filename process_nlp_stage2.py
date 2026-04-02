import json
import re
import os
import logging
from collections import defaultdict
from datetime import datetime

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# --- REGEX PATTERNS ---

# IPv4 robuste
IP_REGEX = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'

# URL (gère aussi hxxp et [.] via normalisation préalable)
URL_REGEX = r'https?://[^\s/$.?#].[^\s]*'

# Domaine (basé sur TLDs communs pour éviter trop de bruit)
DOMAIN_REGEX = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'

# Hashes
MD5_REGEX = r'\b[a-fA-F0-9]{32}\b'
SHA1_REGEX = r'\b[a-fA-F0-9]{40}\b'
SHA256_REGEX = r'\b[a-fA-F0-9]{64}\b'

# Heuristiques patterns
ACTOR_REGEX = r'\b(APT\d+|Lazarus|RedFoxtrot|LockBit|Midnight Blizzard|Nocturnal Ice|Kimsuky|Mustang Panda)\b'

# Mots-clés pour les heuristiques
ATTACK_TYPES = {
    "ransomware": ["ransomware", "rançongiciel"],
    "infostealer": ["infostealer", "logiciel espion", "stealer"],
    "rat": ["rat", "remote access trojan", "cheval de troie"],
    "phishing": ["phishing", "hameçonnage", "spear-phishing"]
}

MALWARE_LIST = [
    "3AM", "Aurora Stealer", "DCRat", "Andromeda", "LockBit", "Acreed", 
    "Lumma", "Rhadamanthys", "Cobalt Strike", "Zbot", "Zeus", "Gamarue", 
    "Wauchos", "AnyDesk", "Bashe", "APT73", "AMOS", "Atomic Stealer", 
    "AVrecon", "ChillyHell", "BeaverTail", "InvisibleFerret", "BlackByte", 
    "Mirai", "Corona"
]

VENDORS = [
    "Microsoft", "VMware", "Apple", "Cisco", "Fortinet", "Google", 
    "Apache", "NetApp", "QNAP", "Zimbra", "AMD", "D-Link", "Hikvision", 
    "Netgear", "TP-Link", "Zyxel", "AnyDesk"
]

PLATFORMS = [
    "Windows", "Linux", "macOS", "ESXi", "Android", "iOS", "Unix", "Solaris"
]

# --- FUNCTIONS ---

def load_input_file(path):
    """Charge le fichier JSON de l'étape 1."""
    if not os.path.exists(path):
        logger.error(f"Fichier non trouvé : {path}")
        return []
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Erreur lors du chargement : {e}")
        return []

def normalize_ioc(value):
    """Nettoie et normalise un IOC (defanging)."""
    if not value:
        return value
    # Normalisation du protocole
    value = value.replace('hxxp://', 'http://').replace('hxxps://', 'https://')
    value = value.replace('HXXP://', 'http://').replace('HXXPS://', 'https://')
    # Normalisation des points
    value = value.replace('[.]', '.').replace('(.)', '.').replace('{.}', '.')
    # Suppression de ponctuations parasites à la fin (souvent capturées par regex)
    value = value.rstrip('.,;)]')
    return value.lower() if not value.startswith('http') else value

def extract_ips(text):
    return re.findall(IP_REGEX, text)

def extract_domains(text):
    # Filtrer pour éviter les extensions de fichiers communes comme .pdf, .exe
    domains = re.findall(DOMAIN_REGEX, text)
    filtered = []
    excluded_exts = {'.pdf', '.exe', '.zip', '.txt', '.doc', '.xlsx', '.png', '.jpg'}
    for d in domains:
        if not any(d.lower().endswith(ext) for ext in excluded_exts):
            filtered.append(d)
    return filtered

def extract_urls(text):
    return re.findall(URL_REGEX, text)

def extract_hashes(text):
    hashes = {
        "md5": re.findall(MD5_REGEX, text),
        "sha1": re.findall(SHA1_REGEX, text),
        "sha256": re.findall(SHA256_REGEX, text)
    }
    return hashes

def extract_entities_with_model(text):
    """
    Placeholder pour future intégration NLP (spaCy / CamemBERT / LLM).
    Pour l'instant, ne fait rien.
    """
    return {}

def extract_context_entities(bulletin):
    """Extrait les entités contextuelles par heuristiques simples."""
    text = (bulletin.get("bulletin_title", "") + " " + 
            bulletin.get("description", "") + " " + 
            bulletin.get("raw_text_clean", "")).lower()
    
    context = {
        "malware": [],
        "threat_actor": [],
        "attack_type": [],
        "vendor": [],
        "product": [],
        "platform": []
    }

    # Attack Type
    for atype, keywords in ATTACK_TYPES.items():
        if any(kw in text for kw in keywords):
            context["attack_type"].append(atype)

    # Malware
    for m in MALWARE_LIST:
        if re.search(r'\b' + re.escape(m.lower()) + r'\b', text):
            context["malware"].append(m)

    # Threat Actor
    found_actors = re.findall(ACTOR_REGEX, text, re.IGNORECASE)
    context["threat_actor"] = list(set(found_actors))

    # Vendor
    for v in VENDORS:
        if re.search(r'\b' + re.escape(v.lower()) + r'\b', text):
            context["vendor"].append(v)

    # Product
    # Priorité aux affected_systems déjà extraits au Stage 1
    affected = bulletin.get("affected_systems", [])
    if isinstance(affected, list) and len(affected) > 0:
        context["product"] = affected
    else:
        # Tentative d'extraction simple si vide
        common_products = ["Windows Server", "Office 365", "vCenter", "Exchange Server", "FortiOS"]
        for p in common_products:
            if p.lower() in text:
                context["product"].append(p)

    # Platform
    for p in PLATFORMS:
        if p.lower() in text:
            context["platform"].append(p)

    # Déduplication
    for k in context:
        if isinstance(context[k], list):
            context[k] = list(set(context[k]))

    return context

def build_ioc_object(value, ioc_type, bulletin, context_data):
    """Construit l'objet IOC final."""
    return {
        "type": "ioc",
        "value": value,
        "ioc_type": ioc_type,
        "sources": ["dgssi"],
        "tags": ["dgssi"],
        "confidence": 80,
        "contexts": [
            {
                "bulletin_id": bulletin.get("bulletin_id"),
                "bulletin_title": bulletin.get("bulletin_title"),
                "published_date": bulletin.get("published_date"),
                "url": bulletin.get("url"),
                "product": ", ".join(context_data.get("product", [])),
                "vendor": ", ".join(context_data.get("vendor", [])),
                "malware": context_data.get("malware", []),
                "threat_actor": context_data.get("threat_actor", []),
                "attack_type": context_data.get("attack_type", []),
                "cves": bulletin.get("cves", []),
                "description": bulletin.get("description", "")
            }
        ]
    }

def process_file(input_path, output_path):
    """Fonction principale de traitement."""
    logger.info(f"Démarrage du traitement Stage 2 : {input_path}")
    data = load_input_file(input_path)
    
    if not data:
        logger.warning("Aucune donnée à traiter.")
        return

    # Dictionnaire pour dédoublonner les IOCs : (value, type) -> full_object
    iocs_map = {}
    
    stats = {
        "total_bulletins": len(data),
        "total_iocs": 0,
        "ips": 0,
        "domains": 0,
        "urls": 0,
        "hashes": 0,
        "bulletins_with_malware": 0,
        "bulletins_with_product": 0
    }

    bulletins_processed = 0

    for bulletin in data:
        raw_text = bulletin.get("raw_text_clean", "")
        if not raw_text:
            continue

        bulletins_processed += 1
        
        # 1. Extraction contextuelle (Heuristiques)
        context_data = extract_context_entities(bulletin)
        
        if context_data["malware"]: stats["bulletins_with_malware"] += 1
        if context_data["product"]: stats["bulletins_with_product"] += 1

        # 2. Extraction IOCs (Regex)
        # On nettoie d'abord un peu le texte pour les defangs communs avant l'extraction
        # Mais attention de ne pas casser les regex URL en remplaçant trop tôt.
        # Strategie : extraire puis normaliser individuellement.
        
        ips = extract_ips(raw_text)
        domains = extract_domains(raw_text)
        urls = extract_urls(raw_text)
        hashes = extract_hashes(raw_text)

        # Liste temporaire d'IOCs trouvés dans ce bulletin
        found_in_bulletin = []

        for ip in ips: found_in_bulletin.append((normalize_ioc(ip), "ip"))
        for d in domains: found_in_bulletin.append((normalize_ioc(d), "domain"))
        for u in urls: found_in_bulletin.append((normalize_ioc(u), "url"))
        for h_type, h_list in hashes.items():
            for h in h_list:
                found_in_bulletin.append((h.lower(), h_type))

        # 3. Mise à jour de la map globale
        for val, itype in found_in_bulletin:
            if not val or len(val) < 3: continue
            
            # Eviter les domaines generic comme "dgssi.gov.ma" ou "google.com" si besoin
            if itype == "domain" and val in ["dgssi.gov.ma", "microsoft.com", "google.com"]:
                continue

            key = (val, itype)
            ioc_obj = build_ioc_object(val, itype, bulletin, context_data)
            
            if key not in iocs_map:
                iocs_map[key] = ioc_obj
            else:
                # Si l'IOC existe déjà, on ajoute le nouveau contexte
                # On évite d'ajouter le même bulletin_id deux fois pour le même IOC
                existing_contexts = [ctx["bulletin_id"] for ctx in iocs_map[key]["contexts"]]
                if bulletin.get("bulletin_id") not in existing_contexts:
                    iocs_map[key]["contexts"].append(ioc_obj["contexts"][0])

    # Conversion de la map en liste
    final_output = list(iocs_map.values())
    
    # Update stats
    stats["total_iocs"] = len(final_output)
    for ioc in final_output:
        t = ioc["ioc_type"]
        if t == "ip": stats["ips"] += 1
        elif t == "domain": stats["domains"] += 1
        elif t == "url": stats["urls"] += 1
        elif t in ["md5", "sha1", "sha256"]: stats["hashes"] += 1

    # Sauvegarde JSON
    try:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(final_output, f, indent=2, ensure_ascii=False)
        
        # Sauvegarde Summary
        summary_path = os.path.join(os.path.dirname(output_path), "summary_stage2.json")
        with open(summary_path, 'w', encoding='utf-8') as f:
            json.dump(stats, f, indent=2, ensure_ascii=False)
            
        logger.info(f"Traitement terminé. {len(final_output)} IOCs extraits.")
        logger.info(f"Output : {output_path}")
        logger.info(f"Summary : {summary_path}")
    except Exception as e:
        logger.error(f"Erreur lors de la sauvegarde : {e}")

if __name__ == "__main__":
    INPUT_FILE = "process_nlp/output/dgssi_stage1.json"
    OUTPUT_FILE = "process_nlp/output/dgssi_iocs_stage2.json"
    
    process_file(INPUT_FILE, OUTPUT_FILE)
