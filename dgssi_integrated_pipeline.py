import json
import re
import logging
from typing import Dict, Any, List, Set, Tuple
from pathlib import Path
try:
    import spacy
except ImportError:
    spacy = None
from tqdm import tqdm
import copy
from urllib.parse import urlparse

# -----------------------------
# Configuration & Logging
# -----------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

INPUT_FILE = "process_nlp/output/dgssi_stage1.json"
OUTPUT_DIR = "output_final"
OUTPUT_FILE = f"{OUTPUT_DIR}/dgssi_cti_final.json"
SPACY_MODEL = "fr_core_news_md"

# -----------------------------
# Regex Patterns (IOCs & CVEs)
# -----------------------------
_IPV4_BASE = r"(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)"
_IP_WITH_PORT = re.compile(f"\\b({_IPV4_BASE})(?::([0-9]{{1,5}}))?\\b")
_URL = re.compile(r"(?:https?|ftp)://[^\s\"'<>\]\[}{|\\^`]{3,}")
_DOMAIN = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|gov|edu|mil|int|info|biz|mobi|name|museum|co|de|fr|uk|us|ru|cn|jp|br|in|ma|eu|be|nl|es|it|pl|se|ch|au|ca|nz|sg|hk|za|ar|mx|tr|ua|ro|cz|hu|gr|fi|no|dk|pt|at|onion|xyz|top|app|dev|cloud|site|tech|club|shop|online|pro|click|stream|zip|mov|review|cc|pw|me|top|icu|bit|info|live|bid)\b", re.IGNORECASE)
_EMAIL = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")
_MD5 = re.compile(r"\b[0-9a-fA-F]{32}\b")
_SHA1 = re.compile(r"\b[0-9a-fA-F]{40}\b")
_SHA256 = re.compile(r"\b[0-9a-fA-F]{64}\b")
_CVE_PAT = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)

# -----------------------------
# CTI NLP Knowledge Base
# -----------------------------
NOISE_PATTERNS = [
    r"main navigation", r"événements\s+bulletins de sécurité", r"niveau de risque",
    r"niveau d'impact", r"numéro de référence", r"date de publication",
    r"indices? de compromission", r"indicateurs? de compromission", r"brochure",
    r"titre", r"accueil", r"présentation", r"documents", r"formulaires", r"contacts",
]

MALWARE_TERMS = {
    "ransomware": "ransomware", "rançongiciel": "ransomware", "trojan": "trojan",
    "cheval de troie": "trojan", "rat": "rat", "backdoor": "backdoor",
    "botnet": "botnet", "infostealer": "infostealer", "stealer": "infostealer",
    "spyware": "spyware", "logiciel espion": "spyware", "worm": "worm",
    "ver": "worm", "rootkit": "rootkit", "loader": "loader",
    "downloader": "downloader", "dropper": "dropper", "keylogger": "keylogger",
    "virus": "virus",
}

ATTACK_TYPE_PATTERNS = {
    "phishing": [r"\bphishing\b", r"hameçonnage", r"spear[\s-]?phishing"],
    "ransomware": [r"\bransomware\b", r"rançongiciel"],
    "infostealer": [r"\binfostealer\b", r"voleur de données", r"stealer"],
    "malvertising": [r"\bmalvertising\b", r"publicité malveillante"],
    "supply_chain": [r"supply chain", r"chaîne d'approvisionnement"],
    "credential_theft": [r"vol d'identifiants", r"vol de mots de passe"],
    "bruteforce": [r"brute force", r"force brute"],
    "rce": [r"\brce\b", r"exécution de code à distance", r"remote code execution"],
    "lateral_movement": [r"mouvement latéral", r"mouvements latéraux"],
    "persistence": [r"persistance"],
    "social_engineering": [r"ingénierie sociale"],
    "ddos": [r"\bddos\b", r"déni de service distribué"],
}

PLATFORM_PATTERNS = {
    "Windows": [r"\bwindows\b"], "Linux": [r"\blinux\b"], "macOS": [r"\bmacos\b", r"\bmac os\b"],
    "Android": [r"\bandroid\b"], "iOS": [r"\bios\b"], "ESXi": [r"\besxi\b"],
    "VMware": [r"\bvmware\b"], "IoT": [r"\biot\b", r"internet of things"],
    "M365": [r"microsoft 365", r"\bm365\b", r"\boffice 365\b"],
}

IMPACT_PATTERNS = {
    "exécution de code": [r"exécution de code", r"code arbitraire", r"remote code execution", r"\brce\b"],
    "déni de service": [r"déni de service", r"\bddos\b"],
    "élévation de privilèges": [r"élévation de privilèges", r"privilèges élevés"],
    "exfiltration": [r"exfiltration", r"données volées", r"vol de données"],
    "chiffrement": [r"chiffrement", r"fichiers chiffrés", r"rançon"],
    "persistance": [r"persistance"],
    "accès non autorisé": [r"accès non autorisé", r"prise de contrôle", r"contrôle complet"],
}

RECOMMENDATION_PATTERNS = [
    r"il est recommandé de[^.:\n]*", r"il est fortement recommandé de[^.:\n]*",
    r"le macert recommande de[^.:\n]*", r"la dgssi recommande de[^.:\n]*",
    r"mettre à jour[^.:\n]*", r"appliquer les correctifs[^.:\n]*",
    r"surveiller les journaux[^.:\n]*", r"activer l'authentification multi[\s-]?facteurs[^.:\n]*",
    r"restreindre l'accès[^.:\n]*", r"intégrer les indicateurs de compromission[^.:\n]*",
]

# -----------------------------
# Extraction Engine
# -----------------------------
class IntegratedExtractor:
    def __init__(self, nlp_model=None):
        self.nlp = nlp_model
        self.known_vendors = {
            "microsoft", "apple", "google", "oracle", "vmware", "broadcom", "qnap", "fortinet",
            "palo alto networks", "sonicwall", "jetbrains", "netapp", "adobe", "mongodb",
            "fortra", "zimbra", "hpe", "hewlett packard enterprise", "samsung", "amazon",
            "aws", "cisco", "barracuda", "zoho", "manageengine"
        }
        self.product_keywords = [
            "server", "vpn", "sharepoint", "exchange", "vcenter", "cloud", "office", "windows",
            "linux", "macos", "android", "ios", "misp", "mongodb", "teamcity", "solarwinds",
            "react native", "metro", "magento", "globalprotect", "pan-os", "fortios", "ssl vpn",
            "netbak", "word", "ssh", "office 2016", "office 2019", "exchange server"
        ]

    def normalize_whitespace(self, text: str) -> str:
        return re.sub(r"\s+", " ", text).strip()

    def is_noise_entity(self, value: str) -> bool:
        if not value: return True
        v = self.normalize_whitespace(value)
        v_lower = v.lower()
        if len(v) < 3: return True
        for pattern in NOISE_PATTERNS:
            if re.search(pattern, v_lower): return True
        if re.fullmatch(r"[\W_]+", v) or re.fullmatch(r"\d+", v): return True
        if re.search(r"https?://|www\.|@", v_lower): return True
        if re.fullmatch(r"[a-fA-F0-9]{32,128}", v): return True
        return False

    def clean_text_for_nlp(self, text: str) -> str:
        if not text: return ""
        cleaned = re.sub(r"https?://\S+", " ", text)
        cleaned = re.sub(r"\b[\w\.-]+@[\w\.-]+\.\w+\b", " ", cleaned)
        cleaned = re.sub(r"[_•·]+", " ", cleaned)
        return self.normalize_whitespace(cleaned)

    def extract_regex_iocs(self, text: str) -> List[Dict[str, Any]]:
        found = []
        seen = set()

        def _add(v, t, p=None):
            v_s = v.strip()
            v_low = v_s.lower()
            if v_low in ("localhost", "127.0.0.1", "127.1", "0.0.0.0"): return
            
            if "://" in v_low:
                try:
                    parsed = urlparse(v_s.rstrip(").,"))
                    host = (parsed.hostname or "").lower()
                    if not host or host in ("localhost", "127.0.0.1", "example.com"): return
                except: pass

            if t == "domain": v_s = v_s.lower()
            if (v_s, t) not in seen:
                seen.add((v_s, t))
                ioc = {"value": v_s, "ioc_type": t}
                if p: ioc["ports"] = [p]
                found.append(ioc)

        for m in _URL.finditer(text): _add(m.group(), "url")
        for m in _EMAIL.finditer(text): _add(m.group(), "email")
        for m in _IP_WITH_PORT.finditer(text): _add(m.group(1), "ip", m.group(2))
        for m in _SHA256.finditer(text): _add(m.group(), "sha256")
        for m in _SHA1.finditer(text): _add(m.group(), "sha1")
        for m in _MD5.finditer(text): _add(m.group(), "md5")
        for m in _DOMAIN.finditer(text): _add(m.group(), "domain")
        
        return found

    def extract_regex_cves(self, text: str) -> Set[str]:
        return {m.group().upper() for m in _CVE_PAT.finditer(text)}

    def extract_nlp_context(self, text: str) -> Dict[str, List[str]]:
        entities = {
            "malware": [], "threat_actor": [], "vendor": [], "product": [],
            "attack_type": [], "platform": [], "impact": [], "recommendations": []
        }
        if not text: return entities

        clean_text = self.clean_text_for_nlp(text)
        text_lower = clean_text.lower()

        # Rule-based CTI
        for term, norm in MALWARE_TERMS.items():
            if re.search(rf"(?<!\w){re.escape(term)}(?!\w)", text_lower):
                entities["malware"].append(norm)
        
        for key, regs in ATTACK_TYPE_PATTERNS.items():
            if any(re.search(r, text_lower) for r in regs): entities["attack_type"].append(key)
        for key, regs in PLATFORM_PATTERNS.items():
            if any(re.search(r, text_lower) for r in regs): entities["platform"].append(key)
        for key, regs in IMPACT_PATTERNS.items():
            if any(re.search(r, text_lower) for r in regs): entities["impact"].append(key)
        
        for pat in RECOMMENDATION_PATTERNS:
            for m in re.findall(pat, clean_text, flags=re.IGNORECASE):
                rec = self.normalize_whitespace(m)
                if len(rec) > 10: entities["recommendations"].append(rec)

        # Regex-based CTI names
        for match in re.findall(r"\b(?:Lumma|Aurora|LockBit|APT[\s-]?\d+|Bashe)\b", clean_text, flags=re.IGNORECASE):
            val = self.normalize_whitespace(match)
            if "APT" in val.upper() or val.lower() == "bashe": entities["threat_actor"].append(val)
            else: entities["malware"].append(val)

        # spaCy NER
        if self.nlp:
            doc = self.nlp(clean_text[:100000]) # Limit length for safety
            for ent in doc.ents:
                val = self.normalize_whitespace(ent.text)
                if self.is_noise_entity(val): continue
                val_low = val.lower()
                
                if ent.label_ == "ORG":
                    if val_low in self.known_vendors: entities["vendor"].append(val)
                    else: entities["vendor"].append(val)
                elif ent.label_ in ("MISC", "PROD"):
                    entities["product"].append(val)

        # Final cleaning & dedup
        for k in entities:
            entities[k] = sorted(list(set(entities[k])))
        return entities

# -----------------------------
# Pipeline Integrator
# -----------------------------
def run_pipeline():
    logging.info("Démarrage du pipeline CTI DGSSI...")
    
    # Check paths
    input_path = Path(INPUT_FILE)
    if not input_path.exists():
        logging.error(f"Fichier d'entrée introuvable : {INPUT_FILE}")
        return

    # Load spaCy
    nlp = None
    if spacy:
        try:
            nlp = spacy.load(SPACY_MODEL)
            logging.info(f"Modèle NLP '{SPACY_MODEL}' chargé.")
        except Exception as e:
            logging.warning(f"Impossible de charger spaCy : {e}. Le script fonctionnera en mode rule-based.")
    else:
        logging.warning("spaCy n'est pas installé ou incompatible. Le script fonctionnera en mode rule-based.")

    extractor = IntegratedExtractor(nlp)
    
    # Load Stage 1
    with open(input_path, "r", encoding="utf-8") as f:
        bulletins = json.load(f)
    
    logging.info(f"Traitement de {len(bulletins)} bulletins...")
    
    global_iocs = {} # (ioc_type, value) -> object
    global_cves = {} # cve_id -> object

    for b in tqdm(bulletins, desc="Processing Bulletins"):
        # 1. Prepare Text
        title = b.get("bulletin_title", "")
        desc = b.get("description", "")
        raw = b.get("raw_text_clean", "")
        full_text = f"{title}\n{desc}\n{raw}"
        
        # 2. Extract NLP Context
        context = extractor.extract_nlp_context(full_text)
        
        # Context object used as template for linking
        bulletin_metadata = {
            "source": b.get("source", "dgssi"),
            "bulletin_id": b.get("bulletin_id", ""),
            "bulletin_title": title,
            "published_date": b.get("published_date", ""),
            "url": b.get("url", ""),
            "description": desc,
            **context # Inject nlp entities directly at root level of context as per requested format
        }

        # 3. Extract IOCs
        iocs = extractor.extract_regex_iocs(full_text)
        for ioc in iocs:
            key = (ioc["ioc_type"], ioc["value"])
            if key not in global_iocs:
                global_iocs[key] = {
                    "type": "ioc",
                    "value": ioc["value"],
                    "ioc_type": ioc["ioc_type"],
                    "ports": ioc.get("ports"),
                    "sources": ["dgssi"],
                    "tags": [],
                    "first_seen": b.get("published_date"),
                    "last_seen": b.get("published_date"),
                    "confidence": None,
                    "contexts": []
                }
            if bulletin_metadata not in global_iocs[key]["contexts"]:
                global_iocs[key]["contexts"].append(bulletin_metadata)
            
            # Merge ports if IP
            if ioc["ioc_type"] == "ip" and ioc.get("ports"):
                p_list = list(set((global_iocs[key].get("ports") or []) + ioc["ports"]))
                global_iocs[key]["ports"] = sorted(p_list)

        # 4. Extract CVEs
        cve_ids = extractor.extract_regex_cves(full_text)
        field_cves = b.get("cves", [])
        if isinstance(field_cves, list):
            for c in field_cves: cve_ids.add(c.upper())
            
        for cid in cve_ids:
            if cid not in global_cves:
                global_cves[cid] = {
                    "type": "cve",
                    "cve_id": cid,
                    "sources": ["dgssi"],
                    "published_date": b.get("published_date"),
                    "description": None, # Will be filled by context if possible
                    "contexts": []
                }
            if bulletin_metadata not in global_cves[cid]["contexts"]:
                global_cves[cid]["contexts"].append(bulletin_metadata)

    # Convert to list and final dedup (sources/dates)
    final_results = sorted(list(global_iocs.values()), key=lambda x: (x["ioc_type"], x["value"]))
    final_results += sorted(list(global_cves.values()), key=lambda x: x["cve_id"])

    # Output
    output_dir = Path(OUTPUT_DIR)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(final_results, f, indent=4, ensure_ascii=False)
    
    logging.info(f"Pipeline terminé. {len(final_results)} objets CTI sauvegardés dans {OUTPUT_FILE}")

if __name__ == "__main__":
    run_pipeline()
