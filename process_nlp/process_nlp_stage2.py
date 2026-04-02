import json
import logging
import re
from typing import Dict, Any, List, Set
from pathlib import Path
import spacy
from tqdm import tqdm

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


# -----------------------------
# Helpers généraux
# -----------------------------
NOISE_PATTERNS = [
    r"main navigation",
    r"événements\s+bulletins de sécurité",
    r"niveau de risque",
    r"niveau d'impact",
    r"numéro de référence",
    r"date de publication",
    r"indices? de compromission",
    r"indicateurs? de compromission",
    r"brochure",
    r"titre",
    r"accueil",
    r"présentation",
    r"documents",
    r"formulaires",
    r"contacts",
]

MALWARE_TERMS = {
    "ransomware": "ransomware",
    "rançongiciel": "ransomware",
    "trojan": "trojan",
    "cheval de troie": "trojan",
    "rat": "rat",
    "backdoor": "backdoor",
    "botnet": "botnet",
    "infostealer": "infostealer",
    "stealer": "infostealer",
    "spyware": "spyware",
    "logiciel espion": "spyware",
    "worm": "worm",
    "ver": "worm",
    "rootkit": "rootkit",
    "loader": "loader",
    "downloader": "downloader",
    "dropper": "dropper",
    "keylogger": "keylogger",
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
    "Windows": [r"\bwindows\b"],
    "Linux": [r"\blinux\b"],
    "macOS": [r"\bmacos\b", r"\bmac os\b"],
    "Android": [r"\bandroid\b"],
    "iOS": [r"\bios\b"],
    "ESXi": [r"\besxi\b"],
    "VMware": [r"\bvmware\b"],
    "IoT": [r"\biot\b", r"internet of things"],
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
    r"il est recommandé de[^.:\n]*",
    r"il est fortement recommandé de[^.:\n]*",
    r"le macert recommande de[^.:\n]*",
    r"la dgssi recommande de[^.:\n]*",
    r"mettre à jour[^.:\n]*",
    r"appliquer les correctifs[^.:\n]*",
    r"surveiller les journaux[^.:\n]*",
    r"activer l'authentification multi[\s-]?facteurs[^.:\n]*",
    r"restreindre l'accès[^.:\n]*",
    r"intégrer les indicateurs de compromission[^.:\n]*",
]


# -----------------------------
# Chargement
# -----------------------------
def load_input_file(path: str) -> List[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            logging.info("Chargement réussi de %s bulletins depuis %s.", len(data), path)
            return data
    except Exception as e:
        logging.error("Erreur lors du chargement de %s: %s", path, e)
        return []


def load_nlp_model() -> spacy.language.Language:
    try:
        nlp = spacy.load("fr_core_news_md")
        logging.info("Modèle NLP 'fr_core_news_md' chargé avec succès.")
        return nlp
    except OSError:
        logging.error("Modèle introuvable. Installe-le avec : python -m spacy download fr_core_news_md")
        raise


# -----------------------------
# Nettoyage
# -----------------------------
def normalize_whitespace(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def is_noise_entity(value: str) -> bool:
    if not value:
        return True

    v = normalize_whitespace(value)
    v_lower = v.lower()

    if len(v) < 3:
        return True

    # Bruit de navigation / PDF / page DGSSI
    for pattern in NOISE_PATTERNS:
        if re.search(pattern, v_lower):
            return True

    # Trop de symboles ou numérique pur
    if re.fullmatch(r"[\W_]+", v):
        return True
    if re.fullmatch(r"\d+", v):
        return True

    # URLs, emails, chemins et hash dans les entités sémantiques
    if re.search(r"https?://|www\.|@", v_lower):
        return True
    if re.fullmatch(r"[a-fA-F0-9]{32,128}", v):
        return True
    if "\\" in v or "/" in v and len(v.split()) <= 2:
        return True

    # Champs typiques parasites
    blacklist = {
        "titre",
        "brochure",
        "solution",
        "recommandations",
        "bulletin",
        "dgssi",
        "macert",
        "niveau de risque",
        "niveau d'impact",
        "date de publication",
        "numéro de référence",
        "iocs",
        "hashs",
        "indices de compromission",
        "indicateurs de compromission",
    }
    if v_lower in blacklist:
        return True

    return False


def clean_text_for_nlp(text: str) -> str:
    if not text:
        return ""

    cleaned = text

    # supprimer URLs / emails
    cleaned = re.sub(r"https?://\S+", " ", cleaned)
    cleaned = re.sub(r"\b[\w\.-]+@[\w\.-]+\.\w+\b", " ", cleaned)

    # supprimer artefacts de multiples espaces / sauts
    cleaned = re.sub(r"[_•·]+", " ", cleaned)
    cleaned = normalize_whitespace(cleaned)

    return cleaned


# -----------------------------
# Détection CTI rule-based
# -----------------------------
def detect_from_patterns(text: str, patterns: Dict[str, List[str]]) -> List[str]:
    found = []
    text_lower = text.lower()

    for label, regs in patterns.items():
        for rgx in regs:
            if re.search(rgx, text_lower, flags=re.IGNORECASE):
                found.append(label)
                break

    return found


def extract_recommendations(text: str) -> List[str]:
    recs = []
    for pattern in RECOMMENDATION_PATTERNS:
        matches = re.findall(pattern, text, flags=re.IGNORECASE)
        for m in matches:
            rec = normalize_whitespace(m)
            if len(rec) > 10 and not is_noise_entity(rec):
                recs.append(rec)
    return sorted(set(recs))


def detect_malware_terms(text: str) -> List[str]:
    text_lower = text.lower()
    found = set()

    for term, normalized in MALWARE_TERMS.items():
        if re.search(rf"(?<!\w){re.escape(term)}(?!\w)", text_lower):
            found.add(normalized)

    return sorted(found)


def extract_possible_cti_names(text: str) -> Dict[str, List[str]]:
    """
    Extraction légère rule-based pour capter des noms explicites dans le texte :
    ex. 'APT29', 'Lumma Stealer', 'Aurora Stealer', 'Dark Crystal RAT'
    """
    results = {
        "malware_names": set(),
        "threat_actor_names": set(),
    }

    patterns_malware = [
        r"\b[A-Z][A-Za-z0-9\-_]{2,}\s+(?:Stealer|RAT|Botnet|Malware|Backdoor|Trojan|Loader|Spyware)\b",
        r"\b(?:Lumma|Aurora|Tinba|PlugX|Ramnit|Remcos|Andromeda|Mirai|BlackByte|LockBit|DcRat|DCRat|Nymaim|Pykspa|Keenadu|M0yv|Acreed|AVrecon|BeaverTail|ChillyHell|Cheana|Bashe|Atomic Stealer)\b",
    ]
    patterns_actor = [
        r"\bAPT[\s-]?\d+\b",
        r"\bUNC\d+\b",
        r"\bShinyHunters\b",
        r"\bRedFoxtrot\b",
        r"\bBashe\b",
        r"\bAPT29\b",
        r"\bShroudedSnooper\b",
    ]

    for pat in patterns_malware:
        for match in re.findall(pat, text):
            value = normalize_whitespace(match)
            if not is_noise_entity(value):
                results["malware_names"].add(value)

    for pat in patterns_actor:
        for match in re.findall(pat, text, flags=re.IGNORECASE):
            value = normalize_whitespace(match)
            if not is_noise_entity(value):
                results["threat_actor_names"].add(value)

    return {
        "malware_names": sorted(results["malware_names"]),
        "threat_actor_names": sorted(results["threat_actor_names"]),
    }


# -----------------------------
# NER + enrichissement CTI
# -----------------------------
def classify_entity(ent_text: str, ent_label: str, full_text_lower: str) -> Dict[str, List[str]]:
    """
    Classement contextuel plus prudent que:
    ORG -> vendor
    MISC -> product
    """
    out = {
        "vendor": [],
        "product": [],
        "threat_actor": [],
        "malware": [],
        "tools": [],
    }

    value = normalize_whitespace(ent_text)
    if is_noise_entity(value):
        return out

    value_lower = value.lower()

    # Threat actors explicites
    if re.search(r"\bapt[\s-]?\d+\b", value_lower) or value in {"ShinyHunters", "RedFoxtrot", "Bashe", "ShroudedSnooper"}:
        out["threat_actor"].append(value)
        return out

    # Noms liés à malware
    if any(word in value_lower for word in ["stealer", "ransomware", "trojan", "rat", "backdoor", "botnet", "worm", "spyware", "loader"]):
        out["malware"].append(value)
        return out

    # Vendors connus / organisations
    known_vendors = {
        "microsoft", "apple", "google", "oracle", "vmware", "broadcom", "qnap", "fortinet",
        "palo alto networks", "sonicwall", "jetbrains", "netapp", "adobe", "mongodb",
        "fortra", "zimbra", "hpe", "hewlett packard enterprise", "samsung", "amazon",
        "aws", "qnap", "misp", "anydesk", "amd", "cisco", "barracuda", "zoho", "manageengine"
    }
    if value_lower in known_vendors:
        out["vendor"].append(value)
        return out

    # Produit / techno
    product_keywords = [
        "server", "vpn", "sharepoint", "exchange", "vcenter", "cloud", "office", "windows",
        "linux", "macos", "android", "ios", "misp", "mongodb", "teamcity", "solarwinds",
        "react native", "metro", "magento", "globalprotect", "pan-os", "fortios", "ssl vpn",
        "netbak", "word", "ssh", "office 2016", "office 2019", "exchange server"
    ]
    if any(k in value_lower for k in product_keywords):
        out["product"].append(value)
        return out

    # Heuristique finale
    if ent_label == "ORG":
        out["vendor"].append(value)
    elif ent_label in {"MISC", "PROD"}:
        out["product"].append(value)

    return out


def extract_entities_with_nlp(text: str, nlp: spacy.language.Language) -> Dict[str, List[str]]:
    entities = {
        "malware": [],
        "threat_actor": [],
        "vendor": [],
        "product": [],
        "attack_type": [],
        "platform": [],
        "impact": [],
        "tools": [],
        "recommendations": []
    }

    if not text:
        return entities

    clean_text = clean_text_for_nlp(text)
    doc = nlp(clean_text)
    full_text_lower = clean_text.lower()

    # 1) Détection rule-based CTI forte
    entities["malware"].extend(detect_malware_terms(clean_text))
    entities["attack_type"].extend(detect_from_patterns(clean_text, ATTACK_TYPE_PATTERNS))
    entities["platform"].extend(detect_from_patterns(clean_text, PLATFORM_PATTERNS))
    entities["impact"].extend(detect_from_patterns(clean_text, IMPACT_PATTERNS))
    entities["recommendations"].extend(extract_recommendations(clean_text))

    named_cti = extract_possible_cti_names(clean_text)
    entities["malware"].extend(named_cti["malware_names"])
    entities["threat_actor"].extend(named_cti["threat_actor_names"])

    # 2) NER spaCy avec classification contextuelle
    for ent in doc.ents:
        value = normalize_whitespace(ent.text)
        if is_noise_entity(value):
            continue

        classified = classify_entity(value, ent.label_, full_text_lower)
        for key, vals in classified.items():
            entities[key].extend(vals)

    return entities


def normalize_entities(entities: Dict[str, List[str]]) -> Dict[str, List[str]]:
    normalized = {}

    for key, values in entities.items():
        cleaned: Set[str] = set()

        for value in values:
            v = normalize_whitespace(str(value))
            if not v:
                continue

            if key != "recommendations" and is_noise_entity(v):
                continue

            # harmonisation simple
            if key in {"malware", "attack_type", "platform", "impact"}:
                v = v.strip()

            cleaned.add(v)

        normalized[key] = sorted(cleaned)

    return normalized


# -----------------------------
# Construction sortie
# -----------------------------
def build_context_object(bulletin: Dict[str, Any], entities: Dict[str, List[str]]) -> Dict[str, Any]:
    return {
        "source": bulletin.get("source", "dgssi"),
        "bulletin_id": bulletin.get("bulletin_id", ""),
        "bulletin_title": bulletin.get("bulletin_title", ""),
        "published_date": bulletin.get("published_date", ""),
        "url": bulletin.get("url", ""),
        "description": bulletin.get("description", ""),
        "cves": bulletin.get("cves", []),
        "nlp_entities": entities,
        "model_info": {
            "engine": "spaCy + rule-based CTI",
            "model_name": "fr_core_news_md"
        }
    }


# -----------------------------
# Pipeline principal
# -----------------------------
def process_file(input_path: str, output_path: str, summary_path: str):
    bulletins = load_input_file(input_path)
    if not bulletins:
        logging.warning("Aucune donnée à traiter.")
        return

    try:
        nlp = load_nlp_model()
    except Exception:
        logging.error("Échec du chargement du modèle NLP. Abandon du processus.")
        return

    output_data = []

    metrics_summary = {
        "total_bulletins": len(bulletins),
        "bulletins_with_malware": 0,
        "bulletins_with_product": 0,
        "bulletins_with_actor": 0,
        "bulletins_with_attack_type": 0,
        "bulletins_with_platform": 0,
        "bulletins_with_impact": 0,
        "bulletins_with_recommendations": 0
    }

    pbar = tqdm(bulletins, desc="Analyse NLP en cours", unit="bulletin")
    for bulletin in pbar:
        text_parts = []
        for field in ["bulletin_title", "description", "raw_text_clean"]:
            val = bulletin.get(field)
            if val and isinstance(val, str):
                text_parts.append(val)

        full_text = " ".join(text_parts)
        entities = extract_entities_with_nlp(full_text, nlp)
        normalized_entities = normalize_entities(entities)

        if normalized_entities["malware"]:
            metrics_summary["bulletins_with_malware"] += 1
        if normalized_entities["product"]:
            metrics_summary["bulletins_with_product"] += 1
        if normalized_entities["threat_actor"]:
            metrics_summary["bulletins_with_actor"] += 1
        if normalized_entities["attack_type"]:
            metrics_summary["bulletins_with_attack_type"] += 1
        if normalized_entities["platform"]:
            metrics_summary["bulletins_with_platform"] += 1
        if normalized_entities["impact"]:
            metrics_summary["bulletins_with_impact"] += 1
        if normalized_entities["recommendations"]:
            metrics_summary["bulletins_with_recommendations"] += 1

        pbar.set_postfix({
            "mw": metrics_summary["bulletins_with_malware"],
            "act": metrics_summary["bulletins_with_actor"],
            "prod": metrics_summary["bulletins_with_product"]
        })

        output_data.append(build_context_object(bulletin, normalized_entities))

    try:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=4, ensure_ascii=False)
        logging.info("Fichier NLP complet sauvegardé sous : %s", output_path)
    except Exception as e:
        logging.error("Erreur lors de la sauvegarde JSON de sortie : %s", e)

    try:
        Path(summary_path).parent.mkdir(parents=True, exist_ok=True)
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(metrics_summary, f, indent=4, ensure_ascii=False)
        logging.info("Fichier Summary sauvegardé sous : %s", summary_path)
    except Exception as e:
        logging.error("Erreur lors de la sauvegarde du summary : %s", e)


if __name__ == "__main__":
    BASE_DIR = Path(__file__).resolve().parent

    INPUT_FILE = BASE_DIR / "output" / "dgssi_stage1_random_1000.json"
    OUTPUT_FILE = BASE_DIR / "output" / "dgssi_nlp_stage2.json"
    SUMMARY_FILE = BASE_DIR / "output" / "dgssi_nlp_stage2_summary.json"

    process_file(str(INPUT_FILE), str(OUTPUT_FILE), str(SUMMARY_FILE))