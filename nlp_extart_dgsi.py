import re
import json
import os
from datetime import datetime

# ─── Patterns IOC ───────────────────────────────────────────────────────────────

PATTERNS = {
    "ip": re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    ),
    "url": re.compile(
        r'https?://[^\s\]\[<>"\'{}|\\^`]+'
    ),
    "domain": re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
        r'+(?:com|net|org|gov|ma|fr|io|xyz|info|biz|co|uk|de|ru|cn|br|eu)\b'
    ),
    "hash_sha256": re.compile(r'\b[a-fA-F0-9]{64}\b'),
    "hash_sha1":   re.compile(r'\b[a-fA-F0-9]{40}\b'),
    "hash_md5":    re.compile(r'\b[a-fA-F0-9]{32}\b'),
    "email":       re.compile(r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'),
}

# ─── Whitelists ─────────────────────────────────────────────────────────────────

DOMAIN_WHITELIST = {
    "dgssi.gov.ma", "www.dgssi.gov.ma", "ic3.gov",
    "microsoft.com", "wordpress.org",
}

IP_WHITELIST = {
    "127.0.0.1", "0.0.0.0", "255.255.255.255",
}

# ─── Mapping des champs structurés connus → ioc_type ───────────────────────────
# Clés JSON qui contiennent directement une valeur IOC atomique

STRUCTURED_FIELD_MAP = {
    # IP
    "ip": "ip",
    "ip_address": "ip",
    "src_ip": "ip",
    "dst_ip": "ip",
    "source_ip": "ip",
    "destination_ip": "ip",
    "remote_ip": "ip",
    "attacker_ip": "ip",
    # URL
    "url": "url",
    "uri": "url",
    "request_url": "url",
    "download_url": "url",
    "c2_url": "url",
    "callback_url": "url",
    # Domaine
    "domain": "domain",
    "hostname": "domain",
    "fqdn": "domain",
    "c2_domain": "domain",
    "dns": "domain",
    # Hash
    "md5": "hash",
    "sha1": "hash",
    "sha256": "hash",
    "hash": "hash",
    "file_hash": "hash",
    "checksum": "hash",
    # Email
    "email": "email",
    "sender": "email",
    "from": "email",
    "reply_to": "email",
    # Standard Adapter Fields
    "raw_iocs": "ioc",
}

# ─── Constructeur d'un objet IOC ────────────────────────────────────────────────

def build_ioc(value: str, ioc_type: str, source: str,
              collected_at: str, raw_text: str,
              description: str = None, tags: list = None) -> dict:
    return {
        "type": "ioc",
        "value": value.strip(),
        "ioc_type": ioc_type,
        "source": source,
        "description": description or f"{ioc_type.upper()} extrait du bulletin {source}",
        "tags": tags or [],
        "first_seen": None,
        "last_seen": None,
        "confidence": None,
        "context": {
            "source": source.lower(),
            "collected_at": collected_at,
            # ⚠️ raw_text uniquement : jamais d'objet IOC imbriqué ici
            "raw_text": raw_text.strip() if raw_text else ""
        }
    }

# ─── Extraction depuis texte brut (NLP / regex) ─────────────────────────────────

def extract_from_text(text: str, source: str, collected_at: str,
                      seen: set, results: list) -> None:
    """
    Parcourt le texte ligne par ligne et extrait les IOC via regex.
    Alimente `results` en place, déduplique via `seen`.
    """
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue

        # Emails (priorité haute avant domaines)
        for m in PATTERNS["email"].finditer(line):
            _add(m.group(), "email", line, source, collected_at, seen, results)

        # URLs (avant domaines pour éviter chevauchement)
        for m in PATTERNS["url"].finditer(line):
            url = m.group().rstrip(".,;)")
            _add(url, "url", line, source, collected_at, seen, results)

        # IPs
        for m in PATTERNS["ip"].finditer(line):
            ip = m.group()
            if ip not in IP_WHITELIST:
                _add(ip, "ip", line, source, collected_at, seen, results)

        # Domaines (évite ceux déjà dans une URL capturée)
        for m in PATTERNS["domain"].finditer(line):
            domain = m.group().lower()
            if domain not in DOMAIN_WHITELIST:
                if not any(
                    ioc["ioc_type"] == "url" and domain in ioc["value"]
                    for ioc in results
                ):
                    _add(domain, "domain", line, source, collected_at, seen, results)

        # Hashes SHA256 → SHA1 → MD5 (du plus long au plus court)
        for m in PATTERNS["hash_sha256"].finditer(line):
            _add(m.group().lower(), "hash", line, source, collected_at, seen, results)
        for m in PATTERNS["hash_sha1"].finditer(line):
            val = m.group().lower()
            if not any(ioc["value"].startswith(val) for ioc in results
                       if ioc["ioc_type"] == "hash"):
                _add(val, "hash", line, source, collected_at, seen, results)
        for m in PATTERNS["hash_md5"].finditer(line):
            val = m.group().lower()
            if not any(ioc["value"].startswith(val) for ioc in results
                       if ioc["ioc_type"] == "hash"):
                _add(val, "hash", line, source, collected_at, seen, results)


def _add(value: str, ioc_type: str, raw_line: str,
         source: str, collected_at: str, seen: set, results: list) -> None:
    key = (ioc_type, value.strip().lower())
    if key in seen:
        return
    seen.add(key)
    results.append(build_ioc(value, ioc_type, source, collected_at, raw_line))


# ─── Extraction depuis structures imbriquées (details, nested JSON) ─────────────

def extract_from_structure(obj, source: str, collected_at: str,
                           seen: set, results: list,
                           _depth: int = 0) -> None:
    """
    Parcourt récursivement n'importe quelle structure dict/list.
    - Si une clé correspond à STRUCTURED_FIELD_MAP → extrait la valeur comme IOC atomique
    - Si la valeur est une str → tente aussi regex dessus
    - Jamais d'IOC imbriqué dans context
    Limite de profondeur à 10 pour éviter les boucles infinies.
    """
    if _depth > 10:
        return

    if isinstance(obj, list):
        for item in obj:
            extract_from_structure(item, source, collected_at, seen, results, _depth + 1)

    elif isinstance(obj, dict):
        for key, value in obj.items():
            key_lower = key.lower()

            # ── Cas 1 : clé connue → valeur = IOC atomique ──────────────────────
            if key_lower in STRUCTURED_FIELD_MAP:
                ioc_type = STRUCTURED_FIELD_MAP[key_lower]

                if isinstance(value, str) and value.strip():
                    _add(value.strip(), ioc_type,
                         f"champ structuré: {key}",
                         source, collected_at, seen, results)

                elif isinstance(value, list):
                    # Ex: "ip_address": ["1.2.3.4", "5.6.7.8"]
                    for item in value:
                        if isinstance(item, str) and item.strip():
                            _add(item.strip(), ioc_type,
                                 f"champ structuré: {key}[]",
                                 source, collected_at, seen, results)
                        elif isinstance(item, dict):
                            # Ex: [{"ip": "1.2.3.4", "port": 443}]
                            extract_from_structure(
                                item, source, collected_at, seen, results, _depth + 1
                            )

            # ── Cas 2 : clé inconnue mais valeur = string → tente regex ─────────
            elif isinstance(value, str) and len(value) > 4:
                # Applique regex sur les valeurs textuelles non structurées
                extract_from_text(value, source, collected_at, seen, results)

            # ── Cas 3 : valeur = dict ou list → descend récursivement ───────────
            elif isinstance(value, (dict, list)):
                extract_from_structure(value, source, collected_at,
                                       seen, results, _depth + 1)


# ─── Pipeline principal ─────────────────────────────────────────────────────────

def process_bulletins(bulletins: list) -> list:
    all_iocs = []
    seen_global = set()

    for bulletin in bulletins:
        source = bulletin.get("source", "DGSSI")
        collected_at = (
            bulletin.get("context", {}).get("fetched_at")
            or bulletin.get("published_date")
            or datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        )

        # ── Étape 1 : extraction depuis les textes bruts ─────────────────────────
        text_fields = [
            bulletin.get("raw_text", ""),
            bulletin.get("description", ""),
            bulletin.get("context", {}).get("raw_text_sample", ""),
            bulletin.get("context", {}).get("title", ""),
        ]
        for text in text_fields:
            if text:
                extract_from_text(text, source, collected_at, seen_global, all_iocs)

        # ── Étape 2 : extraction depuis structures imbriquées (details, etc.) ────
        # On exclut les champs purement textuels déjà traités ci-dessus
        SKIP_KEYS = {"raw_text", "description", "raw_text_sample", "title",
                     "source", "published_date", "fetched_at", "type",
                     "cve_id", "severity", "cvss", "raw_cves", "pdfs", "date"}

        structured_data = {
            k: v for k, v in bulletin.items()
            if k not in SKIP_KEYS and isinstance(v, (dict, list))
        }
        # Inclure aussi bulletin["context"] si présent (peut contenir details, iocs, etc.)
        if "context" in bulletin and isinstance(bulletin["context"], dict):
            context_data = {
                k: v for k, v in bulletin["context"].items()
                if k not in SKIP_KEYS
            }
            structured_data["_context"] = context_data

        extract_from_structure(
            structured_data, source, collected_at, seen_global, all_iocs
        )

    return all_iocs


# ─── Validation finale : aucun IOC imbriqué ────────────────────────────────────

def validate_no_nested_iocs(iocs: list) -> list:
    """
    Vérifie qu'aucun objet IOC ne contient d'autres objets IOC dans son context.
    Supprime les champs non atomiques de context si présents.
    """
    clean = []
    for ioc in iocs:
        ctx = ioc.get("context", {})
        # Supprimer toute clé dans context qui contiendrait une liste d'objets
        safe_ctx = {
            k: v for k, v in ctx.items()
            if not isinstance(v, (dict, list))
        }
        ioc["context"] = safe_ctx
        clean.append(ioc)
    return clean


# ─── Entrée principale ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    input_file = os.path.join("output_adapters", "dgssi_adapter.json")
    output_file = os.path.join("output_adapters", "dgssi_iocs_nlp.json")

    if not os.path.exists(input_file):
        print(f"❌ Erreur : {input_file} introuvable.")
        exit(1)

    print(f"🔍 Chargement de {input_file}...")
    with open(input_file, "r", encoding="utf-8") as f:
        bulletins = json.load(f)

    print(f"🧠 Analyse de {len(bulletins)} bulletins...")
    iocs = process_bulletins(bulletins)
    iocs = validate_no_nested_iocs(iocs)

    # Affichage d'un aperçu
    if iocs:
        print("\n--- Aperçu des IOCs extraits ---")
        for ioc in iocs[:5]:
            print(f"- [{ioc['ioc_type']}] {ioc['value']}")
        if len(iocs) > 5:
            print(f"... et {len(iocs) - 5} autres.")

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(iocs, f, ensure_ascii=False, indent=2)

    print(f"\n✅ Terminé ! {len(iocs)} IOC(s) sauvegardés dans {output_file}.")