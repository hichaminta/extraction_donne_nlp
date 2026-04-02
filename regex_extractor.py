"""
regex_extractor.py
==================
Module de post-traitement CTI optimisé pour une sortie légère et unifiée.
"""

import re
import json
import logging
import copy
from typing import Any
from functools import lru_cache
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

# Sources RÉSERVÉES pour le NLP
NLP_RESERVED_SOURCES = {"dgssi", "otx alienvault", "pulsedive"}

# Patterns regex
_IPV4_BASE = r"(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)"
_IP_WITH_PORT = re.compile(f"\\b({_IPV4_BASE})(?::([0-9]{{1,5}}))?\\b")
_URL = re.compile(r"(?:https?|ftp)://[^\s\"'<>\]\[}{|\\^`]{3,}")
_DOMAIN = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|gov|edu|mil|int|info|biz|mobi|name|museum|co|de|fr|uk|us|ru|cn|jp|br|in|ma|eu|be|nl|es|it|pl|se|ch|au|ca|nz|sg|hk|za|ar|mx|tr|ua|ro|cz|hu|gr|fi|no|dk|pt|at|onion|xyz|top|app|dev|cloud|site|tech|club|shop|online|pro|click|stream|zip|mov|review|cc|pw|me|top|icu|bit|info|live|bid)\b", re.IGNORECASE)
_EMAIL = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")
_MD5 = re.compile(r"\b[0-9a-fA-F]{32}\b")
_SHA1 = re.compile(r"\b[0-9a-fA-F]{40}\b")
_SHA256 = re.compile(r"\b[0-9a-fA-F]{64}\b")
_CVE_PAT = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)

class RegexExtractor:
    @staticmethod
    def normalize_source_name(source: Any) -> str:
        if not source: return ""
        return str(source).strip().lower()

    @staticmethod
    def _normalize_cve(cve: str) -> str:
        if not cve: return ""
        v = cve.upper().strip()
        if not v.startswith("CVE-"):
            if re.match(r"\d{4}-\d{4,}", v): return f"CVE-{v}"
        return v

    @lru_cache(maxsize=10000)
    def extract_iocs_from_text_cached(self, text: str) -> tuple[dict, ...]:
        if not text or len(text) < 4: return tuple()
        found = []
        seen = set()
        
        def _get_existing_ip(ip):
            for f in found:
                if f["value"] == ip and f["ioc_type"] == "ip": return f
            return None

        def _add(v, t, p=None):
            v_s = v.strip()
            
            # Filtrage des faux positifs (localhost, loopback, generic placeholders)
            v_low = v_s.lower()
            if v_low in ("localhost", "127.0.0.1", "127.1", "0.0.0.0"): return
            
            if "://" in v_low:
                try:
                    v_s = v_s.rstrip(").,")
                    parsed = urlparse(v_s)
                    host = (parsed.hostname or "").lower()
                    
                    # 1. Host vide ou local
                    if not host or host in ("localhost", "127.0.0.1", "127.1", "0.0.0.0", "::1"):
                        return
                    
                    # 2. Placeholders génériques communs dans les bulletins (NVD/DGSSI)
                    if host in ("x.x.x.x", "intranet-ip", "domain", "example.com", "example.org", "server.com"):
                        return
                    if "%" in host: # Placeholders comme %humbug-URL%
                        return
                        
                    # 3. Hostnames internes (pas de point et pas une IP numérique)
                    # ex: 'http://gpu', 'http://server'
                    if "." not in host and not host.replace(".", "").isnumeric():
                        return
                        
                    # 4. URLs malformées (ex: 'http://:80')
                    if host.startswith(":"):
                        return
                        
                except Exception:
                    pass

            if t == "domain": v_s = v_s.lower()
            
            # Gestion fusion ports pour IP
            if t == "ip":
                existing = _get_existing_ip(v_s)
                if existing:
                    if p:
                        ports = list(existing.get("ports") or [])
                        if p not in ports:
                            ports.append(p); ports.sort()
                            existing["ports"] = ports
                    return
            
            if (v_s, t) not in seen and v_s:
                seen.add((v_s, t))
                ioc = {"value": v_s, "ioc_type": t}
                if p: ioc["ports"] = [p]
                found.append(ioc)
        
        if "://" in text:
            for m in _URL.finditer(text): _add(m.group(), "url")
        if "@" in text:
            for m in _EMAIL.finditer(text): _add(m.group(), "email")
        if "." in text:
            for m in _IP_WITH_PORT.finditer(text):
                ip_part = m.group(1)
                port_part = m.group(2)
                _add(ip_part, "ip", port_part)
        if len(text) >= 32:
            # On évite d'extraire des hashes s'ils font partie d'une URL déjà trouvée
            excluded_vals = [f["value"] for f in found if f["ioc_type"] in ("url", "email")]
            for m in _SHA256.finditer(text):
                v = m.group()
                if not any(v in fv for fv in excluded_vals): _add(v, "sha256")
            for m in _SHA1.finditer(text):
                v = m.group()
                if (v, "sha256") not in seen and not any(v in fv for fv in excluded_vals):
                    _add(v, "sha1")
            for m in _MD5.finditer(text):
                v = m.group()
                if (v, "sha256") not in seen and (v, "sha1") not in seen and not any(v in fv for fv in excluded_vals):
                    _add(v, "md5")
        if "." in text:
            for m in _DOMAIN.finditer(text):
                v = m.group()
                if not any(v in f["value"] for f in found if f["ioc_type"] in ("url", "email")): _add(v, "domain")
        return tuple(found)

    def extract_iocs_from_text(self, text: str) -> list[dict]:
        return list(copy.deepcopy(self.extract_iocs_from_text_cached(text)))

    @lru_cache(maxsize=10000)
    def extract_cves_from_text_cached(self, text: str) -> tuple[str, ...]:
        if not text: return tuple()
        upper_text = text.upper()
        # Chercher CVE-XXXX-XXXXX ou juste XXXX-XXXXX si contextuel
        cves = {self._normalize_cve(m.group()) for m in _CVE_PAT.finditer(text)}
        return tuple(sorted(cves))

    def extract_cves_from_text(self, text: str) -> list[str]:
        return list(self.extract_cves_from_text_cached(text))

    def _collect_texts(self, item: dict) -> str:
        parts = []
        for f in ("raw_text", "description"):
            val = item.get(f)
            if val and isinstance(val, str): parts.append(val)
        
        ctx = item.get("context")
        if isinstance(ctx, str):
            parts.append(ctx)
        elif isinstance(ctx, dict):
            for k, v in ctx.items():
                if isinstance(v, str) and len(v) < 10000:
                    parts.append(v)
                elif isinstance(v, list):
                    for sub_item in v:
                        if isinstance(sub_item, str) and len(sub_item) < 1000:
                            parts.append(sub_item)
                        elif isinstance(sub_item, dict) and "comment" in sub_item:
                            cmt = sub_item.get("comment")
                            if isinstance(cmt, str) and len(cmt) < 10000:
                                parts.append(cmt)
        return "\n".join(parts)

    def _clean_recursive(self, data: Any, values_to_remove: set[str]) -> Any:
        """Version simplifiée pour éviter le blocage sur de gros volumes."""
        if not data or not values_to_remove: return data
        if isinstance(data, str):
            return "[IOC_VALUE]" if data.strip() in values_to_remove else data
        if isinstance(data, list):
            return [self._clean_recursive(v, values_to_remove) for v in data]
        if isinstance(data, dict):
            # Ne pas masquer cve_id pour garder la visibilité metadata
            return {k: (v if k == "cve_id" else self._clean_recursive(v, values_to_remove)) 
                    for k, v in data.items()}
        return data

    def _sanitize_context(self, ctx: Any) -> dict:
        """Nettoie le contexte pour ne garder que les métadonnées utiles sans les champs lourds."""
        if not ctx or not isinstance(ctx, dict):
            return {}
        # Liste noire des champs à exclure du contexte pour rester léger
        blacklist = {
            "raw_text", "description", "raw", 
            "raw_iocs", "raw_cves", 
            "merged_iocs", "extracted_iocs", 
            "merged_cves", "extracted_cves",
            "reports"
        }
        return {k: v for k, v in ctx.items() if k not in blacklist}

    def _build_ioc_object(self, value: str, ioc_type: str, source: str, item: dict, cleaned_ctx: dict = None, ports: list = None) -> dict:
        """Format final léger IOC (SANS raw_text/description/raw_iocs)"""
        ctx = cleaned_ctx if cleaned_ctx is not None else self._sanitize_context(item.get("context"))
        tags = list(item.get("tags") or [])
        return {
            "type": "ioc",
            "value": value.lower() if ioc_type == "domain" else value,
            "ioc_type": ioc_type,
            "ports": list(set(ports)) if ports else None,
            "sources": [source] if source else [],
            "tags": tags if tags else None,
            "first_seen": item.get("first_seen"),
            "last_seen": item.get("last_seen"),
            "confidence": item.get("confidence"),
            "contexts": [ctx] if ctx else None
        }

    def _build_cve_object(self, cve_id: str, source: str, item: dict, cleaned_ctx: dict = None) -> dict:
        """Format final léger CVE (SANS raw_text/raw_cves). description sera enrichie par NVD."""
        ctx = cleaned_ctx if cleaned_ctx is not None else self._sanitize_context(item.get("context"))
        normalized_id = self._normalize_cve(cve_id)
        # Normalisation CVSS pour être toujours une liste ou None
        cvss = item.get("cvss")
        if cvss is None:
            cvss_list = []
        elif isinstance(cvss, list):
            cvss_list = cvss
        else:
            cvss_list = [cvss]

        # Description : récupère depuis l'item si déjà présente (sinon NVD comblera)
        description = item.get("description") or None

        return {
            "type": "cve",
            "cve_id": normalized_id,
            "description": description,
            "sources": [source] if source else [],
            "severity": item.get("severity"),
            "cvss": cvss_list if cvss_list else None,
            "published_date": item.get("published_date"),
            "contexts": [ctx] if ctx else None
        }

    def process_single_item(self, item: dict) -> dict:
        source = self.normalize_source_name(item.get("source"))
        if source in NLP_RESERVED_SOURCES: return {"iocs": [], "cves": []}
        
        # 1. Extraction regex classique
        text = self._collect_texts(item)
        iocs_reg = self.extract_iocs_from_text(text)
        cves_reg = self.extract_cves_from_text(text)
        
        # 2. Collecte de toutes les valeurs extraites pour le nettoyage futur
        all_vals = {ioc["value"] for ioc in iocs_reg}
        for cid in cves_reg: all_vals.add(cid)
        
        # Ajout des raw_iocs / raw_cves à la liste des valeurs à nettoyer
        for ioc in item.get("raw_iocs", []):
            if isinstance(ioc, dict) and ioc.get("value"): all_vals.add(ioc["value"])
            elif isinstance(ioc, str) and ioc.strip(): all_vals.add(ioc.strip())
        for cid in item.get("raw_cves", []):
            if isinstance(cid, str) and cid.strip(): all_vals.add(cid.strip())
        if item.get("type") == "cve" and item.get("cve_id"): all_vals.add(item["cve_id"])
        
        # 3. Nettoyage récursif du contexte (Copie profonde pour isolation)
        ctx = item.get("context")
        cleaned_ctx = {}
        if ctx and isinstance(ctx, dict):
            # Sanitize d'abord (enlève les champs lourds)
            sanitized = self._sanitize_context(ctx)
            # Puis nettoie récursivement les valeurs d'IOC
            cleaned_ctx = self._clean_recursive(sanitized, all_vals)
        elif ctx and isinstance(ctx, str):
            # Si c'est une string, on ne peut pas vraiment nettoyer récursivement 
            # sans risquer de casser le contenu, mais on suit la règle simple :
            cleaned_ctx = "[REDACTED]" if ctx.strip() in all_vals else ctx

        # 4. Construction des objets finaux avec le contexte nettoyé
        res_iocs = [self._build_ioc_object(ioc["value"], ioc["ioc_type"], source, item, cleaned_ctx, ioc.get("ports")) for ioc in iocs_reg]
        res_cves = [self._build_cve_object(cid, source, item, cleaned_ctx) for cid in cves_reg]
        
        # 5. Récupération Directe depuis l'item (Cas où l'adapter fournit déjà une structure IOC/CVE)
        # Gestion top-level IOC
        if item.get("type") == "ioc" and item.get("value"):
            res_iocs.append(self._build_ioc_object(
                item["value"], 
                item.get("ioc_type", "unknown"), 
                source, item, cleaned_ctx, 
                item.get("ports")
            ))
            
        # Gestion top-level CVE
        if item.get("type") == "cve" and item.get("cve_id"):
            res_cves.append(self._build_cve_object(item["cve_id"], source, item, cleaned_ctx))

        # 6. Récupération CVE ID depuis le contexte ou métadonnées directes
        cve_from_meta = item.get("cve_id")
        if not cve_from_meta and isinstance(item.get("context"), dict):
            cve_from_meta = item["context"].get("cve_id")
        if cve_from_meta:
            res_cves.append(self._build_cve_object(cve_from_meta, source, item, cleaned_ctx))

        # 7. Collecte des raw_iocs et raw_cves (historique/legacy)
        for ioc in item.get("raw_iocs", []):
            if isinstance(ioc, dict) and ioc.get("value"):
                res_iocs.append(self._build_ioc_object(ioc["value"], ioc.get("ioc_type", "unknown"), source, item, cleaned_ctx))
            elif isinstance(ioc, str) and ioc.strip():
                res_iocs.append(self._build_ioc_object(ioc.strip(), "unknown", source, item, cleaned_ctx))
                
        for cid in item.get("raw_cves", []):
            if isinstance(cid, str) and cid.strip():
                res_cves.append(self._build_cve_object(cid.strip(), source, item, cleaned_ctx))
            
        return {"iocs": res_iocs, "cves": res_cves}

    @staticmethod
    def merge_two_iocs(i1: dict, i2: dict) -> dict:
        """Fusion unifiée des IOC selon les règles métier."""
        # Unicité garantie par le 'value' via run_regex_extractor
        
        # Fusion du type d'IOC (on préfère un type spécifique à 'unknown')
        t1, t2 = i1.get("ioc_type", "unknown"), i2.get("ioc_type", "unknown")
        if t1 == "unknown" and t2 != "unknown":
            i1["ioc_type"] = t2
            
        i1["sources"] = list(set(i1.get("sources") or []) | set(i2.get("sources") or []))
        i1["sources"].sort()
        
        tags = list(set(i1.get("tags") or []) | set(i2.get("tags") or []))
        tags.sort()
        i1["tags"] = tags if tags else None
        
        # Dates (min/max)
        for f, op in [("first_seen", min), ("last_seen", max)]:
            v1, v2 = i1.get(f), i2.get(f)
            if v1 and v2: i1[f] = op(v1, v2)
            elif v2: i1[f] = v2
            
        i1["confidence"] = max(i1.get("confidence") or 0, i2.get("confidence") or 0)
        if not i1["confidence"]: i1["confidence"] = None
        
        # Contextes (Liste d'objets uniques)
        c1 = i1.get("contexts") or []
        for ctx in i2.get("contexts") or []:
            if ctx and isinstance(ctx, dict) and ctx not in c1:
                c1.append(ctx)
        i1["contexts"] = c1 if c1 else None

        # Fusion des ports
        p1 = set(i1.get("ports") or [])
        p2 = set(i2.get("ports") or [])
        merged_ports = list(p1 | p2)
        merged_ports.sort()
        i1["ports"] = merged_ports if merged_ports else None
                
        return i1

    @staticmethod
    def merge_two_cves(c1: dict, c2: dict) -> dict:
        """Fusion unifiée des CVE selon les règles métier."""
        c1["sources"] = list(set(c1.get("sources") or []) | set(c2.get("sources") or []))
        c1["sources"].sort()

        # Description : garder la première non-nulle
        if not c1.get("description") and c2.get("description"):
            c1["description"] = c2["description"]

        # CVSS (Union sécurisée pour les objets dict)
        cvss1 = c1.get("cvss") or []
        for val in (c2.get("cvss") or []):
            if val not in cvss1:
                cvss1.append(val)
        c1["cvss"] = cvss1 if cvss1 else None

        # Sévérité & Date (La plus informative/pertinente)
        if not c1.get("severity") and c2.get("severity"): c1["severity"] = c2["severity"]
        if not c1.get("published_date") and c2.get("published_date"): c1["published_date"] = c2["published_date"]

        # Contextes
        ctx1 = c1.get("contexts") or []
        for ctx in c2.get("contexts") or []:
            if ctx and isinstance(ctx, dict) and ctx not in ctx1:
                ctx1.append(ctx)
        c1["contexts"] = ctx1 if ctx1 else None

        return c1
