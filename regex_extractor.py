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

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

# Sources RÉSERVÉES pour le NLP
NLP_RESERVED_SOURCES = {"dgssi", "otx alienvault", "pulsedive"}

# Patterns regex
_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\b")
_URL = re.compile(r"https?://[^\s\"'<>\]\[}{|\\^`]+|ftp://[^\s\"'<>\]\[}{|\\^`]+")
_DOMAIN = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|gov|edu|mil|int|info|biz|mobi|name|museum|co|de|fr|uk|us|ru|cn|jp|br|in|ma|eu|be|nl|es|it|pl|se|ch|au|ca|nz|sg|hk|za|ar|mx|tr|ua|ro|cz|hu|gr|fi|no|dk|pt|at|onion|xyz|top|app|dev|cloud|site|tech|club|shop|online|pro|click|stream|zip|mov|review)\b", re.IGNORECASE)
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

    @lru_cache(maxsize=10000)
    def extract_iocs_from_text_cached(self, text: str) -> tuple[tuple[str, str], ...]:
        if not text or len(text) < 4: return tuple()
        found = []
        seen = set()
        def _add(v, t):
            v_s = v.strip()
            if (v_s, t) not in seen and v_s:
                seen.add((v_s, t)); found.append((v_s, t))
        
        if "://" in text:
            for m in _URL.finditer(text): _add(m.group(), "url")
        if "@" in text:
            for m in _EMAIL.finditer(text): _add(m.group(), "email")
        if "." in text:
            for m in _IPV4.finditer(text): _add(m.group(), "ip")
        if len(text) >= 32:
            for m in _SHA256.finditer(text): _add(m.group(), "sha256")
            for m in _SHA1.finditer(text):
                if (m.group(), "sha256") not in seen: _add(m.group(), "sha1")
            for m in _MD5.finditer(text):
                if (m.group(), "sha256") not in seen and (m.group(), "sha1") not in seen: _add(m.group(), "md5")
        if "." in text:
            for m in _DOMAIN.finditer(text):
                v = m.group()
                if not any(v in f[0] for f in found if f[1] in ("url", "email")): _add(v, "domain")
        return tuple(found)

    def extract_iocs_from_text(self, text: str) -> list[dict]:
        return [{"value": v, "ioc_type": t} for v, t in self.extract_iocs_from_text_cached(text)]

    @lru_cache(maxsize=10000)
    def extract_cves_from_text_cached(self, text: str) -> tuple[str, ...]:
        if not text or "CVE-" not in text.upper(): return tuple()
        return tuple({m.group().upper().strip() for m in _CVE_PAT.finditer(text)})

    def extract_cves_from_text(self, text: str) -> list[str]:
        return list(self.extract_cves_from_text_cached(text))

    def _collect_texts(self, item: dict) -> str:
        parts = []
        for f in ("raw_text", "description"):
            val = item.get(f)
            if val and isinstance(val, str): parts.append(val)
        
        # On évite json.dumps(ctx) car c'est trop lent sur de gros volumes.
        # Si le contexte contient des chaînes, on peut les ajouter sélectivement.
        ctx = item.get("context")
        if isinstance(ctx, str):
            parts.append(ctx)
        elif isinstance(ctx, dict):
            # On ne prend que les valeurs de premier niveau si ce sont des strings
            for v in ctx.values():
                if isinstance(v, str) and len(v) < 10000: # Limite de taille pour rester rapide
                    parts.append(v)
        return "\n".join(parts)

    def _clean_recursive(self, data: Any, values_to_remove: set[str]) -> Any:
        """Version simplifiée pour éviter le blocage sur de gros volumes."""
        if not data or not values_to_remove: return data
        if isinstance(data, str):
            return "[IOC_VALUE]" if data.strip() in values_to_remove else data
        if isinstance(data, list):
            return [v for v in data if v not in values_to_remove]
        if isinstance(data, dict):
            # On ne nettoie que les valeurs de premier niveau pour la performance
            return {k: ("[IOC_VALUE]" if isinstance(v, str) and v.strip() in values_to_remove else v) 
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
            "merged_cves", "extracted_cves"
        }
        return {k: v for k, v in ctx.items() if k not in blacklist}

    def _build_ioc_object(self, value: str, ioc_type: str, source: str, item: dict, cleaned_ctx: dict = None) -> dict:
        """Format final léger IOC (SANS raw_text/description/raw_iocs)"""
        ctx = cleaned_ctx if cleaned_ctx is not None else self._sanitize_context(item.get("context"))
        return {
            "type": "ioc",
            "value": value,
            "ioc_type": ioc_type,
            "sources": [source] if source else [],
            "tags": list(item.get("tags") or []),
            "first_seen": item.get("first_seen"),
            "last_seen": item.get("last_seen"),
            "confidence": item.get("confidence"),
            "contexts": [ctx] if ctx else []
        }

    def _build_cve_object(self, cve_id: str, source: str, item: dict, cleaned_ctx: dict = None) -> dict:
        """Format final léger CVE (SANS raw_text/description/raw_cves)"""
        ctx = cleaned_ctx if cleaned_ctx is not None else self._sanitize_context(item.get("context"))
        # Normalisation CVSS pour être toujours une liste
        cvss = item.get("cvss")
        if cvss is None:
            cvss_list = []
        elif isinstance(cvss, list):
            cvss_list = cvss
        else:
            cvss_list = [cvss]
            
        return {
            "type": "cve",
            "cve_id": cve_id,
            "sources": [source] if source else [],
            "severity": item.get("severity"),
            "cvss": cvss_list,
            "published_date": item.get("published_date"),
            "contexts": [ctx] if ctx else []
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
        res_iocs = [self._build_ioc_object(ioc["value"], ioc["ioc_type"], source, item, cleaned_ctx) for ioc in iocs_reg]
        res_cves = [self._build_cve_object(cid, source, item, cleaned_ctx) for cid in cves_reg]
        
        for ioc in item.get("raw_iocs", []):
            if isinstance(ioc, dict) and ioc.get("value"):
                res_iocs.append(self._build_ioc_object(ioc["value"], ioc.get("ioc_type", "unknown"), source, item, cleaned_ctx))
            elif isinstance(ioc, str) and ioc.strip():
                res_iocs.append(self._build_ioc_object(ioc.strip(), "unknown", source, item, cleaned_ctx))
                
        for cid in item.get("raw_cves", []):
            if isinstance(cid, str) and cid.strip():
                res_cves.append(self._build_cve_object(cid.strip(), source, item, cleaned_ctx))
        
        if item.get("type") == "cve" and item.get("cve_id"):
            res_cves.append(self._build_cve_object(item["cve_id"], source, item, cleaned_ctx))
            
        return {"iocs": res_iocs, "cves": res_cves}

    @staticmethod
    def merge_two_iocs(i1: dict, i2: dict) -> dict:
        """Fusion unifiée des IOC selon les règles métier."""
        # Unicité garantie par (value, ioc_type) via run_regex_extractor
        i1["sources"] = list(set(i1.get("sources", [])) | set(i2.get("sources", [])))
        i1["sources"].sort()
        
        i1["tags"] = list(set(i1.get("tags", [])) | set(i2.get("tags", [])))
        i1["tags"].sort()
        
        # Dates (min/max)
        for f, op in [("first_seen", min), ("last_seen", max)]:
            v1, v2 = i1.get(f), i2.get(f)
            if v1 and v2: i1[f] = op(v1, v2)
            elif v2: i1[f] = v2
            
        i1["confidence"] = max(i1.get("confidence") or 0, i2.get("confidence") or 0)
        if not i1["confidence"]: i1["confidence"] = None
        
        # Contextes (Liste d'objets uniques)
        for ctx in i2.get("contexts", []):
            if ctx and isinstance(ctx, dict) and ctx not in i1["contexts"]:
                i1["contexts"].append(ctx)
                
        return i1

    @staticmethod
    def merge_two_cves(c1: dict, c2: dict) -> dict:
        """Fusion unifiée des CVE selon les règles métier."""
        c1["sources"] = list(set(c1.get("sources", [])) | set(c2.get("sources", [])))
        c1["sources"].sort()
        
        # CVSS (Union sécurisée pour les objets dict)
        for val in (c2.get("cvss") or []):
            if val not in c1["cvss"]:
                c1["cvss"].append(val)
        
        # Sévérité & Date (La plus informative/pertinente)
        if not c1.get("severity") and c2.get("severity"): c1["severity"] = c2["severity"]
        if not c1.get("published_date") and c2.get("published_date"): c1["published_date"] = c2["published_date"]
        
        # Contextes
        for ctx in c2.get("contexts", []):
            if ctx and isinstance(ctx, dict) and ctx not in c1["contexts"]:
                c1["contexts"].append(ctx)
                
        return c1
