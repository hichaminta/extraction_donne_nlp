"""
regex_extractor.py
==================
Module de post-traitement CTI basé uniquement sur des expressions régulières.

Ce module lit les objets normalisés produits par les adapters et :
  1. Extrait les IOC (IPv4, URL, domain, email, hash) par regex
  2. Extrait les CVE (CVE-YYYY-NNNNN) par regex
  3. Fusionne avec les IOC/CVE déjà présents (raw_iocs / raw_cves)
  4. Déduplique proprement
  5. Sépare le résultat final en deux listes : iocs et cves

Sources traitées par regex MAINTENANT :
  - TOUTES les sources sauf celles réservées au NLP.
  - Seules les sources réservées au NLP sont exclues. Toutes les autres sources sont traitées par Regex.

Aucun NLP, uniquement filtrage par blacklist explicite.
"""

import re
import json
import logging
from typing import Any

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

# ---------------------------------------------------------------------------
# Sources RÉSERVÉES pour le NLP (étape future)
# ⚠️ Ne jamais traiter ces sources via Regex.
# ---------------------------------------------------------------------------
NLP_RESERVED_SOURCES = {
    "dgssi",
    "otx alienvault",
    "pulsedive"
}

# ---------------------------------------------------------------------------
# Patterns regex
# ---------------------------------------------------------------------------

# IPv4 - exclut les segments hors 0-255
_IPV4 = re.compile(
    r"\b"
    r"(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)"
    r"\b"
)

# URL (http/https/ftp)
_URL = re.compile(
    r"https?://[^\s\"'<>\]\[}{|\\^`]+"
    r"|ftp://[^\s\"'<>\]\[}{|\\^`]+"
)

# Domain (sans IP, sans TLD trop courts)
_DOMAIN = re.compile(
    r"\b"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|io|gov|edu|mil|int|info|biz|mobi|name|museum"
    r"|co|de|fr|uk|us|ru|cn|jp|br|in|ma|eu|be|nl|es|it|pl|se|ch"
    r"|au|ca|nz|sg|hk|za|ar|mx|tr|ua|ro|cz|hu|gr|fi|no|dk|pt|at"
    r"|onion|xyz|top|app|dev|cloud|site|tech|club|shop|online|pro"
    r"|click|stream|zip|mov|review)"
    r"\b",
    re.IGNORECASE
)

# Email
_EMAIL = re.compile(
    r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
)

# MD5 (32 hex chars)
_MD5 = re.compile(r"\b[0-9a-fA-F]{32}\b")

# SHA1 (40 hex chars)
_SHA1 = re.compile(r"\b[0-9a-fA-F]{40}\b")

# SHA256 (64 hex chars)
_SHA256 = re.compile(r"\b[0-9a-fA-F]{64}\b")

# CVE identifier
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


# ---------------------------------------------------------------------------
# RegexExtractor
# ---------------------------------------------------------------------------

class RegexExtractor:
    """
    Extrait des IOC et des CVE depuis un texte brut par expressions régulières.
    Fusionne avec les données existantes et déduplique.
    """

    @staticmethod
    def normalize_source_name(source: Any) -> str:
        """Normalise le nom de la source (casse et espaces)."""
        if not source:
            return ""
        return str(source).strip().lower()

    # --- Extraction depuis un texte ---

    def extract_iocs_from_text(self, text: str) -> list[dict]:
        """
        Parcourt le texte et extrait tous les IOC détectables par regex.
        Renvoie une liste de dicts {"value": ..., "ioc_type": ...}.
        L'ordre d'application des regex est important pour éviter les
        faux positifs (les URLs et emails sont testés avant les domaines
        et les IPs).
        """
        if not text or not isinstance(text, str):
            return []

        found: list[dict] = []
        seen: set[tuple] = set()

        def _add(value: str, ioc_type: str) -> None:
            key = (value.strip(), ioc_type)
            if key not in seen and value.strip():
                seen.add(key)
                found.append({"value": value.strip(), "ioc_type": ioc_type})

        # URLs doivent être testées en premier pour éviter une collision
        # avec domain ou ip
        for m in _URL.finditer(text):
            _add(m.group(), "url")

        # Emails avant domain pour éviter une collision
        for m in _EMAIL.finditer(text):
            _add(m.group(), "email")

        # IPv4
        for m in _IPV4.finditer(text):
            _add(m.group(), "ip")

        # SHA256 avant SHA1 avant MD5 pour éviter les inclusions partielles
        for m in _SHA256.finditer(text):
            _add(m.group(), "sha256")

        for m in _SHA1.finditer(text):
            # Pas déjà capturé comme sha256
            val = m.group()
            if (val, "sha256") not in seen:
                _add(val, "sha1")

        for m in _MD5.finditer(text):
            val = m.group()
            if (val, "sha256") not in seen and (val, "sha1") not in seen:
                _add(val, "md5")

        # Domains (exclusion des IPs déjà vues)
        for m in _DOMAIN.finditer(text):
            val = m.group()
            already_url = any(
                val in ioc["value"]
                for ioc in found
                if ioc["ioc_type"] == "url"
            )
            already_email = any(
                val in ioc["value"]
                for ioc in found
                if ioc["ioc_type"] == "email"
            )
            if not already_url and not already_email:
                _add(val, "domain")

        return found

    def extract_cves_from_text(self, text: str) -> list[str]:
        """
        Extrait tous les identifiants CVE d'un texte.
        Renvoie une liste de strings normalisées en majuscules.
        """
        if not text or not isinstance(text, str):
            return []
        return list({m.group().upper() for m in _CVE.finditer(text)})

    # --- Sérialisation du contexte pour extraction textuelle ---

    def _context_to_text(self, context: Any) -> str:
        """Convertit un champ context (dict/list/str) en texte brut."""
        if context is None:
            return ""
        if isinstance(context, str):
            return context
        try:
            return json.dumps(context, ensure_ascii=False)
        except (TypeError, ValueError):
            return str(context)

    # --- Collecte des textes sources d'un objet normalisé ---

    def _collect_texts(self, item: dict) -> str:
        """
        Assemble les champs textuels d'un objet normalisé en une seule
        chaîne pour simplifier l'extraction regex.
        Champs inspectés : raw_text, description, context.
        """
        parts: list[str] = []

        for field in ("raw_text", "description"):
            val = item.get(field)
            if val and isinstance(val, str):
                parts.append(val)

        context_text = self._context_to_text(item.get("context"))
        if context_text:
            parts.append(context_text)

        return "\n".join(parts)

    # --- Fusion et déduplication ---

    def merge_iocs(
        self,
        existing_raw: list[str],
        extracted: list[dict],
    ) -> list[dict]:
        """
        Fusionne les IOC bruts (simples strings) déjà présents dans
        raw_iocs avec les dicts extraits par regex.
        Déduplique par couple (value, ioc_type).
        Renvoie une liste de dicts {"value": ..., "ioc_type": ...}.
        """
        merged: list[dict] = []
        seen: set[tuple] = set()

        # Ajouter les IOC déjà présents (type inconnu → "unknown")
        for raw_val in (existing_raw or []):
            if not raw_val:
                continue
            key = (str(raw_val).strip(), "unknown")
            if key not in seen:
                seen.add(key)
                merged.append({"value": str(raw_val).strip(), "ioc_type": "unknown"})

        # Ajouter les IOC extraits par regex
        for ioc in extracted:
            key = (ioc["value"], ioc["ioc_type"])
            if key not in seen:
                seen.add(key)
                merged.append(ioc)

        return merged

    def merge_cves(
        self,
        existing_raw: list[str],
        extracted: list[str],
    ) -> list[str]:
        """
        Fusionne les CVE déjà présentes dans raw_cves avec celles
        extraites par regex.
        Déduplique par cve_id normalisé en majuscules.
        """
        seen: set[str] = set()
        merged: list[str] = []

        for cve_id in list(existing_raw or []) + list(extracted):
            norm = str(cve_id).strip().upper()
            if norm and norm not in seen:
                seen.add(norm)
                merged.append(norm)

        return merged

    # --- Construction des objets de sortie ---

    def _build_ioc_object(
        self,
        original: dict,
        ioc_entry: dict,
    ) -> dict:
        """
        Construit un objet IOC au format standard simplifié.
        """
        return {
            "type": "ioc",
            "ioc_type": ioc_entry.get("ioc_type"),
            "value": ioc_entry.get("value"),
            "source": original.get("source"),
            "description": original.get("description"),
            "raw_text": original.get("raw_text"),
            "tags": list(original.get("tags") or []),
            "first_seen": original.get("first_seen"),
            "last_seen": original.get("last_seen"),
            "confidence": original.get("confidence"),
            "context": original.get("context", {}),
            "raw": original.get("raw", {}),
        }

    def _build_cve_object(
        self,
        original: dict,
        cve_id: str,
    ) -> dict:
        """
        Construit un objet CVE au format standard simplifié.
        """
        return {
            "type": "cve",
            "cve_id": cve_id,
            "source": original.get("source"),
            "description": original.get("description"),
            "raw_text": original.get("raw_text"),
            "severity": original.get("severity"),
            "cvss": original.get("cvss"),
            "published_date": original.get("published_date"),
            "context": original.get("context", {}),
            "raw": original.get("raw", {}),
        }

    # --- Point d'entrée principal ---

    def process(self, items: list[dict]) -> dict:
        """
        Traite une liste d'objets normalisés (IOC ou CVE) produits par
        les adapters.

        Pour chaque objet dont la source est activée :
          1. Collecte les textes (raw_text, description, context)
          2. Extrait les IOC par regex
          3. Extrait les CVE par regex
          4. Fusionne avec raw_iocs / raw_cves existants
          5. Déduplique

        Retourne :
          {
            "iocs": [...],   # objets IOC (type "ioc")
            "cves": [...],   # objets CVE (type "cve")
          }
        """
        result_iocs: list[dict] = []
        result_cves: list[dict] = []

        # Déduplication globale sur l'ensemble du résultat final
        seen_iocs: set[tuple] = set()
        seen_cves: set[str] = set()
        
        total_items = len(items)
        for i, item in enumerate(items):
            if i > 0 and i % 10000 == 0:
                logging.info("   -> Progression dans le fichier : %d/%d objets traités...", i, total_items)
            
            if not isinstance(item, dict):
                continue

            # --- Filtrage des sources ---
            raw_source = item.get("source", "unknown")
            source = self.normalize_source_name(raw_source)

            # Seules les sources réservées au NLP sont exclues. 
            # Toutes les autres sources sont traitées par Regex.
            if source in NLP_RESERVED_SOURCES:
                continue

            # Toutes les autres sources → traitées par Regex.

            item_type = item.get("type", "")
            # --- Collecte des textes ---
            full_text = self._collect_texts(item)

            # --- Extraction par regex ---
            extracted_iocs = self.extract_iocs_from_text(full_text)
            extracted_cves = self.extract_cves_from_text(full_text)

            # --- Fusion avec les données existantes ---
            merged_iocs = self.merge_iocs(
                existing_raw=item.get("raw_iocs") or [],
                extracted=extracted_iocs,
            )
            merged_cves = self.merge_cves(
                existing_raw=item.get("raw_cves") or [],
                extracted=extracted_cves,
            )

            logging.debug(
                "[%s | %s] IOC extraits=%d fusionnés=%d | CVE extraits=%d fusionnés=%d",
                source,
                item_type,
                len(extracted_iocs),
                len(merged_iocs),
                len(extracted_cves),
                len(merged_cves),
            )

            # --- Routage vers la liste appropriée ---
            if item_type == "cve":
                # L'objet d'origine est une CVE → les CVE extraites
                # enrichissent cet objet
                # Les IOC trouvés dans le texte sont aussi produits
                # en tant qu'objets IOC séparés

                # Objet CVE enrichi (basé sur cve_id de l'original ou
                # sur les CVE extraites)
                original_cve_id = item.get("cve_id")
                cves_to_emit: list[str] = list(
                    {original_cve_id} | set(merged_cves)
                    if original_cve_id else set(merged_cves)
                )

                for cve_id in cves_to_emit:
                    if not cve_id:
                        continue
                    norm_id = cve_id.strip().upper()
                    if norm_id not in seen_cves:
                        seen_cves.add(norm_id)
                        result_cves.append(
                            self._build_cve_object(
                                original=item,
                                cve_id=norm_id,
                            )
                        )

                # IOC trouvés dans le texte d'une CVE
                for ioc_entry in merged_iocs:
                    key = (ioc_entry["value"], ioc_entry["ioc_type"])
                    if key not in seen_iocs:
                        seen_iocs.add(key)
                        result_iocs.append(
                            self._build_ioc_object(
                                original=item,
                                ioc_entry=ioc_entry,
                            )
                        )

            else:
                # L'objet d'origine est un IOC (ou un bulletin)
                # Les IOC extraits/fusionnés → liste iocs
                # Les CVE extraites → liste cves

                for ioc_entry in merged_iocs:
                    key = (ioc_entry["value"], ioc_entry["ioc_type"])
                    if key not in seen_iocs:
                        seen_iocs.add(key)
                        result_iocs.append(
                            self._build_ioc_object(
                                original=item,
                                ioc_entry=ioc_entry,
                            )
                        )

                for cve_id in merged_cves:
                    norm_id = cve_id.strip().upper()
                    if norm_id not in seen_cves:
                        seen_cves.add(norm_id)
                        result_cves.append(
                            self._build_cve_object(
                                original=item,
                                cve_id=norm_id,
                            )
                        )

        logging.info(
            "RegexExtractor terminé : %d IOC | %d CVE produits.",
            len(result_iocs),
            len(result_cves),
        )

        return {"iocs": result_iocs, "cves": result_cves}
