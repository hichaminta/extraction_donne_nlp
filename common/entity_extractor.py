from __future__ import annotations

import ipaddress
import re
from typing import Iterable


CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
URL_PATTERN = re.compile(r"\bhttps?://[^\s<>'\"\])}]+", re.IGNORECASE)
IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_PATTERN = re.compile(
    r"\b(?=.{1,253}\b)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b",
    re.IGNORECASE,
)
MD5_PATTERN = re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE)
SHA1_PATTERN = re.compile(r"\b[a-f0-9]{40}\b", re.IGNORECASE)
SHA224_PATTERN = re.compile(r"\b[a-f0-9]{56}\b", re.IGNORECASE)
SHA256_PATTERN = re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE)
SHA384_PATTERN = re.compile(r"\b[a-f0-9]{96}\b", re.IGNORECASE)
SHA512_PATTERN = re.compile(r"\b[a-f0-9]{128}\b", re.IGNORECASE)

TRAILING_PUNCTUATION = ".,;:!?)]}'\""
LEADING_PUNCTUATION = "([{<'\""


def _clean_candidate(value: str) -> str:
    return value.strip().strip(TRAILING_PUNCTUATION).lstrip(LEADING_PUNCTUATION)


def _normalize_texts(texts: Iterable[str | None]) -> list[str]:
    normalized: list[str] = []
    for text in texts:
        if not text:
            continue
        candidate = str(text).strip()
        if candidate:
            normalized.append(candidate)
    return normalized


def normalize_cves(values: Iterable[str | None]) -> list[str]:
    return sorted(
        {
            match.upper()
            for value in values
            if value
            for match in CVE_PATTERN.findall(str(value))
        }
    )


def classify_ioc(value: str | None) -> str | None:
    if value is None:
        return None

    candidate = _clean_candidate(str(value))
    if not candidate:
        return None

    lowered = candidate.lower()

    if lowered.startswith(("http://", "https://")):
        return "url"

    try:
        ipaddress.ip_address(candidate)
        return "ip"
    except ValueError:
        pass

    if SHA512_PATTERN.fullmatch(candidate):
        return "sha512"
    if SHA384_PATTERN.fullmatch(candidate):
        return "sha384"
    if SHA256_PATTERN.fullmatch(candidate):
        return "sha256"
    if SHA224_PATTERN.fullmatch(candidate):
        return "sha224"
    if SHA1_PATTERN.fullmatch(candidate):
        return "sha1"
    if MD5_PATTERN.fullmatch(candidate):
        return "md5"
    if DOMAIN_PATTERN.fullmatch(lowered):
        return "domain"

    return None


def normalize_iocs(items: Iterable[dict | tuple[str, str] | str | None]) -> list[dict]:
    normalized: dict[tuple[str, str], dict] = {}

    for item in items:
        ioc_type = None
        value = None

        if item is None:
            continue

        if isinstance(item, dict):
            value = item.get("value") or item.get("indicator") or item.get("ioc")
            ioc_type = item.get("type") or item.get("ioc_type") or item.get("indicator_type")
        elif isinstance(item, tuple) and len(item) == 2:
            ioc_type, value = item
        else:
            value = str(item)

        if value is None:
            continue

        candidate = _clean_candidate(str(value))
        if not candidate:
            continue

        normalized_type = classify_ioc(candidate)
        if ioc_type:
            ioc_type = str(ioc_type).strip().lower()
        final_type = normalized_type or ioc_type
        if not final_type:
            continue

        key = (final_type, candidate)
        normalized[key] = {"type": final_type, "value": candidate}

    return sorted(normalized.values(), key=lambda entry: (entry["type"], entry["value"]))


def extract_entities_from_texts(texts: Iterable[str | None]) -> dict:
    normalized_texts = _normalize_texts(texts)
    cves = set(normalize_cves(normalized_texts))
    ioc_candidates: list[dict] = []

    for text in normalized_texts:
        for match in URL_PATTERN.findall(text):
            ioc_candidates.append({"type": "url", "value": match})
        for match in IPV4_PATTERN.findall(text):
            if classify_ioc(match) == "ip":
                ioc_candidates.append({"type": "ip", "value": match})
        for match in SHA512_PATTERN.findall(text):
            ioc_candidates.append({"type": "sha512", "value": match})
        for match in SHA384_PATTERN.findall(text):
            ioc_candidates.append({"type": "sha384", "value": match})
        for match in SHA256_PATTERN.findall(text):
            ioc_candidates.append({"type": "sha256", "value": match})
        for match in SHA224_PATTERN.findall(text):
            ioc_candidates.append({"type": "sha224", "value": match})
        for match in SHA1_PATTERN.findall(text):
            ioc_candidates.append({"type": "sha1", "value": match})
        for match in MD5_PATTERN.findall(text):
            ioc_candidates.append({"type": "md5", "value": match})
        for match in DOMAIN_PATTERN.findall(text):
            if classify_ioc(match) == "domain":
                ioc_candidates.append({"type": "domain", "value": match})

    return {
        "cves": sorted(cves),
        "iocs": normalize_iocs(ioc_candidates),
    }


def merge_entities(*entity_sets: dict | None) -> dict:
    cve_values: list[str] = []
    ioc_values: list[dict | tuple[str, str] | str] = []

    for entity_set in entity_sets:
        if not entity_set:
            continue
        cve_values.extend(entity_set.get("cves", []))
        ioc_values.extend(entity_set.get("iocs", []))

    return {
        "cves": normalize_cves(cve_values),
        "iocs": normalize_iocs(ioc_values),
    }
