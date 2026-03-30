import logging

# Configuration des logs
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

class BaseAdapter:
    """
    Classe de base pour tous les adapters CTI.
    Normalisation stricte sans perte de données.
    """

    @staticmethod
    def clean_text(text):
        if text is None or str(text).strip() == "":
            return None
        return str(text).strip()

    @staticmethod
    def to_list(value):
        if value is None or value == "" or value == []:
            return []
        if isinstance(value, list):
            return value
        return [value]

    def normalize_ioc(self, record, source, **kwargs):
        """
        Génère un objet IOC au format standard.
        """
        return {
            "type": "ioc",
            "value": kwargs.get("value"),
            "ioc_type": kwargs.get("ioc_type"),
            "source": source,
            "description": kwargs.get("description"),
            "raw_text": kwargs.get("raw_text"),  # Nouveau champ pour le texte complet
            "raw_iocs": self.to_list(kwargs.get("raw_iocs") or []),  # Nouveau champ pour les IOCs bruts
            "raw_cves": self.to_list(kwargs.get("raw_cves") or []),  # Nouveau champ pour les CVEs brutes
            "tags": self.to_list(kwargs.get("tags") or []),
            "first_seen": kwargs.get("first_seen"),
            "last_seen": kwargs.get("last_seen"),
            "confidence": kwargs.get("confidence"),
            "context": kwargs.get("context", {}),
            "raw": record
        }

    def normalize_cve(self, record, source, **kwargs):
        """
        Génère un objet CVE au format standard.
        """
        return {
            "type": "cve",
            "cve_id": kwargs.get("cve_id"),
            "description": kwargs.get("description"),
            "raw_text": kwargs.get("raw_text"),  # Nouveau champ
            "raw_iocs": self.to_list(kwargs.get("raw_iocs") or []),  # Nouveau champ
            "raw_cves": self.to_list(kwargs.get("raw_cves") or []),  # Nouveau champ
            "severity": kwargs.get("severity"),
            "cvss": kwargs.get("cvss"),
            "published_date": kwargs.get("published_date"),
            "source": source,
            "context": kwargs.get("context", {}),
            "raw": record
        }
