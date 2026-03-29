import logging

# Configuration des logs
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

class BaseAdapter:
    """
    Classe de base contenant les fonctions utiles pour tous les adapters CTI.
    Normalise les sorties vers les formats IOC ou CVE attendus.
    """

    @staticmethod
    def clean_text(text):
        """Nettoie un texte : enlève les espaces inutiles ou retourne None."""
        if text is None or str(text).strip() == "":
            return None
        return str(text).strip()

    @staticmethod
    def to_list(value):
        """Transforme une valeur en liste ou retourne None si vide."""
        if value is None or value == "" or value == []:
            return None
        if isinstance(value, list):
            return value
        return [value]

    @staticmethod
    def get_first_value(data, keys, default=None):
        """Cherche et retourne la première valeur trouvée parmi plusieurs clés possibles."""
        for key in keys:
            if key in data and data[key]:
                return data[key]
        return default

    def normalize_ioc(self, value, ioc_type, source, **kwargs):
        """
        Retourne le format JSON IOC Standard.
        """
        return {
            "type": "ioc",
            "value": self.clean_text(value),
            "ioc_type": self.clean_text(ioc_type),
            "source": self.clean_text(source),
            "description": self.clean_text(kwargs.get("description")),
            "tags": self.to_list(kwargs.get("tags")),
            "first_seen": self.clean_text(kwargs.get("first_seen")),
            "last_seen": self.clean_text(kwargs.get("last_seen")),
            "confidence": kwargs.get("confidence"),
            "raw": kwargs.get("raw", {})
        }

    def normalize_cve(self, cve_id, source, **kwargs):
        """
        Retourne le format JSON CVE Standard.
        """
        return {
            "type": "cve",
            "cve_id": self.clean_text(cve_id),
            "description": self.clean_text(kwargs.get("description")),
            "severity": self.clean_text(kwargs.get("severity")),
            "cvss": kwargs.get("cvss"),
            "published_date": self.clean_text(kwargs.get("published_date")),
            "source": self.clean_text(source),
            "raw": kwargs.get("raw", {})
        }
