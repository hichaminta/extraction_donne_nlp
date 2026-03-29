from .base_adapter import BaseAdapter
import logging

class NvdAdapter(BaseAdapter):
    """
    Adapter pour NVD / CISA (Normalisé).
    Retourne les CVEs au format CVE Standard.
    """

    def process(self, raw_data):
        try:
            cve_id = self.get_first_value(raw_data, ["cve_id", "cveID", "id"])
            if not cve_id:
                logging.warning("Record NVD sans identifiant CVE trouvé.")
                return []

            description = raw_data.get("description")
            published = self.get_first_value(raw_data, ["published", "published_date", "publishedDate"])
            
            # Calcul du score et sévérité
            cvss_score = raw_data.get("base_score")
            severity = raw_data.get("severity")
            
            # Gestion du format spécifique cve_data_exploited
            cvss_list = raw_data.get("cvss", [])
            if cvss_score is None and cvss_list and isinstance(cvss_list, list):
                cvss_score = cvss_list[0].get("score")

            # Normalisation vers le format CVE Standard
            cve_record = self.normalize_cve(
                cve_id=cve_id,
                source="NVD",
                description=description,
                severity=severity,
                cvss=cvss_score,
                published_date=published,
                raw=raw_data  # Contexte complet préservé
            )
            
            return [cve_record] # Retourne toujours une liste
            
        except Exception as e:
            logging.error(f"Erreur lors de la normalisation NVD : {e}")
            return []
