from .base_adapter import BaseAdapter
import logging

class DgssiAdapter(BaseAdapter):
    """
    Adapter pour DGSSI (Normalisé).
    Génère un record CVE pour chaque CVE identifiée dans le bulletin.
    """

    def process(self, raw_data):
        normalized_results = []
        
        # Extraction du contexte du bulletin
        bulletin_title = raw_data.get("title")
        description = raw_data.get("raw_text_sample")
        published = self.get_first_value(raw_data, ["date", "published_at"])
        
        # Liste des CVEs mentionnées
        cves = self.to_list(raw_data.get("cves"))
        
        if not cves:
            # On pourrait quand même créer un record générique ou logguer
            logging.warning(f"Bulletin DGSSI '{bulletin_title}' ne contient aucune CVE structurée.")
            return []

        for cve_id in cves:
            try:
                # On crée un record CVE complet
                cve_record = self.normalize_cve(
                    cve_id=cve_id,
                    source="DGSSI",
                    description=f"Bulletin: {bulletin_title}\n\n{description}",
                    published_date=published,
                    raw=raw_data # On garde tout le bulletin pour référence
                )
                normalized_results.append(cve_record)
            except Exception as e:
                logging.error(f"Erreur lors de la normalisation d'une CVE DGSSI : {e}")

        return normalized_results
