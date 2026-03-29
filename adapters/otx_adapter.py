from .base_adapter import BaseAdapter
import logging

class OtxAdapter(BaseAdapter):
    """
    Adapter pour OTX AlienVault (Normalisé).
    Extrait chaque indicateur individuellement du Pulse.
    """

    def process(self, raw_data):
        normalized_results = []
        
        pulse_name = raw_data.get("name", "Sans nom")
        description = raw_data.get("description")
        published = raw_data.get("created")
        tags = raw_data.get("tags")
        
        indicators = raw_data.get("indicators", [])
        
        if not indicators:
            logging.warning(f"OTX Pulse '{pulse_name}' ne contient aucun indicateur.")
            return []

        for ind in indicators:
            try:
                # On extrait la valeur et le type d'IOC
                value = ind.get("indicator")
                ioc_type = ind.get("type", "unknown").lower()
                
                # Normalisation vers le format IOC Standard
                ioc_record = self.normalize_ioc(
                    value=value,
                    ioc_type=ioc_type,
                    source="OTX AlienVault",
                    description=description,
                    tags=tags,
                    first_seen=published,
                    raw=raw_data  # On garde le contexte complet (Pulse entier)
                )
                normalized_results.append(ioc_record)
            except Exception as e:
                logging.error(f"Erreur lors de la normalisation d'un indicateur OTX : {e}")

        return normalized_results
