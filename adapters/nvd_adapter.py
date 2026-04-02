from .base_adapter import BaseAdapter
from typing import List

class NvdAdapter(BaseAdapter):
    def process(self, record: dict) -> List[dict]:
        cve_id = record.get("cve_id") or record.get("id")
        if not cve_id:
            return []

        # Extraction des infos CVE
        description = record.get("description")
        severity = record.get("severity") or record.get("baseSeverity")
        
        # Gestion CVSS complexe (liste d'objets ou score direct)
        cvss_data = record.get("cvss") or record.get("baseScore")
        
        # Si c'est une liste (cas NVD/CISA), on peut essayer d'extraire le score/version pour le contexte
        enriched_severity = severity
        if isinstance(cvss_data, list) and len(cvss_data) > 0:
            # On prend le premier par défaut, ou on pourrait chercher le plus élevé
            first_cvss = cvss_data[0]
            if not severity and "score" in first_cvss:
                score = first_cvss["score"]
                if score >= 9.0: enriched_severity = "CRITICAL"
                elif score >= 7.0: enriched_severity = "HIGH"
                elif score >= 4.0: enriched_severity = "MEDIUM"
                else: enriched_severity = "LOW"

        published_date = record.get("published_date") or record.get("published")

        context = record.copy()
        
        item = self.normalize_cve(
            record=record,
            source="NVD",
            cve_id=cve_id,
            description=description,
            raw_text=description,
            raw_cves=[cve_id],
            severity=enriched_severity,
            cvss=cvss_data,
            published_date=published_date,
            context=context
        )
        return [item] if item else []
