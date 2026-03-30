from .base_adapter import BaseAdapter
from typing import List

class DgssiAdapter(BaseAdapter):
    def process(self, record: dict) -> List[dict]:
        cves = self.to_list(record.get("cves") or [])
        title = record.get("title")
        description = record.get("description")
        raw_text = record.get("description") or title
        
        # Contexte complet
        context = {k: v for k, v in record.items() if k not in ["cves"]}

        if not cves:
            # Si pas de CVE, on retourne l'objet global comme bulletin
            item = self.normalize_ioc(
                record=record,
                source="DGSSI",
                value=title,
                ioc_type="bulletin",
                description=description or title,
                raw_text=raw_text,
                raw_cves=cves,
                first_seen=record.get("date"),
                tags=[],
                context=context
            )
            return [item] if item else []

        results = []
        for cve_id in cves:
            item = self.normalize_cve(
                record=record,
                source="DGSSI",
                cve_id=cve_id,
                description=description or title,
                raw_text=raw_text,
                raw_cves=cves,
                severity=record.get("severity"),
                cvss=record.get("cvss"),
                published_date=record.get("date"),
                context=context
            )
            if item:
                results.append(item)
        return results
