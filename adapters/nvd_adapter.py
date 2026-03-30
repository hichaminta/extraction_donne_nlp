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
        cvss = record.get("cvss") or record.get("baseScore")
        published_date = record.get("published_date") or record.get("published")

        context = record.copy()

        item = self.normalize_cve(
            record=record,
            source="NVD",
            cve_id=cve_id,
            description=description,
            raw_text=description,
            raw_cves=[cve_id],
            severity=severity,
            cvss=cvss,
            published_date=published_date,
            context=context
        )
        return [item] if item else []
