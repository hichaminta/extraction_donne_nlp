from .base_adapter import BaseAdapter
from typing import List

class CinsAdapter(BaseAdapter):
    def process(self, record: dict) -> List[dict]:
        value = record.get("ip") or record.get("valeur")
        if not value:
            return []

        description = "CINS Army Malicious IP"
        raw_text = f"IP: {value}\nSource: CINS Army"
        
        context = record.copy()

        item = self.normalize_ioc(
            record=record,
            source="CINS Army",
            value=value,
            ioc_type="ip",
            description=description,
            raw_text=raw_text,
            raw_iocs=[value],
            first_seen=record.get("collected_at"),
            confidence=None,
            tags=["cins_army"],
            context=context
        )
        return [item] if item else []
