from .base_adapter import BaseAdapter
from typing import List

class OpenphishAdapter(BaseAdapter):
    def process(self, record: dict) -> List[dict]:
        value = record.get("url")
        if not value:
            return []

        first_seen = record.get("first_seen") or record.get("collected_at")
        description = record.get("description") or "Phishing URL detected"
        raw_text = f"URL: {value}\nSource: OpenPhish\nPhishing detected"
        
        context = record.copy()
        
        item = self.normalize_ioc(
            record=record,
            source="OpenPhish",
            value=value,
            ioc_type="url",
            description=description,
            raw_text=raw_text,
            raw_iocs=[value],
            first_seen=first_seen,
            last_seen=None,
            confidence=None,
            tags=["phishing"],
            context=context
        )
        return [item] if item else []
