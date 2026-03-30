from .base_adapter import BaseAdapter
from typing import List

class UrlhausAdapter(BaseAdapter):
    def process(self, record: dict) -> List[dict]:
        value = record.get("url")
        if not value:
            return []

        description = record.get("description") or "Malicious URL detected"
        threat = record.get("threat")
        if threat:
            description += f" | Threat: {threat}"
            
        raw_text = f"URL: {value}\nSource: URLHaus\nThreat: {threat}\nStatus: {record.get('url_status')}"
        tags = self.to_list(record.get("tags") or [])
        if threat:
            tags.append(threat)

        context = record.copy()

        item = self.normalize_ioc(
            record=record,
            source="URLHaus",
            value=value,
            ioc_type="url",
            description=description,
            raw_text=raw_text,
            raw_iocs=[value],
            first_seen=record.get("date_added") or record.get("first_seen"),
            last_seen=record.get("last_seen"),
            confidence=None,
            tags=tags,
            context=context
        )
        return [item] if item else []
