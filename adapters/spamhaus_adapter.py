from .base_adapter import BaseAdapter
from typing import List

class SpamhausAdapter(BaseAdapter):
    def process(self, record: dict) -> List[dict]:
        value = record.get("ioc_value")
        if not value:
            return []

        if "/" in str(value):
            ioc_type = "ip_range"
        else:
            ioc_type = record.get("ioc_type") or "ip"

        feed = record.get("feed_name") or record.get("ioc_subtype") or "Unknown"
        description = f"Spamhaus Feed: {feed}"
        raw_text = f"IOC: {value}\nFeed: {feed}\nReference: {record.get('reference')}"
        
        tags = self.to_list(record.get("tags") or [])
        if feed != "Unknown":
            tags.append(feed.lower())

        context = record.copy()

        item = self.normalize_ioc(
            record=record,
            source="Spamhaus",
            value=value,
            ioc_type=ioc_type,
            description=description,
            raw_text=raw_text,
            raw_iocs=[value],
            first_seen=record.get("collected_at"),
            last_seen=None,
            confidence=None,
            tags=tags,
            context=context
        )
        return [item] if item else []
