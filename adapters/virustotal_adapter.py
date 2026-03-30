from .base_adapter import BaseAdapter
from typing import List

class VirustotalAdapter(BaseAdapter):
    def process(self, record: dict) -> List[dict]:
        value = record.get("indicator")
        if not value:
            return []

        stats = record.get("stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        reputation = record.get("reputation", 0)
        
        description = f"Malicious: {malicious} | Suspicious: {suspicious} | Reputation Score: {reputation}"
        if record.get("meaningful_name"):
            description += f" | Name: {record.get('meaningful_name')}"
        
        raw_text = f"Indicator: {value}\nDescription: {description}\nMetadata: {record.get('as_owner', '')} {record.get('country', '')}"
        tags = self.to_list(record.get("tags") or [])
        
        context = record.copy()

        item = self.normalize_ioc(
            record=record,
            source="VirusTotal",
            value=value,
            ioc_type=record.get("indicator_type"),
            description=description,
            raw_text=raw_text,
            raw_iocs=[value],
            first_seen=record.get("enriched_at"),
            last_seen=record.get("last_modification_date"),
            confidence=reputation,
            tags=tags,
            context=context
        )
        return [item] if item else []
