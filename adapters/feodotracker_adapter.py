from .base_adapter import BaseAdapter
from typing import List

class FeodotrackerAdapter(BaseAdapter):
    def process(self, record: dict) -> List[dict]:
        value = record.get("ioc_value")
        if not value:
            return []

        malware = record.get("malware_family")
        port = record.get("port")
        status = record.get("c2_status")
        description = f"Malware: {malware or 'Unknown'} | Port: {port or 'N/A'} | Status: {status or 'Unknown'}"
        
        raw_text = f"IOC: {value}\nMalware: {malware}\nPort: {port}\nStatus: {status}\nAS: {record.get('as_name')}"
        tags = self.to_list(record.get("tags") or [])
        if malware:
            tags.append(malware)
        if status:
            tags.append(status)

        context = record.copy()

        item = self.normalize_ioc(
            record=record,
            source="FeodoTracker",
            value=value,
            ioc_type="ip",
            description=description,
            raw_text=raw_text,
            raw_iocs=[value],
            first_seen=record.get("first_seen_utc"),
            last_seen=record.get("last_online"),
            confidence=None,
            tags=tags,
            context=context
        )
        return [item] if item else []
