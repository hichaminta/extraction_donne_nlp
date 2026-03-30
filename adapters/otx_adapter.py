from .base_adapter import BaseAdapter
from typing import List

class OtxAdapter(BaseAdapter):
    def process(self, record: dict) -> List[dict]:
        value = record.get("indicator")
        if not value:
            return []

        pulse_title = record.get("pulse_title") or "Unknown Pulse"
        pulse_description = record.get("pulse_description") or ""
        
        description = f"OTX Pulse: {pulse_title}"
        if pulse_description:
            description += f" | Description: {pulse_description}"

        raw_text = f"Title: {pulse_title}\nDescription: {pulse_description}"
        tags = self.to_list(record.get("tags") or [])
        
        context = record.copy()

        item = self.normalize_ioc(
            record=record,
            source="OTX AlienVault",
            value=value,
            ioc_type=record.get("type"),
            description=description,
            raw_text=raw_text,
            raw_iocs=[value],
            first_seen=record.get("created"),
            last_seen=record.get("modified"),
            confidence=None,
            tags=tags,
            context=context
        )
        return [item] if item else []
