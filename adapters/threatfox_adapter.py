from .base_adapter import BaseAdapter
from typing import List

class ThreatfoxAdapter(BaseAdapter):
    def process(self, record: dict) -> List[dict]:
        value = record.get("ioc")
        if not value:
            return []

        malware = record.get("malware")
        threat_type = record.get("threat_type")
        description = f"Malware: {malware or 'Unknown'} | Threat Type: {threat_type or 'Unknown'}"
        
        # Enrichissement de la description avec le contexte existant
        if record.get("ioc_type_desc"):
            description += f" | IOC: {record.get('ioc_type_desc')}"

        tags = self.to_list(record.get("tags") or [])
        if malware and malware not in tags:
            tags.append(malware)
        if threat_type and threat_type not in tags:
            tags.append(threat_type)

        context = record.copy()  # On garde tout le record dans le contexte

        item = self.normalize_ioc(
            record=record,
            source="ThreatFox",
            value=value,
            ioc_type=record.get("ioc_type"),
            description=description,
            raw_iocs=[value],
            raw_text=description,
            first_seen=record.get("first_seen"),
            last_seen=record.get("last_seen"),
            confidence=record.get("confidence_level"),
            tags=tags,
            context=context
        )
        return [item] if item else []
