from .base_adapter import BaseAdapter
from typing import List

class PulsediveAdapter(BaseAdapter):
    def process(self, record: dict) -> List[dict]:
        value = record.get("indicator")
        if not value:
            return []

        risk = record.get("risk")
        threats = record.get("threats") or record.get("threat")
        description = f"Risk Level: {risk or 'Unknown'} | Threats: {threats or 'None'}"
        
        raw_text = f"Indicator: {value}\nRisk: {risk}\nThreats: {threats}"
        tags = self.to_list(record.get("tags") or [])
        if threats and isinstance(threats, str):
            tags.append(threats)

        context = record.copy()

        item = self.normalize_ioc(
            record=record,
            source="Pulsedive",
            value=value,
            ioc_type=record.get("type"),
            description=description,
            raw_text=raw_text,
            raw_iocs=[value],
            first_seen=record.get("first_seen"),
            last_seen=record.get("last_seen"),
            confidence=risk,
            tags=tags,
            context=context
        )
        return [item] if item else []
