from .base_adapter import BaseAdapter
from typing import List

class PhishtankAdapter(BaseAdapter):
    def process(self, record: dict) -> List[dict]:
        value = record.get("url")
        if not value:
            return []

        description = record.get("description") or "Phishing URL reported"
        raw_text = f"URL: {value}\nSource: PhishTank\nSubmission: {record.get('submission_time')}\nVerified: {record.get('verification_time')}"
        
        context = record.copy()

        item = self.normalize_ioc(
            record=record,
            source="PhishTank",
            value=value,
            ioc_type="url",
            description=description,
            raw_text=raw_text,
            raw_iocs=[value],
            first_seen=record.get("submission_time"),
            last_seen=record.get("verification_time"),
            confidence=None,
            tags=["phishing"],
            context=context
        )
        return [item] if item else []
