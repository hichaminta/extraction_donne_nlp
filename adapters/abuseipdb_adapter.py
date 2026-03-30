from .base_adapter import BaseAdapter
from typing import List

class AbuseipdbAdapter(BaseAdapter):
    def process(self, record: dict) -> List[dict]:
        value = record.get("ipAddress")
        if not value:
            return []

        confidence = record.get("abuseConfidenceScore")
        description = f"Abuse Score: {confidence}% | Country: {record.get('countryCode')}"
        
        raw_text = f"IP: {value}\nScore: {confidence}\nReports: {record.get('totalReports')}"
        
        context = record.copy()

        item = self.normalize_ioc(
            record=record,
            source="AbuseIPDB",
            value=value,
            ioc_type="ip",
            description=description,
            raw_text=raw_text,
            raw_iocs=[value],
            first_seen=record.get("extracted_at"),
            last_seen=record.get("lastReportedAt"),
            confidence=confidence,
            tags=[],
            context=context
        )
        return [item] if item else []
