from .base_adapter import BaseAdapter

class AbuseipdbAdapter(BaseAdapter):
    """
    Adapter pour AbuseIPDB (Normalisé).
    """

    def process(self, raw_data):
        ip = raw_data.get("ipAddress")
        score = raw_data.get("abuseConfidenceScore")
        last_reported = raw_data.get("lastReportedAt")

        # Normalisation vers format IOC Standard
        ioc_record = self.normalize_ioc(
            value=ip,
            ioc_type="ip",
            source="AbuseIPDB",
            description=f"Abuse Confidence Score: {score}%",
            confidence=score,
            last_seen=last_reported,
            raw=raw_data
        )

        return [ioc_record]
