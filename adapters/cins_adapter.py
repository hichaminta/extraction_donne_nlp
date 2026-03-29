from .base_adapter import BaseAdapter

class CinsAdapter(BaseAdapter):
    """
    Adapter pour CINS Army (Normalisé).
    """

    def process(self, raw_data):
        ip = raw_data.get("indicator")
        threat = raw_data.get("threat")
        collected_at = raw_data.get("collected_at")

        ioc_record = self.normalize_ioc(
            value=ip,
            ioc_type="ip",
            source="CINS Army",
            description=f"Threat type: {threat}",
            first_seen=collected_at,
            raw=raw_data
        )

        return [ioc_record]
