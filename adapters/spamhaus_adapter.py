from .base_adapter import BaseAdapter

class SpamhausAdapter(BaseAdapter):
    """
    Adapter pour Spamhaus (Normalisé).
    """

    def process(self, raw_data):
        ioc_value = raw_data.get("ioc_value")
        feed_name = raw_data.get("feed_name")
        collected_at = raw_data.get("collected_at")

        ioc_record = self.normalize_ioc(
            value=ioc_value,
            ioc_type="ip_or_domain",
            source="Spamhaus",
            description=f"Spamhaus Feed: {feed_name}",
            first_seen=collected_at,
            raw=raw_data
        )

        return [ioc_record]
