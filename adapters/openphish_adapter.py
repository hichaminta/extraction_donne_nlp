from .base_adapter import BaseAdapter

class OpenphishAdapter(BaseAdapter):
    """
    Adapter pour OpenPhish (Normalisé).
    """

    def process(self, raw_data):
        url = raw_data.get("url")
        collected_at = raw_data.get("collected_at")

        ioc_record = self.normalize_ioc(
            value=url,
            ioc_type="url",
            source="OpenPhish",
            first_seen=collected_at,
            raw=raw_data
        )

        return [ioc_record]
