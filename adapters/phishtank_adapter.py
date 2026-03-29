from .base_adapter import BaseAdapter

class PhishtankAdapter(BaseAdapter):
    """
    Adapter pour PhishTank (Normalisé).
    """

    def process(self, raw_data):
        url = raw_data.get("url")
        submission_time = raw_data.get("submission_time")
        verified = raw_data.get("verified")

        ioc_record = self.normalize_ioc(
            value=url,
            ioc_type="url",
            source="PhishTank",
            description=f"PhisTank ID: {raw_data.get('phish_id')} | Verified: {verified}",
            first_seen=submission_time,
            raw=raw_data
        )

        return [ioc_record]
