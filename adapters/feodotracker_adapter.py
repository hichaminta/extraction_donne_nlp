from .base_adapter import BaseAdapter

class FeodotrackerAdapter(BaseAdapter):
    """
    Adapter pour FeodoTracker (Normalisé).
    """

    def process(self, raw_data):
        ip = raw_data.get("ip_address")
        malware = raw_data.get("malware")
        status = raw_data.get("status")
        port = raw_data.get("port")
        first_seen = raw_data.get("first_seen")

        ioc_record = self.normalize_ioc(
            value=ip,
            ioc_type="ip",
            source="FeodoTracker",
            description=f"Malware: {malware} | Port: {port} | Status: {status}",
            first_seen=first_seen,
            raw=raw_data
        )

        return [ioc_record]
