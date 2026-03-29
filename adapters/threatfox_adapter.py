from .base_adapter import BaseAdapter

class ThreatfoxAdapter(BaseAdapter):
    """
    Adapter pour ThreatFox (Normalisé).
    """

    def process(self, raw_data):
        ioc = raw_data.get("ioc")
        ioc_type = raw_data.get("ioc_type")
        malware = raw_data.get("malware")
        threat_type = raw_data.get("threat_type")
        first_seen = raw_data.get("first_seen")

        ioc_record = self.normalize_ioc(
            value=ioc,
            ioc_type=ioc_type,
            source="ThreatFox",
            description=f"Malware: {malware} | Threat Type: {threat_type}",
            tags=[malware, threat_type] if malware and threat_type else None,
            first_seen=first_seen,
            raw=raw_data
        )

        return [ioc_record]
