from .base_adapter import BaseAdapter

class VirustotalAdapter(BaseAdapter):
    """
    Adapter pour VirusTotal (Normalisé).
    """

    def process(self, raw_data):
        target = raw_data.get("target")
        target_type = raw_data.get("target_type")
        reputation = raw_data.get("reputation")
        stats = raw_data.get("last_analysis_stats", {})
        tags = raw_data.get("tags")
        
        # On calcule un résumé des détections
        malicious = stats.get("malicious", 0)
        total = sum(stats.values()) if stats else 0
        
        ioc_record = self.normalize_ioc(
            value=target,
            ioc_type=target_type,
            source="VirusTotal",
            description=f"Detections: {malicious}/{total} | Reputation Score: {reputation}",
            confidence=reputation,
            tags=tags,
            raw=raw_data
        )

        return [ioc_record]
