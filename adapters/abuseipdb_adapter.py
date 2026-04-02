from .base_adapter import BaseAdapter
from typing import List

class AbuseipdbAdapter(BaseAdapter):
    def process(self, record: dict) -> List[dict]:
        value = record.get("ipAddress")
        if not value:
            return []

        confidence = record.get("abuseConfidenceScore")
        country_name = record.get("countryName") or record.get("countryCode")
        isp = record.get("isp", "Unknown")
        usage_type = record.get("usageType", "Unknown")
        domain = record.get("domain", "")
        hostnames = record.get("hostnames", [])
        num_users = record.get("numDistinctUsers", 0)

        description = f"Abuse Score: {confidence}% | Country: {country_name} | ISP: {isp} | Usage: {usage_type}"
        if domain:
            description += f" | Domain: {domain}"
        if hostnames:
            first_host = hostnames[0]
            description += f" | Hostnames: {first_host}" + (f" (+{len(hostnames)-1})" if len(hostnames) > 1 else "")
        description += f" | Reporters: {num_users}"
        
        hostnames_str = ", ".join(hostnames) if hostnames else "None"
        raw_text = (
            f"IP: {value}\n"
            f"Score: {confidence}\n"
            f"Reports: {record.get('totalReports')} (from {num_users} users)\n"
            f"Country: {country_name}\n"
            f"ISP: {isp}\n"
            f"Usage Type: {usage_type}\n"
            f"Domain: {domain}\n"
            f"Hostnames: {hostnames_str}\n"
            f"Tor: {record.get('isTor', False)}\n"
            f"Whitelisted: {record.get('isWhitelisted', False)}\n"
            f"Public: {record.get('isPublic', True)}\n"
            f"IP Version: {record.get('ipVersion', 4)}"
        )
        
        reports = record.get("reports", [])
        if reports:
            raw_text += "\n\nRecent Reports:\n"
            for r in reports[:3]:
                comment = r.get("comment", "").replace("\n", " ").strip()
                if len(comment) > 200:
                    comment = comment[:197] + "..."
                raw_text += f"- [{r.get('reportedAt')}] {comment}\n"
        
        context = record.copy()

        tags = []
        if usage_type and usage_type != "Unknown":
            tags.extend([t.strip() for t in usage_type.split("/")])
        if record.get("isTor"):
            tags.append("Tor")
        if record.get("isWhitelisted"):
            tags.append("Whitelisted")

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
            tags=tags,
            context=context
        )
        return [item] if item else []
