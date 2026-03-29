from .base_adapter import BaseAdapter

class PulsediveAdapter(BaseAdapter):
    """
    Adapter pour Pulsedive (Normalisé).
    """

    def process(self, raw_data):
        indicator = raw_data.get("indicator")
        ioc_type = raw_data.get("type")
        risk = raw_data.get("risk")
        threats = raw_data.get("threats")
        collected_at = raw_data.get("collected_at")

        ioc_record = self.normalize_ioc(
            value=indicator,
            ioc_type=ioc_type,
            source="Pulsedive",
            description=f"Risk Level: {risk} | Threats: {threats}",
            confidence=risk,
            first_seen=collected_at,
            raw=raw_data
        )

        return [ioc_record]
