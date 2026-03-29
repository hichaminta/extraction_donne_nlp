from .base_adapter import BaseAdapter

class UrlhausAdapter(BaseAdapter):
    """
    Adapter pour URLHaus (Normalisé).
    """

    def process(self, raw_data):
        normalized_results = []
        
        # URLHaus peut être une liste ou un objet unique
        items = self.to_list(raw_data)
        
        for item in items:
            url = item.get("url")
            status = item.get("url_status")
            reporter = item.get("reporter")
            tags = item.get("tags")
            collected_at = item.get("date_added")

            ioc_record = self.normalize_ioc(
                value=url,
                ioc_type="url",
                source="URLHaus",
                description=f"Status: {status} | Reporter: {reporter}",
                tags=tags,
                first_seen=collected_at,
                raw=item
            )
            normalized_results.append(ioc_record)

        return normalized_results
