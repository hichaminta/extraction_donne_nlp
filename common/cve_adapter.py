from pathlib import Path
from common.base import load_json, load_jsonl, normalize_date, BaseAdapter
from common.entity_extractor import extract_entities_from_texts

class CveAdapter(BaseAdapter):
    def __init__(self, root_dir: Path):
        super().__init__(root_dir)
        self.cves = {}
        
    def _add_cve(self, cve_id: str, source: str, source_record_id: str, published_at: str, description: str = None):
        pub_date = normalize_date(published_at)
        if cve_id not in self.cves:
            self.cves[cve_id] = {
                "cve_id": cve_id,
                "sources": [],
                "first_seen": pub_date,
                "last_seen": pub_date,
                "descriptions": set(),
                "tags": set()
            }
        
        cve = self.cves[cve_id]
        source_info = {"source": source, "source_record_id": str(source_record_id)}
        if source_info not in cve["sources"]:
            cve["sources"].append(source_info)
            
        if pub_date:
            if not cve["first_seen"] or pub_date < cve["first_seen"]:
                cve["first_seen"] = pub_date
            if not cve["last_seen"] or pub_date > cve["last_seen"]:
                cve["last_seen"] = pub_date
                
        if description:
            cve["descriptions"].add(description)

    def process_nvd_cisa(self):
        path = self._check_file("nvd_cisa/cve_data.json")
        if not path: return
        
        payload = load_json(path)
        cves = payload.get("cves", {}) if isinstance(payload, dict) else {}
        for cve_id, row in cves.items():
            self._add_cve(cve_id, "nvd_cisa", cve_id, row.get("published"), description=row.get("description"))

    def process_dgssi(self):
        path = self._check_file("Cert/dgssi_bulletins.jsonl")
        if not path: return
        
        for row in load_jsonl(path):
            date_val = row.get("date")
            for cve in row.get("cves", []):
                self._add_cve(cve, "dgssi", row.get("url"), date_val, description=row.get("title"))

            text_fragments = [row.get("title"), row.get("raw_text_sample")]
            extracted = extract_entities_from_texts(text_fragments)
            for cve in extracted.get("cves", []):
                self._add_cve(cve, "dgssi", row.get("url"), date_val, description=row.get("title"))

    def run_all(self):
        self.process_nvd_cisa()
        self.process_dgssi()
        
        result = []
        for cve_data in self.cves.values():
            cve_data["tags"] = sorted(list(cve_data["tags"]))
            cve_data["descriptions"] = list(cve_data["descriptions"])
            result.append(cve_data)
        return result
