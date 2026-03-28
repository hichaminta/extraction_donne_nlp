from pathlib import Path
from common.base import load_json, load_jsonl, ensure_list, normalize_date, BaseAdapter
from common.entity_extractor import extract_entities_from_texts

class IocAdapter(BaseAdapter):
    def __init__(self, root_dir: Path):
        super().__init__(root_dir)
        self.iocs = {}
        
    def _add_ioc(self, type_: str, value: str, source: str, source_record_id: str, published_at: str, tags: list = None):
        if not type_ or not value:
            return
            
        pub_date = normalize_date(published_at)
        ioc_key = f"{type_}:{value}"
        
        if ioc_key not in self.iocs:
            self.iocs[ioc_key] = {
                "ioc_type": type_,
                "ioc_value": value,
                "sources": [],
                "first_seen": pub_date,
                "last_seen": pub_date,
                "tags": set()
            }
            
        ioc = self.iocs[ioc_key]
        source_info = {"source": source, "source_record_id": str(source_record_id)}
        if source_info not in ioc["sources"]:
            ioc["sources"].append(source_info)
            
        if pub_date:
            if not ioc["first_seen"] or pub_date < ioc["first_seen"]:
                ioc["first_seen"] = pub_date
            if not ioc["last_seen"] or pub_date > ioc["last_seen"]:
                ioc["last_seen"] = pub_date
                
        if tags:
            ioc["tags"].update(tags)

    def process_threatfox(self):
        path = self._check_file("ThreatFox/threatfox_data.json")
        if not path: return
        for row in load_json(path):
            self._add_ioc(row.get("ioc_type"), row.get("ioc"), "threatfox", row.get("id"), row.get("first_seen"), tags=row.get("tags"))

    def process_otx(self):
        path = self._check_file("Otx alienvault/otx_pulses.json")
        if not path: return
        for row in load_json(path):
            for ind in ensure_list(row.get("indicators")):
                if isinstance(ind, dict):
                    t = ind.get("type") or ind.get("indicator_type")
                    v = ind.get("indicator") or ind.get("indicator_value")
                    self._add_ioc(t, v, "otx", row.get("id"), row.get("created"), tags=row.get("tags"))

    def process_abuseipdb(self):
        path = self._check_file("AbuseIPDB/abuseipdb_data.json")
        if not path: return
        for row in load_json(path):
            self._add_ioc("ip", row.get("ipAddress"), "abuseipdb", row.get("ipAddress"), row.get("lastReportedAt"))

    def process_openphish(self):
        path = self._check_file("OpenPhish/openphish_data.json")
        if not path: return
        for row in load_json(path):
            self._add_ioc("url", row.get("url"), "openphish", row.get("url"), row.get("first_seen"))

    def process_feodotracker(self):
        path = self._check_file("feodotracker/feodo_data.json")
        if not path: return
        for row in load_json(path):
            self._add_ioc(row.get("ioc_type"), row.get("ioc_value"), "feodotracker", row.get("ioc_value"), row.get("first_seen_utc"))
            if row.get("hostname"):
                self._add_ioc("domain", row.get("hostname"), "feodotracker", row.get("ioc_value"), row.get("first_seen_utc"))

    def process_malwarebazaar(self):
        path = self._check_file("MalwareBazaar Community API/malwarebazaar_data.json")
        if not path: return
        for row in load_json(path):
            self._add_ioc("md5", row.get("md5_hash"), "malwarebazaar", row.get("sha256_hash"), row.get("first_seen"), tags=row.get("tags"))
            self._add_ioc("sha1", row.get("sha1_hash"), "malwarebazaar", row.get("sha256_hash"), row.get("first_seen"), tags=row.get("tags"))
            self._add_ioc("sha256", row.get("sha256_hash"), "malwarebazaar", row.get("sha256_hash"), row.get("first_seen"), tags=row.get("tags"))

    def process_virustotal(self):
        path = self._check_file("VirusTotal/virustotal_enrichment.json")
        if not path: return
        for row in load_json(path):
            self._add_ioc(row.get("indicator_type"), row.get("indicator"), "virustotal", row.get("vt_id") or row.get("indicator"), row.get("last_analysis_date"), tags=row.get("tags"))

    def process_cins_army(self):
        path = self._check_file("CINS Army/cins_army.json")
        if not path: return
        for row in load_json(path):
            self._add_ioc(row.get("type"), row.get("indicator"), "cins_army", row.get("hash") or row.get("indicator"), row.get("collected_at"))

    def process_spamhaus(self):
        path = self._check_file("Spamhaus/spamhaus_data.json")
        if not path: return
        payload = load_json(path)
        for row in payload.get("iocs", []):
            self._add_ioc(row.get("ioc_type"), row.get("ioc_value"), "spamhaus", f"{row.get('feed_name')}:{row.get('ioc_value')}", row.get("collected_at"))

    def process_urlhaus(self):
        path = self._check_file("url/urlhaus_full.json")
        if not path: return
        payload = load_json(path)
        for url_id, entries in payload.items():
            for row in ensure_list(entries):
                if isinstance(row, dict):
                    self._add_ioc("url", row.get("url"), "urlhaus", url_id, row.get("dateadded"), tags=row.get("tags"))

    def process_pulsedive(self):
        path = self._check_file("pulsedive/pulsedive_iocs.json")
        if not path: return
        for row in load_json(path):
            self._add_ioc(row.get("type"), row.get("indicator"), "pulsedive", row.get("indicator"), row.get("first_seen"))

    def process_dgssi_iocs(self):
        path = self._check_file("Cert/dgssi_bulletins.jsonl")
        if not path: return
        for row in load_jsonl(path):
            date_val = row.get("date")
            text_fragments = [row.get("title"), row.get("raw_text_sample")]
            extracted = extract_entities_from_texts(text_fragments)
            for ioc in extracted.get("iocs", []):
                self._add_ioc(ioc["type"], ioc["value"], "dgssi", row.get("url"), date_val)
                
    def run_all(self):
        self.process_threatfox()
        self.process_otx()
        self.process_abuseipdb()
        self.process_openphish()
        self.process_feodotracker()
        self.process_malwarebazaar()
        self.process_virustotal()
        self.process_cins_army()
        self.process_spamhaus()
        self.process_urlhaus()
        self.process_pulsedive()
        self.process_dgssi_iocs()

        result = []
        for ioc_data in self.iocs.values():
            ioc_data["tags"] = sorted(list(ioc_data["tags"]))
            result.append(ioc_data)
        return result
