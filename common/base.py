import json
from pathlib import Path
from datetime import datetime, timezone

def load_json(path: Path):
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)

def load_jsonl(path: Path):
    items = []
    with path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            items.append(json.loads(line))
    return items

def ensure_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]

def normalize_date(date_val) -> str:
    if not date_val:
        return ""
    if isinstance(date_val, int) or (isinstance(date_val, str) and date_val.isdigit()):
        try:
            return datetime.fromtimestamp(int(date_val), timezone.utc).isoformat()
        except Exception:
            pass
    return str(date_val)

class BaseAdapter:
    def __init__(self, root_dir: Path):
        self.root_dir = root_dir
        self.processed_files = []
        self.missing_files = []
        
    def _check_file(self, rel_path: str):
        path = self.root_dir / rel_path
        if not path.exists():
            self.missing_files.append(rel_path)
            return None
        self.processed_files.append(rel_path)
        return path
