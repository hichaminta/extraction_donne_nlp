import requests
import json
import csv
import os
import io

# Local database file
DB_FILE = "urlhaus_full.json"
# URLhaus public CSV recent export (last 30 days)
URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"

def load_data():
    if os.path.exists(DB_FILE):
        with open(DB_FILE, "r", encoding="utf-8") as f:
            try:
                # Load the data, assuming it's a dictionary of URL IDs
                return json.load(f)
            except json.JSONDecodeError:
                print(f"Warning: {DB_FILE} is not a valid JSON. Starting with empty database.")
                return {}
    return {}

def fetch_recent_urls():
    print(f"Fetching recent URLs from {URLHAUS_CSV_URL}...")
    response = requests.get(URLHAUS_CSV_URL)
    response.raise_for_status()
    
    # URLhaus CSV has some comments at the top starting with #
    lines = response.text.splitlines()
    data_lines = [line for line in lines if not line.startswith('#')]
    
    csv_reader = csv.DictReader(io.StringIO("\n".join(data_lines)))
    return list(csv_reader)

def update_database():
    data = load_data()
    initial_count = len(data)
    
    try:
        recent_urls = fetch_recent_urls()
    except Exception as e:
        print(f"Error fetching data from URLhaus: {e}")
        return

    new_entries = 0
    
    for item in recent_urls:
        url_id = item.get("id")
        if url_id and url_id not in data:
            # Match the JSON structure found in urlhaus_full.json
            # Each entry is a list containing the details
            data[url_id] = [{
                "dateadded": item.get("dateadded"),
                "url": item.get("url"),
                "url_status": item.get("url_status"),
                "last_online": item.get("last_online"),
                "threat": item.get("threat"),
                "tags": [tag.strip() for tag in item.get("tags").split(',')] if item.get("tags") else [],
                "urlhaus_link": item.get("urlhaus_link"),
                "reporter": item.get("reporter")
            }]
            new_entries += 1
            
    if new_entries > 0:
        with open(DB_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        print(f"Success: Added {new_entries} new URLs.")
        print(f"Total URLs in {DB_FILE}: {len(data)}")
    else:
        print(f"Update complete. No new URL found. Total URLs remain: {initial_count}")

if __name__ == "__main__":
    update_database()