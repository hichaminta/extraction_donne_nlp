import json

path = 'c:/Users/Hicham/Desktop/PFE/extraction_donne/unified_output/unified_iocs.jsonl'
output_path = 'c:/Users/Hicham/Desktop/PFE/extraction_donne/example_ioc.json'

with open(path, 'r', encoding='utf-8') as f:
    for line in f:
        data = json.loads(line)
        unique_sources = set(s['source'] for s in data.get('sources', []))
        if len(unique_sources) > 1:
            with open(output_path, 'w', encoding='utf-8') as out:
                json.dump(data, out, indent=2)
            break
