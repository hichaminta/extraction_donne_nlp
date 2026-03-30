import json
from regex_extractor import RegexExtractor

def test_nested_extraction():
    extractor = RegexExtractor()
    
    # Item with nested IOCs in context
    item = {
        "source": "test_source",
        "raw_text": "Main alert text",
        "context": {
            "details": {
                "ip_address": "8.8.8.8",
                "other_ips": ["1.1.1.1", "2.2.2.2"],
                "reporter": "admin@example.com",
                "nested": {
                    "url": "http://evil.com/malware"
                }
            },
            "category": "malware"
        }
    }
    
    res = extractor.process_single_item(item)
    
    print("--- Extraction Results ---")
    print(f"Total IOCs extracted: {len(res['iocs'])}")
    if res['iocs']:
        print("\nCleaned context for the first IOC:")
        print(json.dumps(res['iocs'][0]['contexts'][0], indent=2))
        
    for ioc in res['iocs']:
        print(f"Value: {ioc['value']} Type: {ioc['ioc_type']}")
        # Check contexts for other IOC values
        context_str = json.dumps(ioc['contexts'])
        for other in res['iocs']:
            if other['value'] != ioc['value'] and other['value'] in context_str:
                print(f"  [ISSUE] Found other IOC '{other['value']}' in context of '{ioc['value']}'")
            elif other['value'] == ioc['value'] and other['value'] in context_str:
                print(f"  [INFO] Found own IOC '{other['value']}' in context (redundant)")

    # The goal is that for any IOC, the context should not contain OTHER IOCs.
    # Ideally, it should not even contain itself to avoid ANY IOC value in context.

if __name__ == "__main__":
    test_nested_extraction()
