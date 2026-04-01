from regex_extractor import RegexExtractor
import json

def test_extraction():
    extractor = RegexExtractor()
    
    print("=== Test 1: IP Fusion ===")
    text1 = "L'IP 1.2.3.4:80 est suspecte, tout comme 1.2.3.4:443 et 1.2.3.4."
    res1 = extractor.extract_iocs_from_text(text1)
    print(f"Text: {text1}")
    print(f"Result: {json.dumps(res1, indent=2)}")
    # Expected: 1 IOC for 1.2.3.4 with ports [80, 443]
    ips = [r for r in res1 if r["value"] == "1.2.3.4"]
    if len(ips) == 1 and set(ips[0].get("ports", [])) == {"80", "443"}:
        print("Test 1 PASSED")
    else:
        print("Test 1 FAILED")

    print("\n=== Test 2: CVE Normalization ===")
    text2 = "Voir le bulletin 2021-32628 et CVE-2022-1234."
    res2 = extractor.process_single_item({"description": text2})
    print(f"Text: {text2}")
    cve_ids = [c["cve_id"] for c in res2["cves"]]
    print(f"CVEs: {cve_ids}")
    if "CVE-2021-32628" in cve_ids and "CVE-2022-1234" in cve_ids:
        print("Test 2 PASSED")
    else:
        print("Test 2 FAILED")

    print("\n=== Test 3: Metadata Redaction Exception ===")
    item3 = {
        "description": "Exploit pour CVE-2021-9999",
        "context": {"cve_id": "CVE-2021-9999", "other": "secret_value"}
    }
    res3 = extractor.process_single_item(item3)
    # The context in the resulting CVE should have cve_id preserved but other redacted if matches
    ctx = res3["cves"][0]["contexts"][0]
    print(f"Cleaned Context: {ctx}")
    if ctx.get("cve_id") == "CVE-2021-9999":
        print("Test 3 PASSED (cve_id preserved)")
    else:
        print("Test 3 FAILED")

    print("\n=== Test 4: Auto-extraction from Context ===")
    item4 = {
        "description": "Pas de CVE ici mais dans le contexte",
        "context": {"cve_id": "2023-5555"}
    }
    res4 = extractor.process_single_item(item4)
    cve_ids4 = [c["cve_id"] for c in res4["cves"]]
    print(f"Extracted CVEs: {cve_ids4}")
    if "CVE-2023-5555" in cve_ids4:
        print("Test 4 PASSED")
    else:
        print("Test 4 FAILED")

if __name__ == "__main__":
    test_extraction()
