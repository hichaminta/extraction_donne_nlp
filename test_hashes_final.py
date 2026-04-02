
import sys
import os
sys.path.append(os.getcwd())
from regex_extractor import RegexExtractor

extractor = RegexExtractor()

def test(text):
    print(f"\nTesting: {text}")
    iocs = extractor.extract_iocs_from_text(text)
    if not iocs:
        print("Result: No IOCs found.")
    for ioc in iocs:
        print(f"Result: {ioc['value']} -> {ioc['ioc_type']}")

# Case 1: Hash inside URL
test("Download http://evil.com/498e72767ff3644908077592cf08103c")

# Case 2: Hash outside URL
test("URL http://evil.com/ and MD5 498e72767ff3644908077592cf08103c")

# Case 3: URL that is just a host
test("http://498e72767ff3644908077592cf08103c.com")

# Case 4: Email with hash
test("Contact 498e72767ff3644908077592cf08103c@evil.com")
