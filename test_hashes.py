
import sys
import os
sys.path.append(os.getcwd())
from regex_extractor import RegexExtractor

extractor = RegexExtractor()
# Case 1: Hash inside URL path
text1 = "Download from http://example.com/files/498e72767ff3644908077592cf08103c"
# Case 2: Hash as part of a longer hex string (should NOT match)
text2 = "Long string: 498e72767ff3644908077592cf08103cabc123"
# Case 3: URL that looks like a hash (if that's possible)
text3 = "http://498e72767ff3644908077592cf08103c"

for i, text in enumerate([text1, text2, text3]):
    iocs = extractor.extract_iocs_from_text(text)
    print(f"--- Test {i+1} ---")
    print(f"Text: {text}")
    found = [f"{ioc['value']} ({ioc['ioc_type']})" for ioc in iocs]
    print(f"Found: {', '.join(found) if found else 'None'}")
