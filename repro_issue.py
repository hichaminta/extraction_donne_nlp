
import sys
import os
sys.path.append(os.getcwd())
from regex_extractor import RegexExtractor

extractor = RegexExtractor()
text = "Reference URL: http://恶意.com/files/498e72767ff3644908077592cf08103c.exe and another hash 12345678901234567890123456789012"
iocs = extractor.extract_iocs_from_text(text)

print(f"Text: {text}")
print("Found IOCs:")
for ioc in iocs:
    print(f"- Type: {ioc['ioc_type']} | Value: {ioc['value']}")
