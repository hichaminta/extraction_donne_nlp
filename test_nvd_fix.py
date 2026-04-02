
import json
from adapters.nvd_adapter import NvdAdapter

def test_nvd_enrichment():
    adapter = NvdAdapter()
    
    # Simulation d'un record de NVD/CISA
    record = {
      "cve_id": "CVE-2024-1234",
      "description": "Exemple de faille critique",
      "cvss": [
          {
              "score": 9.8,
              "version": "3.1"
          }
      ],
      "published": "2024-01-01"
    }
    
    results = adapter.process(record)
    assert len(results) > 0
    item = results[0]
    
    print("Normalisation CVE :")
    print(f"ID: {item['cve_id']}")
    print(f"Sévérité: {item['severity']}")
    print(f"CVSS Data: {item['cvss']}")
    print(f"Description: {item['description']}")
    
    # Vérifications
    assert item['severity'] == "CRITICAL"
    assert item['cvss'][0]['score'] == 9.8
    assert item['description'] == "Exemple de faille critique"
    
    print("\nSUCCESS: L'enrichissement score/version fonctionne !")

if __name__ == "__main__":
    test_nvd_enrichment()
