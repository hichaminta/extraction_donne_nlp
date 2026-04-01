# NLP IOC Extraction Suitability Analysis

This report identifies and evaluates the data sources within the `extraction_donne_nlp` project that contain unstructured text suitable for Natural Language Processing (NLP) to extract Indicators of Compromise (IOCs) and Contextual Threat Intelligence.

## Summary of Findings

The following sources provide the most value for NLP-based analysis due to their rich, descriptive, and unstructured nature.

| Source | Location | NLP Potential | Primary Content |
| :--- | :--- | :--- | :--- |
| **DGSSI** | `output_adapters/dgssi_adapter.json` | 🔴 **Very High** | Security bulletins in French (vulnerabilities, impacts, solutions). |
| **OTX AlienVault** | `Otx alienvault/otx_pulses.json` | 🔴 **Very High** | Detailed threat campaign descriptions, TTPs, and actor behaviors. |
| **NVD (CVEs)** | `output_adapters/nvd_adapter.json` | 🟡 **High** | English descriptions of software vulnerabilities and attack vectors. |
| **Pulsedive** | `pulsedive/pulsedive_iocs.json` | ⚪ **Low** | Mostly structured risk scores; some brief descriptive metadata. |

---

## Detailed Analysis by Source

### 1. DGSSI (Cert-MA)
- **Status**: Already partially integrated into an NLP pipeline.
- **Content**: Detailed bulletins describing recent threats.
- **NLP Value**:
    - **Named Entity Recognition (NER)**: Extracting URLs, IPs, and CVE IDs mentioned in the text that might not be in the structured headers.
    - **Categorization**: Classifying the severity or type of threat (e.g., Ransomware vs. Phishing) based on description.
    - **Language**: French (requires French NLP models like `CamemBERT` or `Spacy` French pipelines).

### 2. OTX AlienVault (Pulses)
- **Status**: Raw JSON available in `Otx alienvault/otx_pulses.json`.
- **Content**: "Pulses" contributed by the community. Each pulse has a `description` field that can be several paragraphs long.
- **NLP Value**:
    - **Campaign Extraction**: Linking multiple indicators together through descriptions of threat campaigns.
    - **Behavior Prediction**: Analyzing descriptions to find common techniques (MITRE ATT&CK mapping).
    - **Language**: Primarily English.

### 3. NVD (National Vulnerability Database)
- **Status**: Large dataset adapted in `output_adapters/nvd_adapter.json`.
- **Content**: Standardized vulnerability descriptions.
- **NLP Value**:
    - **Product/Version Extraction**: Identifying specific software versions affected as mentioned in text.
    - **Attack Vector Analysis**: Determining if a vulnerability is "Remote Code Execution", "Local Privilege Escalation", etc., from narrative text.
    - **Language**: English.

### 4. Sources Not Suitable for NLP
The following sources are **highly structured** and provide little to no benefit for NLP because the data is already parsed into fields (IP, Port, Hash, etc.):
- **AbuseIPDB**: Numerical scores and status messages.
- **MalwareBazaar / ThreatFox / FeodoTracker**: Pure lists of hashes and IPs with pre-selected tags.
- **PhishTank / OpenPhish**: Pure URL lists.
- **Spamhaus**: Numeric IP ranges.

## Recommendations for NLP Pipeline

1. **Prioritize DGSSI**: Continue the work on `nlp_extart_dgsi.py` as it handles the most linguistically complex data in the repository.
2. **Adapter for OTX**: Currently, OTX data exists in a raw format. A new adapter should be created to standardize it into `output_adapters/` while preserving the long `description` field for NLP.
3. **NVD Enrichment**: Use NLP to extract mentioned links (URLs) from NVD descriptions to find more IOCs.

> [!IMPORTANT]
> The **OTX pulses** file is large (~96MB). Any NLP processing should use batching or streaming to avoid memory overflows.
