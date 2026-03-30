# Documentation : Unification des Formats IOC & CVE

Ce document définit les formats attendus pour chaque source de données et le schéma unifié utilisé par le pipeline d'extraction.

## 1. Schéma Unifié (Unified Schema)

Tous les adaptateurs (`adapters/`) doivent transformer les données brutes en ces formats standardisés.

### Objet IOC Standard
| Champ | Type | Description |
| :--- | :--- | :--- |
| `type` | string | Fixe : `"ioc"` |
| `value` | string | L'indicateur lui-même (ex: IP, URL) |
| `ioc_type` | string | Catégorie (ip, domain, url, hash, etc.) |
| `source` | string | Nom de la source (ex: AbuseIPDB) |
| `description` | string | Description lisible par l'homme |
| `raw_text` | string | Texte complet pour l'analyse NLP |
| `tags` | list | Tags associés (malware, acteur, etc.) |
| `context` | object | Copie intégrale du record source (lossless) |

### Objet CVE Standard
| Champ | Type | Description |
| :--- | :--- | :--- |
| `type` | string | Fixe : `"cve"` |
| `cve_id` | string | Identifiant CVE (ex: CVE-2023-...) |
| `severity` | string | Niveau de criticité |
| `cvss` | number | Score CVSS |

---

## 2. Analyse par Source (Expected Formats)

| Source | Format Entrée | Type IOC Dominant | Champ Valeur Source |
| :--- | :--- | :--- | :--- |
| **AbuseIPDB** | API JSON | `ip` | `ipAddress` |
| **ThreatFox** | JSON | `ip:port`, `domain`, `hash` | `ioc` |
| **MalwareBazaar** | JSON | `hash` (sha256) | `sha256_hash` |
| **PhishTank** | JSON | `url` | `url` |
| **OpenPhish** | Text/JSON | `url` | `url` |
| **DGSSI** | JSONL | `bulletin`, `cve` | `title`, `cves` |
| **NVD** | JSON | `cve` | `cve_id` |
| **OTX** | JSON | multi-type | `indicator` |

---

## 3. Recommandations NLP

Pour que l'extraction NLP soit efficace, les champs suivants sont **obligatoires** dans les sorties des adaptateurs :
1.  **`raw_text`** : Doit contenir la description textuelle brute.
2.  **`source`** : Indispensable pour choisir le modèle de langue (Français pour DGSSI, Anglais pour les autres).
3.  **`raw_cves`** : Liste des CVE mentionnées pour permettre la corrélation automatique.

---
*Note : Ce schéma est implémenté dans `adapters/base_adapter.py` via les méthodes `normalize_ioc` et `normalize_cve`.*
