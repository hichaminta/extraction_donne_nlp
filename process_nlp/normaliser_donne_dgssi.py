import json
import re
import logging
import html

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class DGSSIProcessorStage1:
    def __init__(self):
        # Regex pour les CVE
        self.cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
        # Regex contextuelle pour le bulletin_id (Numéro de référence)
        # Gère le cas "Numéro de Référence\nNuméro de Référence\nID"
        self.id_context_pattern = re.compile(
            r"Numéro de Référence\s+(?:Numéro de Référence\s+)?([\d/]+)", 
            re.IGNORECASE | re.MULTILINE
        )

    def clean_text(self, text):
        """Corrige l'encodage, supprime le bruit et normalise les espaces."""
        if not text:
            return ""
        
        # 1. Correction manuelle des artefacts d'encodage courants (UTF-8 lu comme Latin-1)
        replacements = {
            "Ã©": "é", "Ã": "à", "Ã¨": "è", "Ã ": "à", "Ã¹": "ù",
            "Ã¢": "â", "Ãª": "ê", "Ã®": "î", "Ã´": "ô", "Ã»": "û",
            "Ã«": "ë", "Ã¯": "ï", "Ã¼": "ü", "Ã§": "ç", "Â«": "«",
            "Â»": "»", "â€™": "'", "â€": '"', "â€œ": '"', "Ã‰": "É",
            "Â": ""
        }
        for bad, good in replacements.items():
            text = text.replace(bad, good)

        # 2. Unescape HTML entities
        text = html.unescape(text)

        # 3. Nettoyage du bruit (Navigation, Pied de page DGSSI)
        noise_markers = [
            "Main navigation", "S.I sensibles des IIV", "www.e-blagh.ma",
            "contact-dsr@dgssi.gov.ma", "Siège de la DGSSI", "All rights reserved"
        ]
        lines = text.split('\n')
        clean_lines = []
        for line in lines:
            if not any(marker in line for marker in noise_markers):
                clean_lines.append(line.strip())
        
        # 4. Normalisation des espaces
        text = "\n".join([l for l in clean_lines if l])
        text = re.sub(r'[ \t]+', ' ', text)
        return text.strip()

    def extract_bulletin_id(self, text):
        """Extraction robuste du bulletin_id."""
        match = self.id_context_pattern.search(text)
        if match:
            return match.group(1).strip()
        
        # Fallback : chercher un pattern type XXXXXXXX/XX n'importe où
        fallback = re.search(r'\b\d{8}/\d{2}\b', text)
        return fallback.group(0) if fallback else "Unknown"

    def parse_sections(self, text):
        """Sépare le texte nettoyé en sections clés via des ancres textuelles."""
        sections = {
            "affected_systems": [],
            "risk_level": "Inconnu",
            "impact_level": "Inconnu",
            "description": "",
            "solution": "",
            "risks": [],
            "references": []
        }

        # Mapping des ancres DGSSI vers nos clés
        mapping = {
            "Systèmes affectés": "affected_systems",
            "Niveau de Risque": "risk_level",
            "Niveau d'Impact": "impact_level",
            "Bilan de la vulnérabilité": "description",
            "Solution": "solution",
            "Risque": "risks",
            "Référence": "references",
            "Annexe": "references"
        }

        lines = text.split('\n')
        current_key = None

        for i, line in enumerate(lines):
            found_anchor = False
            for anchor, key in mapping.items():
                if anchor.lower() in line.lower() and len(line) < len(anchor) + 5:
                    current_key = key
                    found_anchor = True
                    break
            
            if found_anchor or not current_key:
                continue

            # Accumulation des données par section
            val = line.strip()
            if current_key in ["affected_systems", "risks", "references"]:
                if val not in sections[current_key]:
                    sections[current_key].append(val)
            elif current_key in ["risk_level", "impact_level"]:
                # Prend la ligne juste après l'ancre si elle est courte
                if sections[current_key] == "Inconnu":
                    sections[current_key] = val
            else:
                sections[current_key] = (sections[current_key] + " " + val).strip()

        return sections

    def extract_all_cves(self, bulletin, clean_text):
        """Récupère les CVE depuis toutes les sources possibles."""
        cves = set()
        
        # 1. Depuis les champs bruts
        if bulletin.get("raw_cves"):
            cves.update(bulletin["raw_cves"])
        if bulletin.get("cve_id"):
            cves.add(bulletin["cve_id"])
        
        # 2. Depuis le texte (Regex)
        found_in_text = self.cve_pattern.findall(clean_text)
        cves.update([c.upper() for c in found_in_text])
        
        return sorted(list(cves))

    def normalize_bulletin(self, raw_bulletin):
        """Transforme un bulletin brut en format Stage 1."""
        try:
            # Extraction du texte source
            raw_text = raw_bulletin.get("context", {}).get("raw_text_sample") or raw_bulletin.get("description", "")
            
            # Nettoyage
            clean_txt = self.clean_text(raw_text)
            
            # Extraction structurelle
            sections = self.parse_sections(clean_txt)
            bulletin_id = self.extract_bulletin_id(clean_txt)
            
            # Si la description est vide dans les sections, utiliser le champ description de base
            final_desc = sections["description"] if sections["description"] else raw_bulletin.get("description", "")
            if len(final_desc) > 500 and "Main navigation" in final_desc: # Si la description de base est aussi sale
                final_desc = "Résumé non extrait proprement"

            output = {
                "source": "dgssi",
                "bulletin_id": bulletin_id,
                "bulletin_title": raw_bulletin.get("context", {}).get("title") or raw_bulletin.get("value", "Sans titre"),
                "published_date": raw_bulletin.get("published_date") or raw_bulletin.get("context", {}).get("date", "Inconnue"),
                "url": raw_bulletin.get("context", {}).get("url", ""),
                "pdf_urls": raw_bulletin.get("context", {}).get("pdfs", []),
                "description": final_desc,
                "affected_systems": sections["affected_systems"],
                "risk_level": sections["risk_level"],
                "impact_level": sections["impact_level"],
                "solution": sections["solution"],
                "risks": sections["risks"],
                "references": sections["references"],
                "cves": self.extract_all_cves(raw_bulletin, clean_txt),
                "iocs": [], # Strictement vide pour Phase 1
                "raw_text_clean": clean_txt,
                "extraction_stage": "dgssi_stage_1",
                "ready_for_nlp": True
            }
            return output
        except Exception as e:
            logger.error(f"Erreur lors de la normalisation : {e}")
            return None

    def process_file(self, input_path, output_path, summary_path):
        """Fonction principale de traitement."""
        import os
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        os.makedirs(os.path.dirname(summary_path), exist_ok=True)
        
        with open(input_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        results = []
        total_cves = 0
        
        for item in data:
            normalized = self.normalize_bulletin(item)
            if normalized:
                results.append(normalized)
                total_cves += len(normalized["cves"])

        # Écriture du fichier principal
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        # Génération du summary
        summary = {
            "total_input_objects": len(data),
            "total_output_objects": len(results),
            "objects_with_bulletin_id": len([r for r in results if r["bulletin_id"] != "Unknown"]),
            "objects_with_description": len([r for r in results if len(r["description"]) > 10]),
            "total_cves_extracted": total_cves
        }

        with open(summary_path, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2)
        
        logging.info(f"Traitement terminé. {len(results)} objets produits.")

if __name__ == "__main__":
    # Pour tester, créez un fichier 'dgssi_raw.json' avec vos données
    processor = DGSSIProcessorStage1()
    
    # Chemins des fichiers
    INPUT_FILE = "output_adapters/dgssi_adapter.json"
    OUTPUT_FILE = "process_nlp/output/dgssi_stage1.json"
    SUMMARY_FILE = "process_nlp/output/summary_dgssi.json"
    
    # Note: Assurez-vous que dgssi_raw.json existe avant de lancer
    try:
        processor.process_file(INPUT_FILE, OUTPUT_FILE, SUMMARY_FILE)
        print(f"Succès ! Fichiers générés : {OUTPUT_FILE} et {SUMMARY_FILE}")
    except FileNotFoundError:
        print(f"Erreur : Le fichier {INPUT_FILE} est introuvable.")