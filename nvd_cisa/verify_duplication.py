import json
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
FILE_PATH = os.path.join(SCRIPT_DIR, "cve_data.json")

def check_duplicates_in_json():
    print(f"Vérification des doublons dans {FILE_PATH}...\n")
    
    if not os.path.exists(FILE_PATH):
        print(f"Erreur : Le fichier {FILE_PATH} est introuvable.")
        return

    duplicates_found = 0
    
    # Fonction pour détecter les clés en double pendant la lecture du JSON
    def dict_check_duplicates(ordered_pairs):
        nonlocal duplicates_found
        d = {}
        for k, v in ordered_pairs:
            if k in d:
                duplicates_found += 1
                if duplicates_found <= 10:
                    print(f"[!] Clé en double détectée dans le JSON : {k}")
                elif duplicates_found == 11:
                    print(f"[!] D'autres clés en double existent (affichage masqué)...")
            d[k] = v
        return d

    print("Chargement et analyse du fichier JSON (cela peut prendre un instant, le fichier est volumineux)...")
    try:
        with open(FILE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f, object_pairs_hook=dict_check_duplicates)
            
        print("\n" + "="*40)
        print("RESULTATS DE L'ANALYSE")
        print("="*40)
        
        if duplicates_found == 0:
            print("✅ Le JSON est propre. Aucune clé en double (identifiant) n'a été détectée.")
        else:
            print(f"❌ {duplicates_found} clés en double détectées dans le fichier !")
            
        cves = data.get("cves", {})
        metadata = data.get("metadata", {})
        
        expected_total = metadata.get("total_cves", "Inconnu")
        actual_total = len(cves)
        
        print("\n--- Comptage ---")
        print(f"🔹 Total CVE indiqué dans les métadonnées : {expected_total}")
        print(f"🔹 Nombre réel de CVE (clés uniques)     : {actual_total}")
        
        if expected_total == actual_total:
            print("\n✅ Cohérence parfaite entre les données au sein du fichier.")
        else:
            print("\n⚠️ Il y a une différence entre le total des métadonnées et le nombre réel de CVE uniques.")

    except json.JSONDecodeError as e:
        print(f"\n❌ Erreur de lecture : le fichier n'est pas un JSON valide. Détail : {e}")
    except Exception as e:
        print(f"\n❌ Une erreur inattendue est survenue : {e}")

if __name__ == "__main__":
    check_duplicates_in_json()
