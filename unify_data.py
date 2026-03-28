import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from common.cve_adapter import CveAdapter
from common.ioc_adapter import IocAdapter

ROOT_DIR = Path(__file__).resolve().parent
DEFAULT_OUTPUT_DIR = ROOT_DIR / "unified_output"
DEFAULT_SUMMARY_PATH = DEFAULT_OUTPUT_DIR / "unified_summary.json"

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Unifie les données par format (CVE et IOC)."
    )
    parser.add_argument(
        "--output-dir",
        default=str(DEFAULT_OUTPUT_DIR),
        help="Dossier où écrire les résultats unifiés.",
    )
    return parser.parse_args()

def write_outputs(cves: list[dict], iocs: list[dict], summary: dict, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    cves_path = output_dir / "unified_cves.jsonl"
    iocs_path = output_dir / "unified_iocs.jsonl"
    summary_path = output_dir / DEFAULT_SUMMARY_PATH.name

    with cves_path.open("w", encoding="utf-8") as handle:
        for cve in cves:
            handle.write(json.dumps(cve, ensure_ascii=False) + "\n")

    with iocs_path.open("w", encoding="utf-8") as handle:
        for ioc in iocs:
            handle.write(json.dumps(ioc, ensure_ascii=False) + "\n")

    with summary_path.open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, ensure_ascii=False, indent=2)

def main() -> None:
    args = parse_args()
    output_dir = Path(args.output_dir).resolve()

    print("Extraction des CVEs...")
    cve_adapter = CveAdapter(ROOT_DIR)
    cves = cve_adapter.run_all()
    
    print("Extraction des IOCs...")
    ioc_adapter = IocAdapter(ROOT_DIR)
    iocs = ioc_adapter.run_all()
    
    processed_files = sorted(list(set(cve_adapter.processed_files + ioc_adapter.processed_files)))
    missing_files = sorted(list(set(cve_adapter.missing_files + ioc_adapter.missing_files)))

    # Calculate shared
    shared_cves = sum(1 for cve in cves if len(cve["sources"]) > 1)
    shared_iocs = sum(1 for ioc in iocs if len(ioc["sources"]) > 1)

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_unique_cves": len(cves),
        "total_unique_iocs": len(iocs),
        "shared_cves_count": shared_cves,
        "shared_iocs_count": shared_iocs,
        "processed_files": processed_files,
        "missing_files": missing_files,
    }

    print("Ecriture des fichiers unifiés...")
    write_outputs(cves, iocs, summary, output_dir)

    print("=" * 60)
    print("Unified CTI dataset (Type-Based Architecture)")
    print("=" * 60)
    print(f"Sources traitées : {len(processed_files)}")
    print(f"CVE uniques : {summary['total_unique_cves']}")
    print(f"IOC uniques : {summary['total_unique_iocs']}")
    print(f"CVE partagées inter-sources : {shared_cves}")
    print(f"IOC partagés inter-sources : {shared_iocs}")

    if missing_files:
        print("\nFichiers absents ignorés :")
        for path in missing_files:
            print(f"  - {path}")

if __name__ == "__main__":
    main()