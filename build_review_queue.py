"""Create product-match review candidates, never confirmed vulnerability findings."""

import csv
import json
from pathlib import Path

from validate_feed import validate

ROOT = Path(__file__).resolve().parent


def main() -> None:
    source = ROOT / "data" / "cisa_kev.json"
    provenance = validate(source)
    rows = json.loads(source.read_text(encoding="utf-8"))["vulnerabilities"]
    with (ROOT / "data" / "synthetic_assets.csv").open(newline="", encoding="utf-8") as f:
        assets = list(csv.DictReader(f))

    candidates = []
    for asset in assets:
        for kev in rows:
            if (asset["vendor"].casefold(), asset["product"].casefold()) != (
                kev["vendorProject"].casefold(), kev["product"].casefold()
            ):
                continue
            candidates.append({
                "asset_id": asset["asset_id"],
                "cve_id": kev["cveID"],
                "business_criticality": asset["business_criticality"],
                "date_added": kev["dateAdded"],
                "cisa_due_date": kev["dueDate"],
                "cisa_required_action": kev["requiredAction"],
                "review_status": "NEEDS_VERSION_AND_CONFIGURATION_REVIEW",
                "evidence_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "source_sha256": provenance["sha256"],
            })
    candidates.sort(key=lambda x: (x["asset_id"], x["date_added"], x["cve_id"]), reverse=True)
    output = ROOT / "data" / "review_candidates.csv"
    with output.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(candidates[0]) if candidates else ["asset_id"])
        writer.writeheader()
        writer.writerows(candidates)
    print(f"{len(assets)} synthetic assets; {len(candidates)} product-match candidates; {output}")


if __name__ == "__main__":
    main()
