"""Export a reviewable, local evidence snapshot without changing decisions."""

import csv
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import review_app
from validate_feed import validate

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "EVIDENCE_EXPORT.json"


def main():
    source = ROOT / "data/cisa_kev.json"
    feed = validate(source)
    with (ROOT / "data/synthetic_assets.csv").open(newline="", encoding="utf-8") as handle:
        assets = list(csv.DictReader(handle))
    review_app.initialize()
    event_count = review_app.check_chain()
    with review_app.connect() as db:
        candidates = [dict(row) for row in db.execute("SELECT * FROM candidates ORDER BY asset_id,cve_id")]
        decisions = [dict(row) for row in db.execute("SELECT * FROM decisions ORDER BY id")]
    if any(row["source_sha256"] != feed["sha256"] for row in candidates):
        raise ValueError("Candidate source hash does not match the saved CISA snapshot")
    if len(candidates) != 7 or len(assets) != 4:
        raise ValueError("Unexpected synthetic demonstration slice")
    export = {
        "exported_at_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "Local portfolio demonstration; synthetic asset inventory; product-name candidates only",
        "source": {"name": "CISA Known Exploited Vulnerabilities", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", **feed},
        "assertions": {"asset_count": len(assets), "candidate_count": len(candidates), "decision_count": event_count, "decision_chain_valid": True,
                       "candidate_source_hashes_match": True, "installed_versions_verified": False, "real_world_vulnerability_findings": False},
        "synthetic_assets": assets,
        "review_candidates": candidates,
        "decision_events": decisions,
        "decision_chain_head": decisions[-1]["event_hash"] if decisions else "GENESIS",
        "limitations": ["Reviewer names are unverified attribution text; no authentication is implemented.",
                        "A local hash chain cannot prevent an attacker with database access from rewriting and recomputing the entire chain; anchor the exported hash externally for stronger evidence.",
                        "CISA due dates are catalog source fields, not deadlines for the fictional organization."],
    }
    encoded = (json.dumps(export, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    OUT.write_bytes(encoded)
    print(f"Wrote {OUT.name}: {len(candidates)} candidates, {event_count} decisions, SHA-256 {hashlib.sha256(encoded).hexdigest()}")


if __name__ == "__main__":
    main()
