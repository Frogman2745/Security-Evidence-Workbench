"""Validate a saved CISA KEV snapshot before it enters the workbench."""

import argparse
import hashlib
import json
import re
from datetime import date
from pathlib import Path


def validate(path: Path) -> dict:
    raw = path.read_bytes()
    feed = json.loads(raw)
    rows = feed["vulnerabilities"]
    if not isinstance(rows, list):
        raise ValueError("vulnerabilities must be a list")
    if feed["count"] != len(rows):
        raise ValueError("declared count differs from row count")
    ids = set()
    for row in rows:
        cve = row["cveID"]
        if not re.fullmatch(r"CVE-\d{4}-\d{4,19}", cve):
            raise ValueError(f"invalid CVE ID: {cve}")
        if cve in ids:
            raise ValueError(f"duplicate CVE ID: {cve}")
        ids.add(cve)
        date.fromisoformat(row["dateAdded"])
        date.fromisoformat(row["dueDate"])
        for key in ("vendorProject", "product", "vulnerabilityName", "requiredAction"):
            if not isinstance(row[key], str) or not row[key].strip():
                raise ValueError(f"missing {key}: {cve}")
    return {
        "catalog_version": feed["catalogVersion"],
        "date_released": feed["dateReleased"],
        "entries": len(rows),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path, nargs="?", default=Path("data/cisa_kev.json"))
    print(json.dumps(validate(parser.parse_args().path), indent=2))
