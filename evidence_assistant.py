"""Read-only, source-grounded retrieval for synthetic KEV review candidates.

This is deterministic lexical ranking, not a generative model. Source text is
never interpreted as an instruction, and this module has no decision writer.
"""

import argparse
import csv
import json
import math
import re
from collections import Counter
from pathlib import Path

from validate_feed import validate

ROOT = Path(__file__).resolve().parent
FEED = ROOT / "data" / "cisa_kev.json"
CANDIDATES = ROOT / "data" / "review_candidates.csv"
ASSETS = ROOT / "data" / "synthetic_assets.csv"
PINNED_SHA256 = "47e0406b2be5a40420eff66f3d90e83eb8883dae6ff4d08e1b2a942c366f6cc2"
CISA_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
WORD = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*", re.I)


def terms(value):
    return WORD.findall(str(value).casefold())


def load_evidence(feed_path=FEED, candidates_path=CANDIDATES, assets_path=ASSETS,
                  expected_sha256=PINNED_SHA256):
    """Validate provenance and candidate membership before returning source rows."""
    provenance = validate(Path(feed_path))
    if provenance["sha256"] != expected_sha256:
        raise ValueError("Saved CISA snapshot differs from the pinned source hash.")
    feed = json.loads(Path(feed_path).read_text(encoding="utf-8"))
    by_cve = {row["cveID"]: row for row in feed["vulnerabilities"]}
    with Path(assets_path).open(newline="", encoding="utf-8") as handle:
        assets = {row["asset_id"]: row for row in csv.DictReader(handle)}
    with Path(candidates_path).open(newline="", encoding="utf-8") as handle:
        candidates = list(csv.DictReader(handle))
    evidence = []
    for candidate in candidates:
        cve = candidate["cve_id"]
        asset = assets.get(candidate["asset_id"])
        source = by_cve.get(cve)
        if asset is None or source is None or candidate["source_sha256"] != expected_sha256:
            raise ValueError(f"Candidate source or asset is missing or inconsistent: {cve}")
        if (asset["vendor"].casefold(), asset["product"].casefold()) != (
            source["vendorProject"].casefold(), source["product"].casefold()
        ):
            raise ValueError(f"Candidate product match differs from source: {cve}")
        evidence.append({
            "asset_id": asset["asset_id"],
            "asset_owner": asset["owner"],
            "business_criticality": asset["business_criticality"],
            "cve_id": cve,
            "vendor": source["vendorProject"],
            "product": source["product"],
            "vulnerability_name": source["vulnerabilityName"],
            "description": source["shortDescription"],
            "date_added": source["dateAdded"],
            "cisa_due_date": source["dueDate"],
            "source_sha256": expected_sha256,
            "source_url": CISA_URL,
        })
    return evidence


def search(query, evidence, limit=5):
    """BM25-rank only saved candidate evidence; return no unsupported answer."""
    words = terms(query)
    if not words:
        return []
    documents = [terms(" ".join(str(item[key]) for key in (
        "asset_id", "cve_id", "vendor", "product", "vulnerability_name", "description"
    ))) for item in evidence]
    if not documents:
        return []
    frequencies = [Counter(doc) for doc in documents]
    document_frequency = Counter(word for freq in frequencies for word in freq)
    average_length = sum(map(len, documents)) / len(documents)
    scored = []
    for item, freq, doc in zip(evidence, frequencies, documents):
        score = 0.0
        for word in set(words):
            count = freq[word]
            if not count:
                continue
            idf = math.log(1 + (len(documents) - document_frequency[word] + .5) /
                           (document_frequency[word] + .5))
            score += idf * count * 2.2 / (count + 1.2 * (.25 + .75 * len(doc) / average_length))
            if word in terms(item["cve_id"]) or word in terms(item["asset_id"]):
                score += 3
        if score > 0:
            scored.append((score, item))
    scored.sort(key=lambda pair: (-pair[0], pair[1]["asset_id"], pair[1]["cve_id"]))
    return [item for _, item in scored[:limit]]


def answer(query, evidence):
    """Return bounded source fields and an explicit uncertainty statement."""
    results = search(query, evidence)
    return {
        "query": query,
        "method": "deterministic BM25 evidence retrieval; no generative model",
        "answer": ("Product-name matches for human review; installed version and configuration "
                   "have not been verified." if results else
                   "Insufficient evidence in the saved candidate set."),
        "results": results,
        "limits": "Synthetic assets. CISA due dates are source fields, not this lab's deadlines. "
                  "No candidate is confirmed affected by this search.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("query", help="Search the saved candidate evidence")
    args = parser.parse_args()
    print(json.dumps(answer(args.query, load_evidence()), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
