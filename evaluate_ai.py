"""Score fixed evidence questions. Live mode makes explicit model API calls."""

import argparse
import json
import os
from pathlib import Path

from ai_review import review
from evidence_assistant import load_evidence, search

CASES = Path(__file__).with_name("eval_cases.json")


def evaluate(mode="retrieval", cases_path=CASES, evidence=None, provider=None):
    cases = json.loads(Path(cases_path).read_text(encoding="utf-8"))
    evidence = load_evidence() if evidence is None else evidence
    if mode not in {"retrieval", "live"}:
        raise ValueError("Mode must be retrieval or live.")
    if mode == "live" and provider is None and (not os.getenv("OPENAI_API_KEY") or not os.getenv("SECURITY_AI_MODEL")):
        raise RuntimeError("Live evaluation requires OPENAI_API_KEY and SECURITY_AI_MODEL.")
    results = []
    for case in cases:
        candidates = search(case["question"], evidence, limit=5)
        retrieved = {row["cve_id"] for row in candidates}
        row = {"id": case["id"], "answerable": case["answerable"],
               "expected_cves": case["expected_cves"],
               "retrieved_cves": sorted(retrieved),
               "retrieval_hit": bool(set(case["expected_cves"]) & retrieved)
               if case["answerable"] else None}
        if mode == "live":
            try:
                output = review(case["question"], provider=provider, evidence=evidence) if provider else review(case["question"], evidence=evidence)
                cited = {item["cve_id"] for item in output.get("citations", [])}
                row["valid_response"] = True
                row["cited_cves"] = sorted(cited)
                row["expected_citation"] = bool(cited & set(case["expected_cves"])) if case["answerable"] else not cited
                row["unsupported_citation"] = bool(cited - set(case["expected_cves"]))
                row["abstained"] = not cited
            except (ValueError, RuntimeError) as exc:
                row["valid_response"] = False
                row["error_type"] = type(exc).__name__
        results.append(row)
    positives = [row for row in results if row["answerable"]]
    negatives = [row for row in results if not row["answerable"]]
    summary = {"mode": mode, "source": "pinned CISA snapshot plus synthetic lab assets",
               "case_count": len(results), "answerable_count": len(positives),
               "unanswerable_count": len(negatives),
               "retrieval_recall_at_5": sum(row["retrieval_hit"] for row in positives) / len(positives)}
    if mode == "live":
        summary.update({
            "model": os.getenv("SECURITY_AI_MODEL", "simulated provider"),
            "valid_response_count": sum(row["valid_response"] for row in results),
            "expected_citation_count": sum(row.get("expected_citation", False) for row in positives),
            "unsupported_citation_count": sum(row.get("unsupported_citation", False) for row in results),
            "correct_abstention_count": sum(row.get("abstained", False) for row in negatives),
        })
    return {"summary": summary, "cases": results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true", help="Call the configured model for each case")
    parser.add_argument("--output", type=Path, help="Save JSON results at this path")
    args = parser.parse_args()
    report = evaluate("live" if args.live else "retrieval")
    serialized = json.dumps(report, indent=2, ensure_ascii=False)
    if args.output:
        args.output.write_text(serialized + "\n", encoding="utf-8")
    print(serialized)


if __name__ == "__main__":
    main()
