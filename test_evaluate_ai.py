"""Evaluation metrics separate retrieval coverage from answer quality."""

import unittest

from evaluate_ai import evaluate


class EvaluationTests(unittest.TestCase):
    def test_fixed_retrieval_set_reports_coverage_only(self):
        report = evaluate()
        self.assertEqual(report["summary"]["case_count"], 9)
        self.assertEqual(report["summary"]["answerable_count"], 5)
        self.assertEqual(report["summary"]["unanswerable_count"], 4)
        self.assertNotIn("expected_citation_count", report["summary"])

    def test_irrelevant_exact_quote_is_scored_wrong(self):
        def irrelevant_provider(payload):
            item = payload["candidate_evidence"][0]
            return {"insufficient_evidence": False, "selections": [{
                "asset_id": item["asset_id"], "cve_id": item["cve_id"],
                "field": "description", "quote": item["description"][:80]}]}

        report = evaluate("live", provider=irrelevant_provider)
        self.assertEqual(report["summary"]["correct_abstention_count"], 0)
        self.assertGreater(report["summary"]["unsupported_citation_count"], 0)
        self.assertEqual(report["summary"]["valid_response_count"], 9)


if __name__ == "__main__":
    unittest.main()
