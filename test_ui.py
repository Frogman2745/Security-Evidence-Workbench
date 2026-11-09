"""Source text and query strings must remain inert when rendered."""

import unittest

from evidence_assistant import load_evidence
from ui import render_page


class RenderTests(unittest.TestCase):
    def test_queue_evidence_and_hostile_text(self):
        evidence = load_evidence()
        source = [dict(row) for row in evidence]
        source[0]["description"] = "<script>steal()</script>"
        candidates = [{"asset_id": row["asset_id"], "cve_id": row["cve_id"],
                       "review_status": "NEEDS_VERSION_AND_CONFIGURATION_REVIEW",
                       "business_criticality": row["business_criticality"],
                       "date_added": row["date_added"],
                       "cisa_due_date": row["cisa_due_date"],
                       "evidence_url": row["source_url"],
                       "source_sha256": row["source_sha256"]} for row in source]
        page = render_page(candidates, [], source, None, '" onfocus="steal()', "test").decode()
        self.assertEqual(page.count("<details class='candidate'"), 7)
        self.assertIn("&lt;script&gt;steal()&lt;/script&gt;", page)
        self.assertIn("&quot; onfocus=&quot;steal()", page)
        self.assertNotIn("<script>steal()", page)


if __name__ == "__main__":
    unittest.main()
