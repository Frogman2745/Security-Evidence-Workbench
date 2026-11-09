# Security Evidence Workbench

**Question:** How can public known-exploited-vulnerability intelligence become a reviewable asset queue without presenting a product-name match as a confirmed finding?

**Work:** Validated a dated CISA KEV JSON snapshot, recorded its SHA-256 hash, matched exact vendor/product names against four synthetic assets, built a local human-review interface, and added a hash-linked decision log with tamper-detection checks and a JSON evidence export. Added read-only BM25 search and an optional model boundary that accepts only exact cited source quotes.

**Verified result:** The saved CISA snapshot contains 1,769 entries. Four synthetic assets generate seven product-name candidates, all initially marked `NEEDS_VERSION_AND_CONFIGURATION_REVIEW`. The test suite verifies decision recording and detects local modifications to candidate status or the decision log. The current demonstration export has zero human decisions.

**Tools:** Python, SQLite, HTTP/HTML, BM25 text retrieval, structured model-output validation, source hashing, automated checks, and an illustrative NIST CSF 2.0 evidence register.

**What a reviewer can inspect:** [README and setup](README.md), [evidence snapshot](EVIDENCE_EXPORT.json), [GRC register](GRC_EVIDENCE_REGISTER.md), [security boundaries](SECURITY_MODEL.md), and tests.

**Limits:** The inventory and any future decisions are synthetic. The interface is local-only and unauthenticated. A hash chain without an independent anchor is not an immutable audit log. No live model run or model-quality score has been verified. A KEV product-name match does not verify an affected installed version.
