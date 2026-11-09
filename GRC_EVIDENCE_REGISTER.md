# GRC evidence register (portfolio demonstration)

This register maps project artifacts to relevant **NIST CSF 2.0 categories**. It is a practitioner interpretation, not an official NIST crosswalk, an audit opinion, or evidence that a real organization complies with the framework. The category names come from [NIST CSF 2.0](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf).

| CSF 2.0 category | What this project demonstrates | Reviewable evidence | Material gap |
|---|---|---|---|
| ID.AM — Asset Management | A bounded, synthetic inventory is joined to a public vulnerability catalog by exact vendor/product name. | `data/synthetic_assets.csv`, `build_review_queue.py` | No discovery system, ownership verification, or installed-version evidence. |
| ID.RA — Risk Assessment | KEV membership and business criticality are available for triage; match status remains unconfirmed. | `data/review_candidates.csv`, `EVIDENCE_EXPORT.json` | No validated exposure, exploit path, control effectiveness, or organization-approved risk criteria. |
| GV.RR — Roles, Responsibilities, and Authorities | A human decision form requests reviewer attribution and rationale. | `review_app.py`, exported decision events | Reviewer names are not authenticated or bound to organizational roles. |
| GV.OV — Oversight | A hash-linked event log can be checked for local modification and exported for inspection. | `review_app.py check`, `EVIDENCE_EXPORT.json` | No independent anchor, immutable log store, approval separation, or periodic review. |
| PR.PS — Platform Security | The interface binds to localhost and escapes displayed feed text. | `review_app.py`, `SECURITY_MODEL.md` | No production-grade access control, deployment hardening, or security assessment. |

## Evidence review procedure

1. Run `python validate_feed.py` and compare its source hash with the export's `source.sha256`.
2. Run `python build_review_queue.py` and confirm that the seven candidates are still marked for version and configuration review.
3. Run `python review_app.py check` before `python export_evidence.py`.
4. For any reviewer decision, inspect the event's rationale and supporting version/configuration evidence. A product-name match alone is insufficient.
5. Preserve the export file hash outside the local machine if later using it as stronger tamper evidence.

The [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) is the public source for catalog entries. Its due-date field is not a deadline assigned to this fictional asset inventory.
