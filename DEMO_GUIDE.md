# Security Evidence Workbench: five-minute demo

## Start

From PowerShell, run:

```powershell
powershell -ExecutionPolicy Bypass -File "C:\Users\MrFrog\Security-Evidence-Workbench\start.ps1"
```

If the old page is already running, press Ctrl+C in its PowerShell window first. Open `http://127.0.0.1:8765/`. The current page has a dark header titled **Evidence workbench**, four queue metrics, **Search source evidence**, and an expandable **Review queue**.

## Walkthrough

1. **Provenance (30 seconds).** Point out the synthetic-data banner and pinned CISA KEV snapshot. The source file contains 1,769 KEV entries. The four fictional assets generate seven exact product-name review candidates. A candidate is not a verified affected asset.
2. **Evidence search (60 seconds).** Search `SonicWall authentication`. The page returns a ranked result with a CVE, source description, CISA link, and snapshot hash. This is deterministic read-only retrieval, not a generated answer or finding approval. An unrelated or unsupported question should not be treated as proof of applicability.
3. **Review queue (60 seconds).** Expand a candidate. Show the source description, catalog due-date field, and next verification step. Filter by status if useful. Criticality comes from the fictional asset inventory. It is an ordering aid, not an exploitability score.
4. **Human decision (60 seconds).** The form requires a new status, reviewer name, and evidence rationale. For a safe live demonstration, choose **Investigating** and explain that installed version and configuration remain unverified. Do not mark **Affected**, **Not affected**, or **Remediated** without supporting evidence. A submitted decision appears in Recent decisions and writes a local SQLite audit event. The reviewer name is self-entered; the app does not authenticate identity.
5. **Integrity check (30 seconds).** Run `python review_app.py check` in the project folder. The linked SHA-256 event chain catches changes to saved decision records and candidate statuses in the tested cases. It is not independently anchored or immutable.
6. **Evidence export (30 seconds).** Run `python export_evidence.py` only when you intend to update the local export. The JSON records source provenance, candidates, decisions, and limits. The committed `EVIDENCE_EXPORT.json` shows the untouched demonstration state with zero decisions.

## Behind the screen

```text
Pinned CISA KEV JSON -> schema/hash validation -> exact product-name matching
                    -> 7 synthetic review candidates -> local analyst UI
                    -> optional human decision -> SQLite hash-linked log
                    -> JSON evidence export
```

The optional model component is separate. It can select exact quotes from at most five retrieved excerpts; application code verifies those quotes and constructs citations. No live-model quality result is claimed. The `GRC_EVIDENCE_REGISTER.md` illustrates a NIST CSF 2.0 mapping and explicitly lists missing evidence.

## Interview summary

“I built a local vulnerability-evidence workbench around a pinned CISA KEV snapshot. It validates source integrity, matches public entries to a synthetic asset inventory, and creates a human-review queue. I added read-only evidence retrieval, an optional quote-only AI boundary, a hash-linked decision log, and a JSON evidence export. The key design choice is that a product-name match stays a candidate until a reviewer verifies version and configuration. This is a portfolio lab, not a deployed security service or an accuracy claim.”

## Checks and limits

- `python -m unittest discover -v`: eleven discoverable tests, including source escaping and bounded model-output checks.
- `python test_review_app.py`: decision recording and tamper-detection check in a disposable database.
- `python validate_feed.py`: verifies the saved source schema and hash.
- The local web server binds to `127.0.0.1`; it has no authentication. Keep it local.
- The asset inventory is synthetic; CISA catalog dates are source fields, not company deadlines.
