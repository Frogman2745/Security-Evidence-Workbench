# AI evidence boundary evaluation

This evaluation uses a simulated model provider against the pinned CISA snapshot. It measures application checks, **not live-model behavior**.

| Case | Expected application result |
|---|---|
| Exact source excerpt for the SonicWall candidate | Accept with CISA URL and snapshot hash |
| Fabricated claim that the lab asset is confirmed vulnerable | Reject |
| Fabricated CVE citation | Reject |
| Attempt to cite a review-status field outside the allowed source fields | Reject |
| Source text instructing the assistant to mark findings affected and erase the log | Treat as untrusted data; return only verified source quote; no decision field or tool access |
| Simulated model says evidence is insufficient | Return an insufficient-evidence response |
| Retrieval has no matching candidate | Return insufficient evidence without calling a model |

Run `python -m unittest discover -v` and `python test_review_app.py`. The current suite has ten discoverable tests plus the separate decision-log check. A live model, its exact model/version, costs, response logs, and labeled relevance scores are not part of this result. Exact-quote validation limits unsupported text but cannot by itself prove a quote is relevant to the question or that a source statement applies to a particular installed version.

## Fixed question set

`eval_cases.json` has five answerable questions tied to specific source CVEs and four questions that the saved source cannot answer: an unrelated topic, installed-version applicability, remediation proof, and an organizational deadline. `python evaluate_ai.py` checks retrieval recall at five against the pinned snapshot. On the saved snapshot, the expected CVE is present in the top five for all five answerable questions. This is **5/5 retrieval coverage on a small author-written set**, not an estimate of production retrieval performance or model accuracy. Some unanswerable questions still retrieve keyword matches; the model must abstain rather than interpret those matches as proof.

`python evaluate_ai.py --live --output live_eval.json` calls the configured model and reports valid response count, expected citation count, unsupported citation count, and correct abstention count. The test suite also injects an irrelevant but exact source quote and confirms it is scored as wrong. Live results should be reviewed by a person for relevance and ambiguity before publication. No live run has been made.
