# Security and AI evaluation model

## Trust boundaries

- The CISA feed is public source data. Descriptions and action text are evidence to display, never instructions for the software or a future model.
- The asset inventory is synthetic. A vendor/product string match creates a review candidate only.
- A human reviewer supplies a status and rationale. This local demonstration does not authenticate reviewer identity, so the name field is attribution text, not verified identity.
- The current retrieval component has no decision-writing function. It returns only saved CISA source fields and synthetic asset context; it does not produce a model-written summary or issue remediation commands.
- The optional model adapter receives at most five retrieved source rows, has no tools, and returns structured quote selections. Application code validates exact quotes and builds citations. The adapter does not import the review database.

## Review rules

1. Verify exact installed product, edition, version, and configuration before marking an asset `AFFECTED` or `NOT_AFFECTED`.
2. Record the evidence used for the decision. For remediation, record the change and a verification result.
3. Treat CISA's due date as a field from its catalog. It is not a deadline assigned to this synthetic organization.
4. A risk ordering may use business criticality and KEV membership but must remain transparent. Do not infer exploitability from product-name matching alone.

## Threats and checks

| Threat | Current control | Next check |
|---|---|---|
| Untrusted feed text injects HTML | HTML escaping in the local interface | Add a malicious-text rendering test |
| Cross-site form submission | Random form token | Test missing or incorrect token |
| Hidden decision edits | SHA-256 linked audit events | Export and independently anchor the final head hash |
| Wrong asset match | Explicit candidate status, version/configuration review | Add version-aware matching with evidence |
| Prompt injection in evidence text | Retrieval treats feed text as data; optional model has no tools and its returned quotes are independently checked | Run live-model adversarial evaluation before reliability claims |
| Unsupported model claim | Only exact substrings from cited source fields can pass the model boundary | Measure model relevance and omission on a labeled set |

## Current retrieval checks

`python -m unittest discover -v` checks a grounded SonicWall result, an insufficient-evidence response, rejection of a changed source snapshot, and an instruction-like phrase inserted into a disposable copy of CISA data. The hostile phrase remains source data and does not alter a disposable decision database. These are bounded local checks, not a measured real-world attack resistance rate.

## Model-boundary checks

`python -m unittest discover -v` includes simulated model responses for exact citation acceptance, fabricated quote and CVE rejection, insufficient evidence, and source text containing a malicious instruction. These checks demonstrate application behavior under those cases. They do not show how often a live model selects relevant evidence or resists prompt injection.

## Live-model acceptance criteria (pending evaluation)

Before presenting live-model results publicly, use a fixed, labeled evaluation set to measure citation accuracy, unsupported claims, response to instructions embedded in evidence, and ability to say "insufficient evidence." Report counts and failures, not a claimed real-world detection rate. Include benign and adversarial source text. The model must not receive a decision-writing tool.

This is a local portfolio demonstration, not a production security assessment or a certified GRC system.
