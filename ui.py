"""Escaped, local-only analyst workspace for the synthetic review queue."""

import html


STYLE = """
:root{font-family:Inter,Segoe UI,system-ui,sans-serif;color:#eaf2ff;background:#0a1120;font-synthesis:none}
*{box-sizing:border-box}[hidden]{display:none!important}body{margin:0}a{color:#79c8ff}a:hover{color:#b9e5ff}
.shell{max-width:1500px;margin:auto;padding:30px 28px 70px}.top{display:flex;justify-content:space-between;gap:20px;align-items:start}
.eyebrow{text-transform:uppercase;letter-spacing:.15em;color:#67c9b8;font-size:12px;font-weight:750}.top h1{font-size:clamp(28px,3vw,42px);margin:7px 0 8px;letter-spacing:-.04em}
.muted{color:#aabbd3}.top p{margin:0;max-width:780px;line-height:1.5}.source{font-size:13px;text-align:right;min-width:230px;line-height:1.8}
.banner{background:#17243a;border:1px solid #a77f37;border-left:4px solid #e4ae55;border-radius:10px;padding:14px 18px;margin:25px 0;line-height:1.5}
.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin-bottom:28px}.stat,.panel{background:#111d30;border:1px solid #263b58;border-radius:14px;box-shadow:0 12px 25px #0002}
.stat{padding:18px}.stat strong{display:block;font-size:30px;line-height:1.15;margin-top:8px}.stat span{font-size:13px;color:#aabbd3}.stat small{display:block;color:#aabbd3;margin-top:4px}
.grid{display:grid;grid-template-columns:minmax(0,1fr) 335px;gap:20px}.panel{padding:20px}.panel h2{font-size:20px;margin:0 0 5px;letter-spacing:-.02em}.panel>p{margin:0 0 18px;line-height:1.5}
.search{display:flex;gap:9px}.search input,.filter,select,input,textarea{background:#091426;color:#eaf2ff;border:1px solid #3c5270;border-radius:8px;padding:10px 11px;font:inherit;min-width:0}
.search input{flex:1}.search button,.decision button{background:#29aa98;color:#06131c;border:0;border-radius:8px;padding:10px 15px;font:inherit;font-weight:750;cursor:pointer}.search button:hover,.decision button:hover{background:#5ad2c0}
.results{margin-top:18px}.result{border-top:1px solid #2d405c;padding:13px 0;line-height:1.5}.result p{margin:4px 0}.result small,.foot{color:#aabbd3}.result b{color:#f4f8ff}
.toolbar{display:flex;gap:10px;align-items:center;justify-content:space-between;margin:26px 0 12px}.toolbar h2{margin:0}.toolbar select{max-width:260px}
.queue{display:grid;gap:12px}.candidate{border:1px solid #304760;border-radius:12px;background:#132239;overflow:hidden}.candidate summary{cursor:pointer;list-style:none;padding:15px 17px;display:grid;grid-template-columns:minmax(0,1fr) auto;gap:14px;align-items:center}.candidate summary::-webkit-details-marker{display:none}.candidate summary:hover{background:#1a2d49}.candidate[open] summary{border-bottom:1px solid #304760}
.candidate h3{font-size:17px;margin:5px 0 4px}.candidate .id{font:12px Consolas,monospace;color:#9ec8ee}.candidate .meta{font-size:13px;color:#aabbd3}.badges{display:flex;gap:7px;align-items:center;flex-wrap:wrap;justify-content:end}.badge{font-size:11px;font-weight:750;border:1px solid #52708d;border-radius:99px;padding:4px 9px;color:#cfe4f7}.badge.high{border-color:#d78e69;color:#ffc39e}.badge.medium{border-color:#d9ba70;color:#f3da9c}.badge.status{border-color:#5aa99f;color:#9ce6d9}
.candidate-body{padding:16px 17px 19px;display:grid;grid-template-columns:minmax(0,1fr) minmax(250px,.75fr);gap:24px;line-height:1.5}.candidate-body h4{margin:0 0 7px;color:#c6d7ee}.candidate-body p{margin:6px 0 12px}.candidate-body small{color:#aabbd3}.mono{font:12px Consolas,monospace;word-break:break-all;color:#aabbd3}
.decision{display:grid;gap:9px}.decision label{font-size:13px;color:#c6d7ee}.decision textarea{resize:vertical;min-height:75px}.decision button{justify-self:start}.audit{margin-top:20px}.event{border-top:1px solid #304760;padding:12px 0;font-size:13px;line-height:1.5}.event strong{display:block}.event p{margin:3px 0}.empty{padding:16px;border:1px dashed #52708d;border-radius:10px;color:#aabbd3}
footer{margin-top:25px;color:#aabbd3;font-size:13px;line-height:1.5}
@media(max-width:1000px){.grid{grid-template-columns:1fr}.stats{grid-template-columns:repeat(2,1fr)}.source{text-align:left}.top{display:block}}
@media(max-width:650px){.shell{padding:18px 12px 40px}.stats{grid-template-columns:repeat(2,1fr)}.candidate summary,.candidate-body{display:block}.badges{justify-content:start;margin-top:9px}.search{display:grid}.toolbar{display:block}.toolbar select{margin-top:10px;max-width:none;width:100%}}
"""


def render_page(candidates, decisions, evidence, search_result, query, token):
    e = lambda value: html.escape(str(value), quote=True)
    by_key = {(row["asset_id"], row["cve_id"]): row for row in evidence}
    pending = sum(row["review_status"] == "NEEDS_VERSION_AND_CONFIGURATION_REVIEW" for row in candidates)
    high = sum(row["business_criticality"].lower() == "high" for row in candidates)
    reviewed = len(candidates) - pending
    parts = [f"<!doctype html><html lang='en'><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Security Evidence Workbench</title><style>{STYLE}</style><main class='shell'>",
             "<header class='top'><div><div class='eyebrow'>Security operations / portfolio lab</div><h1>Evidence workbench</h1><p class='muted'>Turn known exploited vulnerability intelligence into a traceable, human-reviewed queue.</p></div><div class='source'>Pinned source: <a href='https://www.cisa.gov/known-exploited-vulnerabilities-catalog'>CISA KEV</a><br>Snapshot: 2026-11-08<br><span class='muted'>Local demonstration</span></div></header>",
             "<div class='banner'><strong>Synthetic demonstration.</strong> Product-name matches are review candidates, not confirmed vulnerable systems. Verify installed versions, configuration, and remediation evidence. CISA due dates are source fields, not deadlines for this fictional organization.</div>",
             f"<section class='stats' aria-label='Queue overview'><div class='stat'><span>Review candidates</span><strong>{len(candidates)}</strong><small>Product-name matches</small></div><div class='stat'><span>High criticality</span><strong>{high}</strong><small>Synthetic asset context</small></div><div class='stat'><span>Needs verification</span><strong>{pending}</strong><small>Version and configuration</small></div><div class='stat'><span>Reviewed status</span><strong>{reviewed}</strong><small>Human status changes</small></div></section>",
             "<div class='grid'><div><section class='panel'><h2>Search source evidence</h2><p class='muted'>Read-only retrieval from the pinned CISA snapshot. Text in source fields is untrusted data.</p>",
             f"<form class='search' method='get' action='/'><input aria-label='Search evidence' name='q' maxlength='200' placeholder='Search a CVE, product, or weakness' value='{e(query)}'><button>Search evidence</button></form>"]
    if search_result:
        parts.append(f"<div class='results'><strong>{e(search_result['answer'])}</strong>")
        if not search_result["results"]:
            parts.append("<p class='empty'>No supported match in the saved candidate set.</p>")
        for item in search_result["results"]:
            parts.append(f"<div class='result'><b>{e(item['asset_id'])} · {e(item['cve_id'])}</b><p>{e(item['vulnerability_name'])}</p><small>{e(item['description'])}</small><p><a href='{e(item['source_url'])}'>CISA catalog</a> · Snapshot SHA-256 <span class='mono'>{e(item['source_sha256'][:16])}…</span></p></div>")
        parts.append(f"<small>{e(search_result['limits'])}</small></div>")
    parts.append("</section><div class='toolbar'><h2>Review queue</h2><select id='status-filter' class='filter' aria-label='Filter candidates by status'><option value=''>All statuses</option><option value='NEEDS_VERSION_AND_CONFIGURATION_REVIEW'>Needs verification</option><option value='INVESTIGATING'>Investigating</option><option value='AFFECTED'>Affected</option><option value='NOT_AFFECTED'>Not affected</option><option value='REMEDIATED'>Remediated</option></select></div><div class='queue' id='queue'>")
    for row in candidates:
        item = by_key.get((row["asset_id"], row["cve_id"]))
        if item is None:
            raise ValueError("Candidate has no validated source evidence.")
        status = row["review_status"]
        label = "Needs verification" if status == "NEEDS_VERSION_AND_CONFIGURATION_REVIEW" else status.replace("_", " ").title()
        parts.extend((f"<details class='candidate' data-status='{e(status)}'><summary><div><span class='id'>{e(row['asset_id'])} / {e(row['cve_id'])}</span><h3>{e(item['vulnerability_name'])}</h3><span class='meta'>{e(item['vendor'])} · {e(item['product'])} · CISA added {e(row['date_added'])}</span></div><div class='badges'><span class='badge {e(row['business_criticality'].lower())}'>{e(row['business_criticality'])} criticality</span><span class='badge status'>{e(label)}</span></div></summary>",
                     f"<div class='candidate-body'><div><h4>Source evidence</h4><p>{e(item['description'])}</p><p><small>CISA due-date field: {e(row['cisa_due_date'])}. This is not a lab deadline.</small></p><p><a href='{e(row['evidence_url'])}'>View CISA catalog</a></p><p class='mono'>Snapshot SHA-256: {e(row['source_sha256'])}</p><small>Next check: verify installed version and configuration against vendor guidance. Preserve evidence in the reviewer rationale.</small></div>",
                     f"<form class='decision' method='post' action='/decide'><h4>Record a human review</h4><input type='hidden' name='token' value='{e(token)}'><input type='hidden' name='asset_id' value='{e(row['asset_id'])}'><input type='hidden' name='cve_id' value='{e(row['cve_id'])}'><label for='status-{e(row['asset_id'])}-{e(row['cve_id'])}'>New status</label><select id='status-{e(row['asset_id'])}-{e(row['cve_id'])}' name='status'>" + "".join(f"<option value='{e(value)}'>{e(value.replace('_',' ').title())}</option>" for value in ("INVESTIGATING", "NOT_AFFECTED", "AFFECTED", "REMEDIATED", "NEEDS_VERSION_AND_CONFIGURATION_REVIEW") if value != status) + f"</select><label for='reviewer-{e(row['asset_id'])}-{e(row['cve_id'])}'>Reviewer</label><input id='reviewer-{e(row['asset_id'])}-{e(row['cve_id'])}' name='reviewer' maxlength='80' required placeholder='Your name'><label for='rationale-{e(row['asset_id'])}-{e(row['cve_id'])}'>Evidence and rationale</label><textarea id='rationale-{e(row['asset_id'])}-{e(row['cve_id'])}' name='rationale' maxlength='2000' required placeholder='What did you verify? Include version, configuration, and source.'></textarea><button>Record decision</button></form></div></details>"))
    parts.append("</div></div><aside><section class='panel'><h2>Review guidance</h2><p class='muted'>Use the queue to separate evidence from assumptions.</p><ol><li>Confirm the installed product and version.</li><li>Check vendor guidance and exposure.</li><li>Record a status with supporting evidence.</li><li>Run the decision-log integrity check.</li></ol><p class='muted'>The source is pinned; refresh before using it for current prioritization.</p></section><section class='panel audit'><h2>Recent decisions</h2>")
    if not decisions:
        parts.append("<p class='empty'>No local review decisions yet. Open a candidate to record one.</p>")
    for row in decisions:
        parts.append(f"<div class='event'><strong>{e(row['asset_id'])} / {e(row['cve_id'])}</strong><span>{e(row['old_status'].replace('_',' ').title())} → {e(row['new_status'].replace('_',' ').title())}</span><p>{e(row['rationale'])}</p><small>{e(row['reviewer'])} · {e(row['at_utc'])}</small></div>")
    parts.append("</section></aside></div><footer>The local SHA-256 audit chain detects changes to decision records. It is not independent storage, access control, or proof of compliance.</footer></main><script>const f=document.getElementById('status-filter');f.addEventListener('change',()=>document.querySelectorAll('.candidate').forEach(x=>x.hidden=!!f.value&&x.dataset.status!==f.value));</script></html>")
    return "".join(parts).encode("utf-8")
