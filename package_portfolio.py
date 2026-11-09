"""Create a restorable local security-workflow portfolio ZIP."""

from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED

ROOT = Path(__file__).resolve().parent
FILES = [
    "README.md", ".gitignore", "start.ps1", "PORTFOLIO_CASE_STUDY.md", "GRC_EVIDENCE_REGISTER.md", "SECURITY_MODEL.md", "AI_EVALUATION.md", "eval_cases.json",
    "EVIDENCE_EXPORT.json", "retrieval_eval.json", "validate_feed.py", "build_review_queue.py", "review_app.py",
    "evidence_assistant.py", "ai_review.py", "evaluate_ai.py", "test_evidence_assistant.py", "test_ai_review.py", "test_evaluate_ai.py", "test_review_app.py", "export_evidence.py", "data/cisa_kev.json", "data/synthetic_assets.csv",
    "data/review_candidates.csv", "data/README.md",
]
with ZipFile(ROOT / "Security_Evidence_Workbench_Portfolio.zip", "w", ZIP_DEFLATED) as archive:
    for relative in FILES:
        archive.write(ROOT / relative, relative)
print(f"Packaged {len(FILES)} files with source paths preserved")
