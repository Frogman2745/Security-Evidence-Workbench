"""Focused checks for decision recording and audit tamper detection."""

from pathlib import Path
from tempfile import TemporaryDirectory

import review_app


def main():
    original = review_app.DB
    try:
        with TemporaryDirectory() as folder:
            review_app.DB = Path(folder) / "test.sqlite3"
            assert review_app.initialize() == 7
            with review_app.connect() as db:
                row = db.execute("SELECT asset_id,cve_id FROM candidates LIMIT 1").fetchone()
            review_app.decide(row["asset_id"], row["cve_id"], "INVESTIGATING", "Test reviewer", "Synthetic test: verify installed version")
            assert review_app.check_chain() == 1
            with review_app.connect() as db:
                db.execute("UPDATE candidates SET review_status='AFFECTED' WHERE asset_id=? AND cve_id=?", (row["asset_id"], row["cve_id"]))
            try:
                review_app.check_chain()
            except ValueError:
                pass
            else:
                raise AssertionError("candidate status tampering was not detected")
            with review_app.connect() as db:
                db.execute("UPDATE candidates SET review_status='INVESTIGATING' WHERE asset_id=? AND cve_id=?", (row["asset_id"], row["cve_id"]))
            with review_app.connect() as db:
                db.execute("UPDATE decisions SET rationale='tampered' WHERE id=1")
            try:
                review_app.check_chain()
            except ValueError:
                pass
            else:
                raise AssertionError("tampering was not detected")
    finally:
        review_app.DB = original
    print("Decision path and audit tamper detection passed")


if __name__ == "__main__":
    main()
