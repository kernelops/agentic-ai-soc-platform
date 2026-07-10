"""
Standalone RAG ingestion script.

Loads the curated MITRE ATT&CK techniques and response runbooks from
rag/data/*.json and upserts them into Qdrant. Idempotent — re-running updates
documents in place (stable IDs), so it's safe to run after editing the data.

The payloads stored here are what the agent tools read back, so they carry the
full fields the Investigation/Remediation agents consume (descriptions,
detection guidance, steps, and recommended actions with destructive flags).

Run once after the Qdrant service is up:
    docker compose run --rm worker python -m rag.ingest
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from rag.store import MITRE_COLLECTION, RUNBOOKS_COLLECTION, RAGStore

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger("soc.rag.ingest")

DATA_DIR = Path(__file__).parent / "data"


def _mitre_text(t: dict) -> str:
    """Compose the text that gets embedded for a MITRE technique."""
    indicators = "; ".join(t.get("indicators", []))
    return (
        f"{t['technique_id']} {t['name']} (tactic: {t['tactic']}). "
        f"{t['description']} "
        f"Detection: {t.get('detection', '')} "
        f"Indicators: {indicators}"
    )


def _runbook_text(r: dict) -> str:
    """Compose the text that gets embedded for a runbook."""
    applies = ", ".join(r.get("applies_to", []))
    steps = " ".join(f"{i}) {s}" for i, s in enumerate(r.get("steps", []), start=1))
    return (
        f"{r['title']}. Applies to: {applies}. "
        f"{r.get('summary', '')} "
        f"Steps: {steps}"
    )


def _load(filename: str) -> list[dict]:
    return json.loads((DATA_DIR / filename).read_text(encoding="utf-8"))


def main() -> None:
    store = RAGStore()
    try:
        store.ensure_collections()

        # --- MITRE ATT&CK techniques ---
        techniques = _load("mitre_techniques.json")
        mitre_docs = [
            (
                t["technique_id"],
                _mitre_text(t),
                {
                    "technique_id": t["technique_id"],
                    "name": t["name"],
                    "tactic": t["tactic"],
                    "description": t["description"],
                    "detection": t.get("detection", ""),
                },
            )
            for t in techniques
        ]
        store.add_documents(MITRE_COLLECTION, mitre_docs)

        # --- Runbooks ---
        runbooks = _load("runbooks.json")
        runbook_docs = [
            (
                r["runbook_id"],
                _runbook_text(r),
                {
                    "runbook_id": r["runbook_id"],
                    "title": r["title"],
                    "applies_to": r.get("applies_to", []),
                    "steps": r.get("steps", []),
                    "recommended_actions": r.get("recommended_actions", []),
                },
            )
            for r in runbooks
        ]
        store.add_documents(RUNBOOKS_COLLECTION, runbook_docs)

        logger.info(
            "Ingestion complete: %d MITRE techniques, %d runbooks",
            len(mitre_docs),
            len(runbook_docs),
        )
    finally:
        store.close()


if __name__ == "__main__":
    main()
