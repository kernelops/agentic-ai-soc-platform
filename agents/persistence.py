"""
Incremental case-document persistence for agent nodes.

Every node writes its slice onto the single `cases` document as soon as it
finishes, so a crash mid-pipeline leaves correct partial progress and an
accurate status (and later powers live Grafana updates). Pydantic outputs are
serialized with `model_dump(mode="json")` so enums/datetimes store cleanly.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel

from common.database import get_mongo_db
from common.models import CaseStatus


async def update_case(case_id: str, status: CaseStatus | None = None, **fields: Any) -> None:
    """`$set` the given fields (and optional status) on a case document."""
    to_set: dict[str, Any] = {}
    for key, value in fields.items():
        to_set[key] = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    if status is not None:
        to_set["status"] = status.value
    to_set["updated_at"] = datetime.now(timezone.utc).isoformat()

    await get_mongo_db().cases.update_one({"case_id": case_id}, {"$set": to_set})
