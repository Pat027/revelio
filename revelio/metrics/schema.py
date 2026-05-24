"""Shared pydantic schemas for red-teaming metrics.

Every per-metric ``schema.py`` historically redefined an identical subset of
these three models; they are consolidated here so the metric base class has a
single source of truth. The per-metric ``schema.py`` files are kept for any
direct importers but are no longer used by the metric classes themselves.
"""

from typing import List

from pydantic import BaseModel


class Purpose(BaseModel):
    purpose: str


class Entities(BaseModel):
    entities: List[str]


class ReasonScore(BaseModel):
    reason: str
    score: float
