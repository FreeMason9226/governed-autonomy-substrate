"""Deterministic GIR inference contract used by regression fixtures."""

from __future__ import annotations

import re

_OBLIGATION_TERMS = {
    "access-control": ("authorized", "permitted", "access", "principal"),
    "auditability": ("traceable", "evidence", "audit", "record"),
    "human-oversight": ("human", "override", "review"),
    "retention": ("retain", "retention", "kept", "store"),
}


def extract_obligations(text: str) -> list[str]:
    """Return stable obligation labels for the published preprocessing contract."""
    normalized = re.sub(r"\s+", " ", text.casefold()).strip()
    return [
        label
        for label, terms in _OBLIGATION_TERMS.items()
        if any(term in normalized for term in terms)
    ]