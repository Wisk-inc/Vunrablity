"""Severity vocabulary shared by the rule engine, the model, and the UI."""
from __future__ import annotations

ORDER = ["critical", "high", "medium", "low", "info"]

# The model is encouraged to speak plainly; map its words onto our scale.
ALIASES = {
    "critical": "critical", "crit": "critical", "severe": "critical",
    "catastrophic": "critical", "urgent": "critical", "blocker": "critical",
    "high": "high", "dangerous": "high", "major": "high", "serious": "high",
    "important": "high",
    "medium": "medium", "moderate": "medium", "med": "medium", "warning": "medium",
    "low": "low", "small": "low", "minor": "low", "nit": "low",
    "info": "info", "informational": "info", "note": "info", "none": "info",
}

LABEL = {
    "critical": "Critical",
    "high": "Dangerous",
    "medium": "Moderate",
    "low": "Small",
    "info": "Informational",
}

DESCRIPTION = {
    "critical": "Exploitable now, with direct loss of data, funds, or control.",
    "high": "Serious weakness — exploitable with modest effort or preconditions.",
    "medium": "Real weakness that needs another bug or user interaction to matter.",
    "low": "Hardening gap or minor leak; fix when convenient.",
    "info": "Observation worth knowing, not a vulnerability by itself.",
}


def normalize(value: str | None) -> str:
    if not value:
        return "info"
    return ALIASES.get(str(value).strip().lower(), "info")


def rank(value: str) -> int:
    v = normalize(value)
    return ORDER.index(v) if v in ORDER else len(ORDER)


def worst(values) -> str:
    best = "info"
    for v in values:
        if rank(v) < rank(best):
            best = normalize(v)
    return best
