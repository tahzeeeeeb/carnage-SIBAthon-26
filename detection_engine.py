# detection_engine.py

from config import (
    URGENCY_KEYWORDS,
    SCARCITY_KEYWORDS,
    CONFIRMSHAMING_KEYWORDS,
    FORCED_CONTINUITY_KEYWORDS
)

def detect_patterns(text):
    results = {
        "urgency": {"count": 0, "matches": []},
        "scarcity": {"count": 0, "matches": []},
        "confirmshaming": {"count": 0, "matches": []},
        "forced_continuity": {"count": 0, "matches": []}
    }

    # Urgency
    for phrase in URGENCY_KEYWORDS:
        if phrase in text:
            results["urgency"]["count"] += 1
            results["urgency"]["matches"].append(phrase)

    # Scarcity
    for phrase in SCARCITY_KEYWORDS:
        if phrase in text:
            results["scarcity"]["count"] += 1
            results["scarcity"]["matches"].append(phrase)

    # Confirmshaming
    for phrase in CONFIRMSHAMING_KEYWORDS:
        if phrase in text:
            results["confirmshaming"]["count"] += 1
            results["confirmshaming"]["matches"].append(phrase)

    # Forced Continuity
    for phrase in FORCED_CONTINUITY_KEYWORDS:
        if phrase in text:
            results["forced_continuity"]["count"] += 1
            results["forced_continuity"]["matches"].append(phrase)

    return results
