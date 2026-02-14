# config.py

URGENCY_KEYWORDS = [
    "hurry",
    "act now",
    "limited time",
    "last chance",
    "offer ends soon"
]

SCARCITY_KEYWORDS = [
    "only 1 left",
    "only a few left",
    "almost sold out",
    "limited stock"
]

CONFIRMSHAMING_KEYWORDS = [
    "no thanks, i don't like saving money",
    "i prefer to miss out",
    "no i hate discounts"
]

FORCED_CONTINUITY_KEYWORDS = [
    "auto-renew",
    "subscription continues",
    "charged automatically",
    "billed monthly"
]

WEIGHTS = {
    "urgency": 15,
    "scarcity": 20,
    "confirmshaming": 25,
    "forced_continuity": 30
}

LOW_THRESHOLD = 30
MEDIUM_THRESHOLD = 60