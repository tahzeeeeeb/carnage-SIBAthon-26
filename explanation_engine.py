# explanation_engine.py

EXPLANATIONS = {
    "urgency": "Urgency tactics pressure users into quick decisions.",
    "scarcity": "Scarcity creates fear of missing out.",
    "confirmshaming": "Confirmshaming induces guilt to manipulate choices.",
    "forced_continuity": "Forced continuity may charge users without clear consent."
}

def generate_explanations(detection_results):
    explanations = []

    for category, data in detection_results.items():
        if data["count"] > 0:
            explanations.append({
                "type": category,
                "explanation": EXPLANATIONS.get(category, "")
            })

    return explanations
