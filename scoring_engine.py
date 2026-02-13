# scoring_engine.py

from config import WEIGHTS

def calculate_manipulation_index(detection_results):
    total_score = 0

    for category, data in detection_results.items():
        weight = WEIGHTS.get(category, 0)
        total_score += data["count"] * weight

    return min(total_score, 100)
