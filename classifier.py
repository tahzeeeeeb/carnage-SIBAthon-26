# classifier.py

from config import LOW_THRESHOLD, MEDIUM_THRESHOLD

def classify_risk(score):
    if score <= LOW_THRESHOLD:
        return "Low"
    elif score <= MEDIUM_THRESHOLD:
        return "Medium"
    else:
        return "High"