from preprocessing import preprocess_text
from detection_engine import detect_patterns
from scoring_engine import calculate_manipulation_index
from classifier import classify_risk
from explanation_engine import generate_explanations

text = "Hurry! Only 1 left! Subscription continues automatically."

cleaned = preprocess_text(text)
detections = detect_patterns(cleaned)
score = calculate_manipulation_index(detections)
risk = classify_risk(score)
explanations = generate_explanations(detections)

print("Detections:", detections)
print("Score:", score)
print("Risk:", risk)
print("Explanations:", explanations)
