# app.py
from flask import Flask, request, jsonify

# These imports will work once Person 1 pushes core logic.
# Keep them as-is; do not rename.
from detection_engine import detect_patterns
from scoring_engine import calculate_manipulation_index
from classifier import classify_risk
from explanation_engine import generate_explanations

app = Flask(__name__)

@app.route("/analyze", methods=["POST"])
def analyze():
    try:
        data = request.get_json(silent=True) or {}
        text = data.get("text", "")

        if not isinstance(text, str) or not text.strip():
            return jsonify({"error": "Empty or invalid input"}), 400

        detection_results = detect_patterns(text)
        score = calculate_manipulation_index(detection_results)
        risk_level = classify_risk(score)
        explanations = generate_explanations(detection_results)

        return jsonify({
            "manipulation_index": score,
            "risk_level": risk_level,
            "detected_patterns": detection_results,
            "explanations": explanations
        }), 200

    except Exception as e:
        # Simple catch-all; refine later if needed.
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)