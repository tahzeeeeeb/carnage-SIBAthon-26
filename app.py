# app.py
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

from preprocessing import preprocess_text
from detection_engine import detect_patterns
from scoring_engine import calculate_manipulation_index
from classifier import classify_risk
from explanation_engine import generate_explanations
from cookies_decoder import analyze_cookie_value
from cookie_security_analyzer import analyze_cookie_security

app = Flask(__name__, static_folder='static')
CORS(app)  # Enable CORS for frontend communication

@app.route("/")
def index():
    return send_from_directory('.', 'index.html')

@app.route("/analyze", methods=["POST"])
def analyze():
    """Analyze text for dark patterns/manipulation tactics"""
    try:
        data = request.get_json(silent=True) or {}
        text = data.get("text", "")

        if not isinstance(text, str) or not text.strip():
            return jsonify({"error": "Empty or invalid input"}), 400

        # Preprocess and analyze
        cleaned_text = preprocess_text(text)
        detection_results = detect_patterns(cleaned_text)
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
        return jsonify({"error": str(e)}), 500


@app.route("/analyze-cookie", methods=["POST"])
def analyze_cookie():
    """Analyze cookie for security threats"""
    try:
        data = request.get_json(silent=True) or {}
        
        cookie_data = {
            "name": data.get("name", ""),
            "value": data.get("value", ""),
            "domain": data.get("domain", ""),
            "path": data.get("path", "/"),
            "expires": data.get("expires", ""),
            "secure": data.get("secure", False),
            "httponly": data.get("httponly", False),
            "samesite": data.get("samesite", "")
        }

        if not cookie_data["value"]:
            return jsonify({"error": "Cookie value is required"}), 400

        # Perform comprehensive security analysis
        security_analysis = analyze_cookie_security(cookie_data)
        
        # Also decode and analyze the value
        value_analysis = analyze_cookie_value(cookie_data["value"])

        return jsonify({
            "cookie_name": cookie_data["name"],
            "security_analysis": security_analysis,
            "value_analysis": value_analysis
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True, port=5000)