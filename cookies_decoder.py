import base64
import json
import re
from datetime import datetime

def is_base64(value):
    pattern = r'^[A-Za-z0-9+/=]+$'
    return re.fullmatch(pattern, value) is not None

def decode_base64(value):
    try:
        decoded_bytes = base64.b64decode(value)
        decoded_string = decoded_bytes.decode("utf-8")
        return decoded_string
    except Exception:
        return None

def analyze_decoded_cookie(decoded_string):
    analysis = {
        "is_json": False,
        "risk_score": 0,
        "findings": []
    }
    try:
        data = json.loads(decoded_string)
        analysis["is_json"] = True

        if "id" in data:
            analysis["risk_score"] += 20
            analysis["findings"].append("Contains unique identifier (possible tracking).")

        if "created" in data:
            try:
                timestamp = int(data["created"])
                year = datetime.fromtimestamp(timestamp / 1000).year
                if year > datetime.now().year:
                    analysis["risk_score"] += 15
                    analysis["findings"].append("Future expiry timestamp detected (long tracking duration).")
            except Exception:
                pass

        if "existing" in data:
            analysis["risk_score"] += 10
            analysis["findings"].append("User state tracking detected.")
    except json.JSONDecodeError:
        analysis["findings"].append("Decoded value is not JSON. Possibly encrypted or session token.")
    return analysis

def analyze_cookie_value(value):
    result = {
        "is_base64": False,
        "decoded_value": None,
        "analysis": None
    }
    if is_base64(value):
        result["is_base64"] = True
        decoded = decode_base64(value)
        if decoded:
            result["decoded_value"] = decoded
            result["analysis"] = analyze_decoded_cookie(decoded)
    return result