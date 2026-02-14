# cookie_security_analyzer.py
"""
Comprehensive Cookie Security Analyzer
Performs real threat detection based on security best practices
"""

import re
import math
import base64
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any

# Known tracking cookie patterns (real-world trackers)
KNOWN_TRACKERS = {
    "_ga": {"name": "Google Analytics", "type": "analytics", "risk": "medium"},
    "_gid": {"name": "Google Analytics", "type": "analytics", "risk": "medium"},
    "_fbp": {"name": "Facebook Pixel", "type": "advertising", "risk": "high"},
    "_fbc": {"name": "Facebook Click", "type": "advertising", "risk": "high"},
    "fr": {"name": "Facebook Ads", "type": "advertising", "risk": "high"},
    "_gcl_au": {"name": "Google Ads", "type": "advertising", "risk": "high"},
    "IDE": {"name": "Google DoubleClick", "type": "advertising", "risk": "high"},
    "DSID": {"name": "Google DoubleClick", "type": "advertising", "risk": "high"},
    "_uetsid": {"name": "Microsoft Ads", "type": "advertising", "risk": "high"},
    "_uetvid": {"name": "Microsoft Ads", "type": "advertising", "risk": "high"},
    "MUID": {"name": "Microsoft Tracking", "type": "tracking", "risk": "high"},
    "_pin_unauth": {"name": "Pinterest", "type": "advertising", "risk": "medium"},
    "li_sugr": {"name": "LinkedIn", "type": "advertising", "risk": "high"},
    "bcookie": {"name": "LinkedIn Browser ID", "type": "tracking", "risk": "medium"},
    "_tt_enable_cookie": {"name": "TikTok", "type": "advertising", "risk": "high"},
    "sp_t": {"name": "Spotify", "type": "tracking", "risk": "medium"},
    "__stripe_mid": {"name": "Stripe", "type": "functional", "risk": "low"},
    "intercom-id": {"name": "Intercom", "type": "analytics", "risk": "medium"},
    "hubspotutk": {"name": "HubSpot", "type": "marketing", "risk": "medium"},
    "_clck": {"name": "Microsoft Clarity", "type": "analytics", "risk": "medium"},
    "_clsk": {"name": "Microsoft Clarity", "type": "analytics", "risk": "medium"},
}

# Suspicious patterns in cookie values
SUSPICIOUS_PATTERNS = [
    (r"password", "Potential password storage", "critical"),
    (r"passwd", "Potential password storage", "critical"),
    (r"pwd", "Potential password storage", "high"),
    (r"secret", "Secret data exposure", "critical"),
    (r"api[_-]?key", "API key exposure", "critical"),
    (r"token", "Token storage detected", "medium"),
    (r"auth", "Authentication data", "medium"),
    (r"session", "Session identifier", "low"),
    (r"credit", "Potential financial data", "critical"),
    (r"card", "Potential card data", "high"),
    (r"ssn", "Potential SSN", "critical"),
    (r"email", "Email data stored", "medium"),
    (r"phone", "Phone number stored", "medium"),
    (r"address", "Address data stored", "medium"),
    (r"user[_-]?id", "User identifier", "low"),
    (r"uuid", "Unique identifier", "low"),
]


def calculate_entropy(value: str) -> float:
    """Calculate Shannon entropy of a string"""
    if not value:
        return 0.0
    
    freq = {}
    for char in value:
        freq[char] = freq.get(char, 0) + 1
    
    entropy = 0.0
    length = len(value)
    for count in freq.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    
    return round(entropy, 2)


def detect_encoding(value: str) -> Dict[str, Any]:
    """Detect if value is encoded and try to decode it"""
    result = {
        "encoding_detected": None,
        "decoded_value": None,
        "decoded_analysis": []
    }
    
    # Check Base64
    base64_pattern = r'^[A-Za-z0-9+/=]{20,}$'
    if re.match(base64_pattern, value) and len(value) % 4 == 0:
        try:
            decoded = base64.b64decode(value).decode('utf-8')
            result["encoding_detected"] = "base64"
            result["decoded_value"] = decoded
            
            # Try to parse as JSON
            try:
                json_data = json.loads(decoded)
                result["decoded_analysis"].append({
                    "finding": "Contains JSON data",
                    "risk": "medium",
                    "details": f"Keys found: {list(json_data.keys())[:5]}"
                })
            except json.JSONDecodeError:
                pass
                
        except Exception:
            pass
    
    # Check URL encoding
    if '%' in value:
        try:
            from urllib.parse import unquote
            decoded = unquote(value)
            if decoded != value:
                result["encoding_detected"] = "url"
                result["decoded_value"] = decoded
        except Exception:
            pass
    
    # Check Hex encoding
    hex_pattern = r'^[0-9a-fA-F]{32,}$'
    if re.match(hex_pattern, value):
        result["encoding_detected"] = "hex"
        result["decoded_analysis"].append({
            "finding": "Hex-encoded value detected",
            "risk": "low",
            "details": "May contain binary data or hash"
        })
    
    return result


def analyze_expiration(expires: str) -> Dict[str, Any]:
    """Analyze cookie expiration for security issues"""
    result = {
        "type": "unknown",
        "risk": "low",
        "findings": []
    }
    
    if not expires or expires.lower() == "session":
        result["type"] = "session"
        result["findings"].append({
            "finding": "Session cookie (expires when browser closes)",
            "risk": "low",
            "recommendation": "Appropriate for temporary data"
        })
        return result
    
    try:
        # Parse various date formats
        formats = [
            "%a, %d %b %Y %H:%M:%S GMT",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%a, %d-%b-%Y %H:%M:%S GMT"
        ]
        
        expiry_date = None
        for fmt in formats:
            try:
                expiry_date = datetime.strptime(expires, fmt)
                break
            except ValueError:
                continue
        
        # Also try Unix timestamp
        if expiry_date is None:
            try:
                timestamp = int(expires)
                if timestamp > 1000000000000:  # Milliseconds
                    timestamp = timestamp / 1000
                expiry_date = datetime.fromtimestamp(timestamp)
            except (ValueError, OSError):
                pass
        
        if expiry_date:
            now = datetime.now()
            duration = expiry_date - now
            
            if duration.days > 365:
                result["type"] = "persistent"
                result["risk"] = "high"
                result["findings"].append({
                    "finding": f"Long expiration: {duration.days} days",
                    "risk": "high",
                    "recommendation": "Cookies persisting over 1 year are potential tracking vectors"
                })
            elif duration.days > 90:
                result["type"] = "persistent"
                result["risk"] = "medium"
                result["findings"].append({
                    "finding": f"Extended expiration: {duration.days} days",
                    "risk": "medium",
                    "recommendation": "Consider reducing cookie lifetime"
                })
            elif duration.days < 0:
                result["type"] = "expired"
                result["risk"] = "low"
                result["findings"].append({
                    "finding": "Cookie has already expired",
                    "risk": "low",
                    "recommendation": "This cookie should be automatically removed"
                })
            else:
                result["type"] = "normal"
                result["findings"].append({
                    "finding": f"Normal expiration: {duration.days} days",
                    "risk": "low",
                    "recommendation": "Expiration period is within acceptable range"
                })
                
    except Exception as e:
        result["findings"].append({
            "finding": f"Could not parse expiration date",
            "risk": "low",
            "recommendation": "Verify date format"
        })
    
    return result


def analyze_domain_scope(domain: str) -> Dict[str, Any]:
    """Check if domain scope is overly permissive"""
    result = {
        "findings": [],
        "risk": "low"
    }
    
    if not domain:
        result["findings"].append({
            "finding": "No domain specified",
            "risk": "low",
            "recommendation": "Cookie restricted to current domain only"
        })
        return result
    
    # Check for overly broad domain
    if domain.startswith('.'):
        parts = domain.split('.')
        if len(parts) <= 2:  # e.g., .com, .co.uk
            result["risk"] = "critical"
            result["findings"].append({
                "finding": f"Extremely broad domain scope: {domain}",
                "risk": "critical",
                "recommendation": "This cookie may be accessible across many websites"
            })
        elif len(parts) == 3:  # e.g., .example.com
            result["risk"] = "medium"
            result["findings"].append({
                "finding": f"Domain includes all subdomains: {domain}",
                "risk": "medium",
                "recommendation": "Cookie accessible from all subdomains"
            })
    
    return result


def check_known_trackers(name: str) -> Dict[str, Any]:
    """Check if cookie matches known tracking cookies"""
    result = {
        "is_tracker": False,
        "tracker_info": None
    }
    
    # Exact match
    if name in KNOWN_TRACKERS:
        result["is_tracker"] = True
        result["tracker_info"] = KNOWN_TRACKERS[name]
        return result
    
    # Partial match (for cookies like _ga_XXXXX)
    for tracker_name, info in KNOWN_TRACKERS.items():
        if name.startswith(tracker_name):
            result["is_tracker"] = True
            result["tracker_info"] = info
            return result
    
    return result


def scan_suspicious_patterns(name: str, value: str) -> List[Dict[str, Any]]:
    """Scan cookie name and value for suspicious patterns"""
    findings = []
    
    combined = f"{name.lower()} {value.lower()}"
    
    for pattern, description, risk in SUSPICIOUS_PATTERNS:
        if re.search(pattern, combined, re.IGNORECASE):
            findings.append({
                "pattern": pattern,
                "description": description,
                "risk": risk,
                "recommendation": f"Review if {description.lower()} should be stored in cookies"
            })
    
    return findings


def analyze_cookie_security(cookie_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main function: Comprehensive security analysis of a cookie
    """
    name = cookie_data.get("name", "")
    value = cookie_data.get("value", "")
    domain = cookie_data.get("domain", "")
    path = cookie_data.get("path", "/")
    expires = cookie_data.get("expires", "")
    secure = cookie_data.get("secure", False)
    httponly = cookie_data.get("httponly", False)
    samesite = cookie_data.get("samesite", "")
    
    analysis = {
        "overall_risk_score": 0,
        "overall_risk_level": "low",
        "security_flags": [],
        "tracking_analysis": {},
        "value_analysis": {},
        "expiration_analysis": {},
        "domain_analysis": {},
        "suspicious_patterns": [],
        "recommendations": []
    }
    
    risk_score = 0
    
    # 1. Security Flags Analysis
    if not secure:
        risk_score += 15
        analysis["security_flags"].append({
            "flag": "Secure",
            "status": "MISSING",
            "risk": "high",
            "description": "Cookie can be transmitted over unencrypted HTTP connections",
            "recommendation": "Set Secure flag to prevent transmission over HTTP"
        })
    else:
        analysis["security_flags"].append({
            "flag": "Secure",
            "status": "PRESENT",
            "risk": "none",
            "description": "Cookie only transmitted over HTTPS"
        })
    
    if not httponly:
        risk_score += 20
        analysis["security_flags"].append({
            "flag": "HttpOnly",
            "status": "MISSING",
            "risk": "high",
            "description": "Cookie accessible via JavaScript (XSS vulnerability)",
            "recommendation": "Set HttpOnly flag to prevent JavaScript access"
        })
    else:
        analysis["security_flags"].append({
            "flag": "HttpOnly",
            "status": "PRESENT",
            "risk": "none",
            "description": "Cookie protected from JavaScript access"
        })
    
    if not samesite or samesite.lower() == "none":
        risk_score += 15
        analysis["security_flags"].append({
            "flag": "SameSite",
            "status": "MISSING/NONE",
            "risk": "high",
            "description": "Cookie vulnerable to CSRF attacks",
            "recommendation": "Set SameSite to 'Strict' or 'Lax'"
        })
    elif samesite.lower() == "lax":
        analysis["security_flags"].append({
            "flag": "SameSite",
            "status": "LAX",
            "risk": "low",
            "description": "Partial CSRF protection enabled"
        })
    elif samesite.lower() == "strict":
        analysis["security_flags"].append({
            "flag": "SameSite",
            "status": "STRICT",
            "risk": "none",
            "description": "Full CSRF protection enabled"
        })
    
    # 2. Known Tracker Detection
    tracker_check = check_known_trackers(name)
    analysis["tracking_analysis"] = tracker_check
    if tracker_check["is_tracker"]:
        tracker_risk = tracker_check["tracker_info"]["risk"]
        if tracker_risk == "high":
            risk_score += 25
        elif tracker_risk == "medium":
            risk_score += 15
        analysis["recommendations"].append({
            "category": "Privacy",
            "recommendation": f"This is a known {tracker_check['tracker_info']['type']} cookie from {tracker_check['tracker_info']['name']}",
            "action": "Consider blocking or reviewing privacy policy"
        })
    
    # 3. Value Analysis
    entropy = calculate_entropy(value)
    encoding_analysis = detect_encoding(value)
    
    analysis["value_analysis"] = {
        "length": len(value),
        "entropy": entropy,
        "entropy_assessment": "high" if entropy > 4.5 else "normal" if entropy > 3.0 else "low",
        "encoding": encoding_analysis
    }
    
    if entropy > 4.5 and len(value) > 20:
        analysis["value_analysis"]["note"] = "High entropy suggests session token or encrypted data"
        if not httponly:
            risk_score += 10
            analysis["recommendations"].append({
                "category": "Security",
                "recommendation": "High-entropy value (likely session token) without HttpOnly flag",
                "action": "Add HttpOnly flag to protect session token"
            })
    
    # 4. Expiration Analysis
    analysis["expiration_analysis"] = analyze_expiration(expires)
    if analysis["expiration_analysis"]["risk"] == "high":
        risk_score += 15
    elif analysis["expiration_analysis"]["risk"] == "medium":
        risk_score += 8
    
    # 5. Domain Scope Analysis
    analysis["domain_analysis"] = analyze_domain_scope(domain)
    if analysis["domain_analysis"]["risk"] == "critical":
        risk_score += 30
    elif analysis["domain_analysis"]["risk"] == "medium":
        risk_score += 10
    
    # 6. Suspicious Pattern Scanning
    suspicious = scan_suspicious_patterns(name, value)
    analysis["suspicious_patterns"] = suspicious
    for pattern in suspicious:
        if pattern["risk"] == "critical":
            risk_score += 35
        elif pattern["risk"] == "high":
            risk_score += 20
        elif pattern["risk"] == "medium":
            risk_score += 10
    
    # 7. Path Analysis
    if path == "/":
        analysis["recommendations"].append({
            "category": "Scope",
            "recommendation": "Cookie accessible on entire domain",
            "action": "Consider restricting path if cookie only needed for specific routes"
        })
    
    # Calculate final risk score and level
    analysis["overall_risk_score"] = min(risk_score, 100)
    
    if risk_score >= 60:
        analysis["overall_risk_level"] = "high"
    elif risk_score >= 30:
        analysis["overall_risk_level"] = "medium"
    else:
        analysis["overall_risk_level"] = "low"
    
    return analysis