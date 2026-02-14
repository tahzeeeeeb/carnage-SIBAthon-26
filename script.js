// script.js - Fixed version with real backend integration

document.getElementById("analyzeBtn").addEventListener("click", analyze);

// Add event listener for cookie analysis if the tab exists
const cookieAnalyzeBtn = document.getElementById("analyzeCookieBtn");
if (cookieAnalyzeBtn) {
    cookieAnalyzeBtn.addEventListener("click", analyzeCookie);
}

async function analyze() {
    const text = document.getElementById("inputText").value;

    if (text.trim() === "") {
        showAlert("Please enter some content to analyze.");
        return;
    }

    // Show loading state
    const btn = document.getElementById("analyzeBtn");
    const originalText = btn.innerText;
    btn.innerText = "Analyzing...";
    btn.disabled = true;

    try {
        const response = await fetch("/analyze", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ text: text }),
        });

        if (!response.ok) {
            throw new Error(`Server error: ${response.status}`);
        }

        const result = await response.json();
        displayResults(result);

    } catch (error) {
        console.error("Analysis failed:", error);
        showAlert("Analysis failed. Make sure the server is running on http://localhost:5000");
    } finally {
        btn.innerText = originalText;
        btn.disabled = false;
    }
}

function displayResults(result) {
    // Show result box
    document.getElementById("resultBox").style.display = "block";

    // Update score
    document.getElementById("scoreValue").innerText = result.manipulation_index;

    // Update risk badge
    const badge = document.getElementById("riskBadge");
    badge.innerText = result.risk_level;
    badge.className = "risk " + result.risk_level.toLowerCase();

    // Clear and populate patterns
    const patternsDiv = document.getElementById("patterns");
    patternsDiv.innerHTML = "";

    // Display detected patterns with details
    const patterns = result.detected_patterns;
    let hasDetections = false;

    for (const [category, data] of Object.entries(patterns)) {
        if (data.count > 0) {
            hasDetections = true;
            const card = document.createElement("div");
            card.className = "pattern-card";
            
            const title = document.createElement("div");
            title.className = "pattern-title";
            title.innerText = formatCategoryName(category);
            
            const matches = document.createElement("div");
            matches.className = "pattern-matches";
            matches.innerText = `Matches found: ${data.matches.join(", ")}`;
            
            card.appendChild(title);
            card.appendChild(matches);
            patternsDiv.appendChild(card);
        }
    }

    // Display explanations
    if (result.explanations && result.explanations.length > 0) {
        const explanationsHeader = document.createElement("div");
        explanationsHeader.className = "explanations-header";
        explanationsHeader.innerText = "⚠️ Explanations";
        patternsDiv.appendChild(explanationsHeader);

        result.explanations.forEach(exp => {
            const expCard = document.createElement("div");
            expCard.className = "pattern-card explanation";
            expCard.innerHTML = `<strong>${formatCategoryName(exp.type)}:</strong> ${exp.explanation}`;
            patternsDiv.appendChild(expCard);
        });
    }

    if (!hasDetections) {
        const noPatterns = document.createElement("div");
        noPatterns.className = "pattern-card safe";
        noPatterns.innerText = "✓ No manipulation patterns detected";
        patternsDiv.appendChild(noPatterns);
    }
}

async function analyzeCookie() {
    const cookieName = document.getElementById("cookieName")?.value || "";
    const cookieValue = document.getElementById("cookieValue")?.value || "";
    const cookieDomain = document.getElementById("cookieDomain")?.value || "";
    const cookiePath = document.getElementById("cookiePath")?.value || "/";
    const cookieExpires = document.getElementById("cookieExpires")?.value || "";
    const cookieSecure = document.getElementById("cookieSecure")?.checked || false;
    const cookieHttpOnly = document.getElementById("cookieHttpOnly")?.checked || false;
    const cookieSameSite = document.getElementById("cookieSameSite")?.value || "";

    if (cookieValue.trim() === "") {
        showAlert("Please enter a cookie value to analyze.");
        return;
    }

    const btn = document.getElementById("analyzeCookieBtn");
    const originalText = btn.innerText;
    btn.innerText = "Analyzing...";
    btn.disabled = true;

    try {
        const response = await fetch("/analyze-cookie", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                name: cookieName,
                value: cookieValue,
                domain: cookieDomain,
                path: cookiePath,
                expires: cookieExpires,
                secure: cookieSecure,
                httponly: cookieHttpOnly,
                samesite: cookieSameSite
            }),
        });

        if (!response.ok) {
            throw new Error(`Server error: ${response.status}`);
        }

        const result = await response.json();
        displayCookieResults(result);

    } catch (error) {
        console.error("Cookie analysis failed:", error);
        showAlert("Analysis failed. Make sure the server is running.");
    } finally {
        btn.innerText = originalText;
        btn.disabled = false;
    }
}

function displayCookieResults(result) {
    const resultBox = document.getElementById("cookieResultBox");
    if (!resultBox) return;
    
    resultBox.style.display = "block";
    
    const analysis = result.security_analysis;
    
    // Update risk score and level
    document.getElementById("cookieRiskScore").innerText = analysis.overall_risk_score;
    
    const riskBadge = document.getElementById("cookieRiskBadge");
    riskBadge.innerText = analysis.overall_risk_level.toUpperCase();
    riskBadge.className = "risk " + analysis.overall_risk_level;
    
    // Display security flags
    const flagsContainer = document.getElementById("securityFlags");
    flagsContainer.innerHTML = "<h4>Security Flags</h4>";
    
    analysis.security_flags.forEach(flag => {
        const flagDiv = document.createElement("div");
        flagDiv.className = `flag-item ${flag.status === 'MISSING' || flag.status === 'MISSING/NONE' ? 'flag-warning' : 'flag-ok'}`;
        flagDiv.innerHTML = `
            <span class="flag-name">${flag.flag}</span>
            <span class="flag-status">${flag.status}</span>
            <p class="flag-desc">${flag.description}</p>
            ${flag.recommendation ? `<p class="flag-rec">💡 ${flag.recommendation}</p>` : ''}
        `;
        flagsContainer.appendChild(flagDiv);
    });
    
    // Display tracking analysis
    const trackingContainer = document.getElementById("trackingAnalysis");
    trackingContainer.innerHTML = "<h4>Tracking Analysis</h4>";
    
    if (analysis.tracking_analysis.is_tracker) {
        const info = analysis.tracking_analysis.tracker_info;
        const trackerDiv = document.createElement("div");
        trackerDiv.className = "tracker-warning";
        trackerDiv.innerHTML = `
            <span class="tracker-icon">🔍</span>
            <strong>Known Tracker Detected!</strong>
            <p>Service: ${info.name}</p>
            <p>Type: ${info.type}</p>
            <p>Risk Level: ${info.risk.toUpperCase()}</p>
        `;
        trackingContainer.appendChild(trackerDiv);
    } else {
        trackingContainer.innerHTML += "<p class='no-tracker'>✓ Not a known tracking cookie</p>";
    }
    
    // Display value analysis
    const valueContainer = document.getElementById("valueAnalysis");
    valueContainer.innerHTML = "<h4>Value Analysis</h4>";
    
    const valueInfo = analysis.value_analysis;
    valueContainer.innerHTML += `
        <div class="value-info">
            <p><strong>Length:</strong> ${valueInfo.length} characters</p>
            <p><strong>Entropy:</strong> ${valueInfo.entropy} (${valueInfo.entropy_assessment})</p>
            ${valueInfo.encoding?.encoding_detected ? 
                `<p><strong>Encoding:</strong> ${valueInfo.encoding.encoding_detected}</p>` : ''}
            ${valueInfo.note ? `<p class="value-note">ℹ️ ${valueInfo.note}</p>` : ''}
        </div>
    `;
    
    // Display decoded value if available
    if (result.value_analysis?.decoded_value) {
        valueContainer.innerHTML += `
            <div class="decoded-value">
                <strong>Decoded Value:</strong>
                <pre>${escapeHtml(result.value_analysis.decoded_value)}</pre>
            </div>
        `;
    }
    
    // Display suspicious patterns
    if (analysis.suspicious_patterns.length > 0) {
        const suspiciousContainer = document.getElementById("suspiciousPatterns");
        suspiciousContainer.innerHTML = "<h4>⚠️ Suspicious Patterns Found</h4>";
        
        analysis.suspicious_patterns.forEach(pattern => {
            const patternDiv = document.createElement("div");
            patternDiv.className = `suspicious-item risk-${pattern.risk}`;
            patternDiv.innerHTML = `
                <strong>${pattern.description}</strong>
                <p>Risk: ${pattern.risk.toUpperCase()}</p>
                <p class="pattern-rec">${pattern.recommendation}</p>
            `;
            suspiciousContainer.appendChild(patternDiv);
        });
    }
    
    // Display recommendations
    if (analysis.recommendations.length > 0) {
        const recContainer = document.getElementById("recommendations");
        recContainer.innerHTML = "<h4>Recommendations</h4>";
        
        analysis.recommendations.forEach(rec => {
            const recDiv = document.createElement("div");
            recDiv.className = "recommendation-item";
            recDiv.innerHTML = `
                <span class="rec-category">${rec.category}</span>
                <p>${rec.recommendation}</p>
                <p class="rec-action">→ ${rec.action}</p>
            `;
            recContainer.appendChild(recDiv);
        });
    }
}

function formatCategoryName(category) {
    const names = {
        "urgency": "🔴 Urgency Tactics",
        "scarcity": "⚠️ Scarcity Messaging",
        "confirmshaming": "😔 Confirmshaming",
        "forced_continuity": "🔄 Forced Continuity"
    };
    return names[category] || category;
}

function showAlert(message) {
    // Custom alert instead of browser alert
    const alertDiv = document.createElement("div");
    alertDiv.className = "custom-alert";
    alertDiv.innerHTML = `
        <div class="alert-content">
            <p>${message}</p>
            <button onclick="this.parentElement.parentElement.remove()">OK</button>
        </div>
    `;
    document.body.appendChild(alertDiv);
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}