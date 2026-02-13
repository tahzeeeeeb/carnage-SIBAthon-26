document.getElementById("analyzeBtn").addEventListener("click", analyze);

function analyze() {

    let text = document.getElementById("inputText").value;

    if (text.trim() === "") {
        alert("Please enter some content.");
        return;
    }

    // Demo logic (replace later with backend fetch)
    let score = Math.floor(Math.random() * 100);

    let riskLevel = "Low";
    let riskClass = "low";

    if (score > 60) {
        riskLevel = "High";
        riskClass = "high";
    } 
    else if (score > 30) {
        riskLevel = "Medium";
        riskClass = "medium";
    }

    document.getElementById("resultBox").style.display = "block";
    document.getElementById("scoreValue").innerText = score;

    let badge = document.getElementById("riskBadge");
    badge.innerText = riskLevel;
    badge.className = "risk " + riskClass;

    let patternsDiv = document.getElementById("patterns");
    patternsDiv.innerHTML = "";

    let samplePatterns = [
        "Urgency Tactics Detected",
        "Scarcity Messaging Found",
        "Emotional Pressure Language",
        "Forced Subscription Indicators"
    ];

    samplePatterns.forEach(pattern => {
        let div = document.createElement("div");
        div.className = "pattern-card";
        div.innerText = pattern;
        patternsDiv.appendChild(div);
    });
}
