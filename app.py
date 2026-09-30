
import os, re, base64, requests
from flask import Flask, request, jsonify, send_from_directory
from urllib.parse import urlparse

app = Flask(__name__, static_folder="static")

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "").strip()
ENABLE_EXTERNAL_URL_SCANS = os.getenv("ENABLE_EXTERNAL_URL_SCANS", "false").lower() == "true"

SHORTENERS = {"bit.ly","tinyurl.com","t.co","goo.gl","is.gd","cutt.ly","rb.gy","ow.ly"}
SUSPICIOUS_TLDS = {".xyz",".top",".click",".shop",".work",".buzz",".icu",".cam"}
RISKY_WORDS = [
    ("urgent", 1, "Creates urgency or pressure."),
    ("verify your account", 2, "Requests account verification."),
    ("send money", 2, "Requests that money be sent."),
    ("pay now", 2, "Uses immediate payment language."),
    ("otp", 2, "Mentions a one-time verification code."),
    ("pin", 2, "Mentions a PIN or sensitive credential."),
    ("password", 2, "Mentions a password."),
    ("won", 2, "Claims an unexpected prize or reward."),
    ("prize", 2, "Mentions an unexpected prize."),
    ("investment", 1, "Mentions an investment opportunity."),
    ("loan", 1, "Mentions a loan offer."),
    ("job offer", 1, "Contains an unexpected job offer."),
    ("click here", 1, "Pushes the user to click a link."),
]

def extract_urls(text):
    return [x.rstrip(".,);") for x in re.findall(r'https?://[^\s<>"\']+', text)]

def local_signals(text):
    low = text.lower()
    score, reasons = 0, []
    for word, points, reason in RISKY_WORDS:
        if word in low:
            score += points
            reasons.append(reason)

    for u in extract_urls(text):
        p = urlparse(u)
        host = (p.hostname or "").lower()
        if p.scheme != "https":
            score += 2; reasons.append("The link does not use HTTPS.")
        if host in SHORTENERS:
            score += 2; reasons.append("The link uses a URL shortener, hiding its final destination.")
        if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
            score += 1; reasons.append("The domain uses a TLD that deserves extra verification.")
        if host.count(".") >= 3:
            score += 1; reasons.append("The domain has an unusually deep subdomain structure.")
    return score, reasons

def vt_existing_report(url):
    if not VT_API_KEY:
        return None
    # This GET retrieves an existing VT URL object and avoids submitting a new indicator.
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    r = requests.get(
        f"https://www.virustotal.com/api/v3/urls/{url_id}",
        headers={"x-apikey": VT_API_KEY, "accept": "application/json"},
        timeout=12,
    )
    if r.status_code == 404:
        return {"status": "not_found"}
    r.raise_for_status()
    data = r.json().get("data", {}).get("attributes", {})
    stats = data.get("last_analysis_stats", {})
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    total = sum(int(v or 0) for v in stats.values() if isinstance(v, (int, float)))
    return {
        "status": "found",
        "malicious": malicious,
        "suspicious": suspicious,
        "total": total,
        "last_analysis_date": data.get("last_analysis_date"),
        "categories": data.get("categories", {}),
    }

def urlscan_search(url):
    if not URLSCAN_API_KEY:
        return None
    host = urlparse(url).hostname
    if not host:
        return None
    r = requests.get(
        "https://urlscan.io/api/v1/search/",
        params={"q": f"domain:{host}"},
        headers={"API-Key": URLSCAN_API_KEY},
        timeout=12,
    )
    r.raise_for_status()
    return {"status": "found", "results": r.json().get("results", [])[:3]}

def analyze(text):
    if len(text) > 10000:
        raise ValueError("Input is too long.")
    urls = extract_urls(text)
    score, reasons = local_signals(text)
    providers = []

    # External lookups are restricted to URLs and do not submit scans by default.
    if ENABLE_EXTERNAL_URL_SCANS and urls:
        for u in urls[:3]:
            try:
                vt = vt_existing_report(u)
                if vt:
                    providers.append({"provider": "VirusTotal", "url": u, "result": vt})
                    if vt.get("status") == "found":
                        if vt.get("malicious", 0) > 0:
                            score += min(5, vt["malicious"])
                            reasons.append(f"VirusTotal currently has {vt['malicious']} malicious engine detection(s) for this URL.")
                        if vt.get("suspicious", 0) > 0:
                            score += min(3, vt["suspicious"])
                            reasons.append(f"VirusTotal currently has {vt['suspicious']} suspicious engine detection(s) for this URL.")
            except Exception as e:
                providers.append({"provider": "VirusTotal", "url": u, "error": "lookup_failed"})

            try:
                us = urlscan_search(u)
                if us:
                    providers.append({"provider": "urlscan.io", "url": u, "result": us})
            except Exception:
                providers.append({"provider": "urlscan.io", "url": u, "error": "lookup_failed"})

    if score >= 6:
        level = "HIGH RISK"
        advice = "Do not send money or share PINs, OTPs, passwords, or other sensitive information until independently verified."
    elif score >= 3:
        level = "SUSPICIOUS"
        advice = "Pause and verify the sender, business, and destination using an official source."
    else:
        level = "LOWER RISK SIGNALS"
        advice = "No strong warning signals were detected. This does not prove the content is safe."

    return {
        "level": level, "score": score,
        "reasons": reasons[:10] or ["No common warning signal was detected."],
        "advice": advice, "urls_found": urls,
        "external_checks_enabled": bool(ENABLE_EXTERNAL_URL_SCANS and urls),
        "providers": providers,
        "privacy_note": "External checks are URL-only. Do not paste private, confidential, or personally identifying information.",
        "disclaimer": "Risk screening is not a guarantee of safety."
    }

@app.get("/")
def home():
    return send_from_directory("static", "index.html")

@app.post("/api/check")
def check():
    data = request.get_json(silent=True) or {}
    text = str(data.get("text", "")).strip()
    if not text:
        return jsonify({"error": "Please provide text to check."}), 400
    try:
        return jsonify(analyze(text))
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.get("/api/status")
def status():
    return jsonify({
        "external_url_checks": ENABLE_EXTERNAL_URL_SCANS,
        "virustotal_configured": bool(VT_API_KEY),
        "urlscan_configured": bool(URLSCAN_API_KEY)
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
