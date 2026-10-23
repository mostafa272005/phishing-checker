from flask import Flask, request, render_template_string
from urllib.parse import urlparse
import re

app = Flask(__name__)

PAGE = """
<!doctype html>
<html>
<head><meta charset="utf-8"><title>Phishing URL Checker</title></head>
<body style="font-family: Arial; max-width: 600px; margin: 40px auto;">
  <h1>Phishing URL Checker</h1>
  <form method="post">
    <input name="url" placeholder="Paste a link here" style="width:100%; padding:8px;" value="{{ url }}">
    <br><br>
    <button type="submit" style="padding:8px 16px;">Check</button>
  </form>
  {% if verdict %}
    <h2>Result: {{ verdict }}</h2>
    <ul>
    {% for r in reasons %}<li>{{ r }}</li>{% endfor %}
    </ul>
  {% endif %}
</body>
</html>
"""

def check_url(url):
    reasons = []
    score = 0
    host = urlparse(url if "://" in url else "http://" + url).netloc

    if not url.startswith("https://"):
        score += 1
        reasons.append("Link does not use HTTPS")
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+(:\d+)?", host):
        score += 2
        reasons.append("Link uses an IP address instead of a domain name")
    if "@" in url:
        score += 2
        reasons.append("Link contains the @ symbol")
    if len(url) > 75:
        score += 1
        reasons.append("Link is very long")
    if host.count(".") > 3:
        score += 1
        reasons.append("Link has too many subdomains")
    if "-" in host:
        score += 1
        reasons.append("Domain name contains a hyphen")
    for word in ["login", "verify", "secure", "account", "update", "bank"]:
        if word in url.lower():
            score += 1
            reasons.append("Link contains the suspicious word: " + word)

    if score >= 3:
        verdict = "Suspicious"
    elif score >= 1:
        verdict = "Be careful"
    else:
        verdict = "Looks safe"
    return verdict, reasons

@app.route("/", methods=["GET", "POST"])
def home():
    url = ""
    verdict = None
    reasons = []
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if url:
            verdict, reasons = check_url(url)
    return render_template_string(PAGE, url=url, verdict=verdict, reasons=reasons)

app.run(host="0.0.0.0", port=5000)
