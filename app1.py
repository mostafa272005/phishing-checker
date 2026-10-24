import os
import re
import secrets
import sqlite3
from datetime import datetime
from urllib.parse import urlparse
from flask import (Flask, request, render_template_string, session,
                   redirect, url_for, flash)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "history.db")


def get_secret_key():
    """Key used to sign login sessions. Kept in a local file (never in the code)."""
    env = os.environ.get("SECRET_KEY")
    if env:
        return env
    path = os.path.join(BASE, "secret.key")
    try:
        if os.path.exists(path):
            with open(path) as f:
                return f.read().strip()
        key = secrets.token_hex(32)
        with open(path, "w") as f:
            f.write(key)
        return key
    except OSError:
        return secrets.token_hex(32)


app.secret_key = get_secret_key()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")


def init_db():
    with sqlite3.connect(DB) as con:
        con.execute(
            "CREATE TABLE IF NOT EXISTS users ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "username TEXT UNIQUE NOT NULL COLLATE NOCASE, "
            "password_hash TEXT NOT NULL, created TEXT)"
        )
        con.execute(
            "CREATE TABLE IF NOT EXISTS checks ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "url TEXT, verdict TEXT, created TEXT, user_id INTEGER)"
        )
        # Older databases were created without user_id: add it.
        cols = [row[1] for row in con.execute("PRAGMA table_info(checks)")]
        if "user_id" not in cols:
            con.execute("ALTER TABLE checks ADD COLUMN user_id INTEGER")


init_db()

LAYOUT = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title }} | PhishGuard</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Segoe UI',Tahoma,Arial,sans-serif;color:#e2e8f0;min-height:100vh;
       background:radial-gradient(circle at 20% 0%,#312e81 0,transparent 45%),
                  radial-gradient(circle at 90% 20%,#0e7490 0,transparent 40%),#0b1020;
       background-attachment:fixed}
  a{color:inherit;text-decoration:none}
  .wrap{max-width:900px;margin:0 auto;padding:0 18px}
  nav{display:flex;align-items:center;justify-content:space-between;padding:18px 0;flex-wrap:wrap;gap:10px}
  .brand{display:flex;align-items:center;gap:10px;font-weight:700;font-size:20px}
  .brand svg{width:34px;height:34px;stroke:#22d3ee;fill:rgba(34,211,238,.15)}
  .links{display:flex;flex-wrap:wrap;gap:6px;background:rgba(255,255,255,.06);padding:5px;border-radius:999px}
  .links a{padding:8px 18px;border-radius:999px;font-size:14px;color:#94a3b8;transition:.2s}
  .links a:hover{color:#fff}
  .links a.active{background:linear-gradient(135deg,#6366f1,#06b6d4);color:#fff}
  .hero{text-align:center;padding:36px 0 22px}
  .hero h1{font-size:40px;line-height:1.2;background:linear-gradient(90deg,#a5b4fc,#67e8f9);
           -webkit-background-clip:text;background-clip:text;color:transparent}
  .hero p{color:#94a3b8;margin-top:10px}
  .card{background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.1);border-radius:20px;
        padding:24px;backdrop-filter:blur(8px);box-shadow:0 10px 40px rgba(0,0,0,.35);margin-bottom:22px}
  .row{display:flex;gap:10px;flex-wrap:wrap}
  input[type=text],input[type=password]{flex:1;min-width:220px;padding:15px 18px;border-radius:14px;border:1px solid rgba(255,255,255,.15);
        background:rgba(0,0,0,.35);color:#fff;font-size:16px;outline:none}
  input[type=text]:focus,input[type=password]:focus{border-color:#22d3ee;box-shadow:0 0 0 3px rgba(34,211,238,.25)}
  button{padding:15px 28px;border:0;border-radius:14px;font-size:16px;font-weight:700;color:#fff;cursor:pointer;
        background:linear-gradient(135deg,#6366f1,#06b6d4);transition:.2s}
  button:hover{transform:translateY(-2px);box-shadow:0 8px 20px rgba(99,102,241,.45)}
  .result{display:flex;gap:26px;align-items:center;flex-wrap:wrap}
  .gauge{width:230px;flex-shrink:0}
  .gauge .track{stroke:rgba(255,255,255,.12)}
  .gauge .safe{stroke:#22c55e}.gauge .warn{stroke:#f59e0b}.gauge .bad{stroke:#ef4444}
  .gauge .num{fill:#fff;font-size:34px;font-weight:700}
  .gauge .lbl{fill:#94a3b8;font-size:11px}
  .badge{display:inline-block;padding:6px 16px;border-radius:999px;font-weight:700;font-size:14px}
  .badge.safe{background:rgba(34,197,94,.18);color:#4ade80}
  .badge.warn{background:rgba(245,158,11,.18);color:#fbbf24}
  .badge.bad{background:rgba(239,68,68,.18);color:#f87171}
  .reasons{list-style:none;margin-top:14px}
  .reasons li{padding:8px 0;border-bottom:1px solid rgba(255,255,255,.08);font-size:15px}
  .reasons li:last-child{border:0}
  .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:14px;margin-bottom:22px}
  .stat{border-radius:18px;padding:18px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.1)}
  .stat b{display:block;font-size:30px}
  .stat span{color:#94a3b8;font-size:13px}
  .chartbox{display:flex;align-items:center;gap:30px;flex-wrap:wrap}
  .donut{width:190px;flex-shrink:0}
  .donut .t{stroke:rgba(255,255,255,.1)}
  .donut .safe{stroke:#22c55e}.donut .warn{stroke:#f59e0b}.donut .bad{stroke:#ef4444}
  .legend div{margin:8px 0;display:flex;align-items:center;gap:10px;font-size:15px}
  .dot{width:12px;height:12px;border-radius:50%;display:inline-block}
  .dot.safe{background:#22c55e}.dot.warn{background:#f59e0b}.dot.bad{background:#ef4444}
  table{width:100%;border-collapse:collapse;font-size:14px}
  th{text-align:left;color:#94a3b8;font-weight:600;padding:10px;border-bottom:1px solid rgba(255,255,255,.15)}
  td{padding:12px 10px;border-bottom:1px solid rgba(255,255,255,.07);word-break:break-all}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:16px}
  .tip{border-radius:18px;padding:22px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.1);transition:.2s}
  .tip:hover{transform:translateY(-4px);border-color:#22d3ee}
  .tip .ic{font-size:32px;margin-bottom:10px}
  .tip h3{margin-bottom:8px}
  .tip p{color:#94a3b8;font-size:14px;line-height:1.6}
  .steps{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px;margin-bottom:22px}
  .step{position:relative;border-radius:18px;padding:22px 18px;background:rgba(255,255,255,.06);
        border:1px solid rgba(255,255,255,.1);text-align:center}
  .step .n{position:absolute;top:-12px;left:50%;transform:translateX(-50%);width:28px;height:28px;border-radius:50%;
        background:linear-gradient(135deg,#6366f1,#06b6d4);font-weight:700;font-size:14px;line-height:28px}
  .step .ic{font-size:34px;margin:8px 0 10px}
  .step h3{font-size:16px;margin-bottom:6px}
  .step p{color:#94a3b8;font-size:13px;line-height:1.5}
  .bars .bar{margin:14px 0}
  .bars .bar .top{display:flex;justify-content:space-between;font-size:14px;margin-bottom:6px}
  .bars .bar .top b{color:#22d3ee}
  .bars .track{height:10px;border-radius:999px;background:rgba(255,255,255,.1);overflow:hidden}
  .bars .fill{height:100%;border-radius:999px;background:linear-gradient(90deg,#6366f1,#06b6d4)}
  .scale{display:flex;border-radius:999px;overflow:hidden;margin:16px 0 8px;font-size:13px;font-weight:700;text-align:center}
  .scale div{padding:10px 4px}
  .formcard{max-width:440px;margin:0 auto 22px}
  .formcard label{display:block;margin:14px 0 6px;font-size:14px;color:#94a3b8}
  .formcard input{width:100%}
  .formcard button{width:100%;margin-top:20px}
  .formcard .alt{text-align:center;margin-top:16px;font-size:14px;color:#94a3b8}
  .formcard .alt a{color:#22d3ee}
  .flash{border-radius:14px;padding:12px 16px;margin-bottom:16px;font-size:14px}
  .flash.ok{background:rgba(34,197,94,.15);color:#4ade80}
  .flash.warn{background:rgba(245,158,11,.15);color:#fbbf24}
  .flash.err{background:rgba(239,68,68,.15);color:#f87171}
  .hint{color:#94a3b8;font-size:14px;margin:-10px 0 18px;text-align:center}
  .hint a{color:#22d3ee}
  footer{text-align:center;color:#64748b;font-size:13px;padding:26px 0}
  @media(max-width:600px){.hero h1{font-size:30px}}
</style>
</head>
<body>
<div class="wrap">
  <nav>
    <div class="brand">
      <svg viewBox="0 0 24 24" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3z"/><path d="m9 12 2 2 4-4"/>
      </svg>
      PhishGuard
    </div>
    <div class="links">
      <a href="/" class="{{ 'active' if active == 'home' }}">Checker</a>
      <a href="/history" class="{{ 'active' if active == 'history' }}">History</a>
      <a href="/how" class="{{ 'active' if active == 'how' }}">How it Works</a>
      <a href="/tips" class="{{ 'active' if active == 'tips' }}">Security Tips</a>
      {% if user %}
      <a href="/logout">Logout ({{ user }})</a>
      {% else %}
      <a href="/login" class="{{ 'active' if active == 'login' }}">Login</a>
      <a href="/register" class="{{ 'active' if active == 'register' }}">Register</a>
      {% endif %}
    </div>
  </nav>
  {% for cat, msg in get_flashed_messages(with_categories=true) %}
  <div class="flash {{ cat }}">{{ msg }}</div>
  {% endfor %}
  {{ body|safe }}
  <footer>PhishGuard - Cloud Computing Project</footer>
</div>
</body>
</html>
"""

CHECKER = """
<div class="hero">
  <h1>Is this link safe?</h1>
  <p>Paste any link and we will check it for phishing signs.</p>
</div>
<div class="card">
  <form method="post" class="row">
    <input type="hidden" name="csrf" value="{{ csrf }}">
    <input type="text" name="url" placeholder="https://example.com/login" value="{{ url }}">
    <button type="submit">Check link</button>
  </form>
</div>
{% if not user %}<p class="hint"><a href="/login">Log in</a> to save your checks in your own History.</p>{% endif %}
{% if r %}
<div class="card result">
  <svg viewBox="0 0 200 125" class="gauge">
    <path d="M 20 100 A 80 80 0 0 1 180 100" class="track" fill="none" stroke-width="16" stroke-linecap="round"/>
    {% if r.score > 0 %}
    <path d="M 20 100 A 80 80 0 0 1 180 100" class="{{ r.level }}" fill="none" stroke-width="16"
          stroke-linecap="round" stroke-dasharray="{{ r.dash }} 251.3"/>
    {% endif %}
    <text x="100" y="92" text-anchor="middle" class="num">{{ r.score }}</text>
    <text x="100" y="114" text-anchor="middle" class="lbl">RISK SCORE</text>
  </svg>
  <div style="flex:1;min-width:240px">
    <span class="badge {{ r.level }}">{{ r.verdict }}</span>
    <ul class="reasons">
      {% for reason in r.reasons %}<li>&#9888;&#65039; {{ reason }}</li>{% endfor %}
      {% if not r.reasons %}<li>&#9989; No suspicious signs found.</li>{% endif %}
    </ul>
  </div>
</div>
{% endif %}
"""

HISTORY = """
<div class="hero">
  <h1>Your history</h1>
  <p>Only the links that you checked, {{ user }}.</p>
</div>
<div class="stats">
  <div class="stat"><b>{{ total }}</b><span>Total checks</span></div>
  {% for s in segs %}
  <div class="stat"><b>{{ s.n }}</b><span>{{ s.name }}</span></div>
  {% endfor %}
</div>
{% if total %}
<div class="card chartbox">
  <svg viewBox="0 0 42 42" class="donut">
    <circle class="t" cx="21" cy="21" r="15.9155" fill="none" stroke-width="6"/>
    {% for s in segs %}{% if s.n %}
    <circle class="{{ s.cls }}" cx="21" cy="21" r="15.9155" fill="none" stroke-width="6"
            stroke-dasharray="{{ s.pct }} {{ 100 - s.pct }}" stroke-dashoffset="{{ s.offset }}"/>
    {% endif %}{% endfor %}
    <text x="21" y="22.5" text-anchor="middle" fill="#fff" font-size="7" font-weight="700">{{ total }}</text>
  </svg>
  <div class="legend">
    {% for s in segs %}
    <div><span class="dot {{ s.cls }}"></span>{{ s.name }}: <b>{{ s.n }}</b></div>
    {% endfor %}
  </div>
</div>
<div class="card">
  <table>
    <tr><th>Time</th><th>Link</th><th>Result</th></tr>
    {% for row in rows %}
    <tr>
      <td>{{ row[2] }}</td>
      <td>{{ row[0] }}</td>
      <td><span class="badge {{ levels[row[1]] }}">{{ row[1] }}</span></td>
    </tr>
    {% endfor %}
  </table>
</div>
{% else %}
<div class="card">No checks yet. Go to the Checker page and try a link while you are logged in.</div>
{% endif %}
"""

TIPS = """
<div class="hero">
  <h1>Stay safe online</h1>
  <p>Simple rules that help you spot fake links.</p>
</div>
<div class="grid">
  <div class="tip"><div class="ic">&#128274;</div><h3>Check HTTPS</h3>
    <p>Real websites use HTTPS. A link without it is a warning sign, but HTTPS alone does not prove a site is safe.</p></div>
  <div class="tip"><div class="ic">&#128290;</div><h3>IP addresses</h3>
    <p>Real companies use a domain name. A link made of numbers is very suspicious.</p></div>
  <div class="tip"><div class="ic">&#128279;</div><h3>The @ symbol</h3>
    <p>Anything before the @ in a link is ignored by the browser and can hide the real destination.</p></div>
  <div class="tip"><div class="ic">&#128207;</div><h3>Long links</h3>
    <p>Very long links with many subdomains are often used to hide the real website name.</p></div>
  <div class="tip"><div class="ic">&#127907;</div><h3>Bait words</h3>
    <p>Words like login, verify, secure, bank and update are used to scare you into clicking.</p></div>
  <div class="tip"><div class="ic">&#9989;</div><h3>What to do</h3>
    <p>Never enter a password after clicking a link in a message. Type the official address yourself.</p></div>
</div>
"""

HOW = """
<div class="hero">
  <h1>How it works</h1>
  <p>From a pasted link to a clear safety result, in four steps.</p>
</div>
<div class="steps">
  <div class="step"><div class="n">1</div><div class="ic">&#128279;</div><h3>Paste a link</h3>
    <p>You paste any link into the Checker page and press the button.</p></div>
  <div class="step"><div class="n">2</div><div class="ic">&#128269;</div><h3>Analyze</h3>
    <p>The server breaks the link into parts and tests it against phishing rules.</p></div>
  <div class="step"><div class="n">3</div><div class="ic">&#128202;</div><h3>Risk score</h3>
    <p>Every rule that matches adds points, and the total is the risk score.</p></div>
  <div class="step"><div class="n">4</div><div class="ic">&#128737;&#65039;</div><h3>Result</h3>
    <p>You see the verdict and the reasons, and a logged-in user gets the check saved in their own History.</p></div>
</div>
<div class="card bars">
  <h3 style="margin-bottom:6px">Points added by each rule</h3>
  <div class="bar"><div class="top"><span>Link uses an IP address</span><b>+2</b></div>
    <div class="track"><div class="fill" style="width:100%"></div></div></div>
  <div class="bar"><div class="top"><span>Link contains the @ symbol</span><b>+2</b></div>
    <div class="track"><div class="fill" style="width:100%"></div></div></div>
  <div class="bar"><div class="top"><span>No HTTPS</span><b>+1</b></div>
    <div class="track"><div class="fill" style="width:50%"></div></div></div>
  <div class="bar"><div class="top"><span>Very long link</span><b>+1</b></div>
    <div class="track"><div class="fill" style="width:50%"></div></div></div>
  <div class="bar"><div class="top"><span>Too many subdomains</span><b>+1</b></div>
    <div class="track"><div class="fill" style="width:50%"></div></div></div>
  <div class="bar"><div class="top"><span>Hyphen in the domain name</span><b>+1</b></div>
    <div class="track"><div class="fill" style="width:50%"></div></div></div>
  <div class="bar"><div class="top"><span>Each bait word (login, verify, secure, account, update, bank)</span><b>+1</b></div>
    <div class="track"><div class="fill" style="width:50%"></div></div></div>
</div>
<div class="card">
  <h3>How the score becomes a result</h3>
  <div class="scale">
    <div style="flex:1;background:#16a34a">0 = Looks safe</div>
    <div style="flex:2;background:#d97706">1 - 2 = Be careful</div>
    <div style="flex:3;background:#dc2626">3 or more = Suspicious</div>
  </div>
</div>
<div class="card">
  <h3 style="margin-bottom:10px">&#128274; Accounts and security</h3>
  <p style="color:#94a3b8;line-height:1.7">Users register with a username and password. Passwords are never stored as plain text:
  they are saved as salted hashes. A signed session cookie keeps you logged in, every form is protected with a CSRF token,
  and each user can only see their own History.</p>
</div>
<div class="card">
  <h3 style="margin-bottom:10px">Behind the scenes</h3>
  <p style="color:#94a3b8;line-height:1.7">The website is written in Python with Flask. Each check is stored in a SQLite database,
  which feeds the History page and its chart. The code is kept on GitHub and the site runs on a cloud server.</p>
</div>
"""

AUTH = """
<div class="hero">
  <h1>{{ 'Create account' if mode == 'register' else 'Welcome back' }}</h1>
  <p>{{ 'Register to keep your own check history.' if mode == 'register' else 'Log in to see your own check history.' }}</p>
</div>
<div class="card formcard">
  {% if error %}<div class="flash err">{{ error }}</div>{% endif %}
  <form method="post">
    <input type="hidden" name="csrf" value="{{ csrf }}">
    <label>Username</label>
    <input type="text" name="username" value="{{ username }}" maxlength="20" autocomplete="username" required>
    <label>Password</label>
    <input type="password" name="password" autocomplete="{{ 'new-password' if mode == 'register' else 'current-password' }}" required>
    {% if mode == 'register' %}
    <label>Confirm password</label>
    <input type="password" name="confirm" autocomplete="new-password" required>
    {% endif %}
    <button type="submit">{{ 'Register' if mode == 'register' else 'Log in' }}</button>
  </form>
  <div class="alt">
    {% if mode == 'register' %}Already have an account? <a href="/login">Log in</a>
    {% else %}No account yet? <a href="/register">Register</a>{% endif %}
  </div>
</div>
"""

LEVELS = {"Looks safe": "safe", "Be careful": "warn", "Suspicious": "bad"}


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


def csrf_ok():
    sent = request.form.get("csrf", "")
    return bool(sent) and secrets.compare_digest(sent, session.get("csrf", ""))


def page(title, active, body_template, **ctx):
    ctx.setdefault("csrf", csrf_token())
    ctx.setdefault("user", session.get("username"))
    body = render_template_string(body_template, **ctx)
    return render_template_string(LAYOUT, title=title, active=active, body=body,
                                  user=session.get("username"))


USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")


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
    return verdict, reasons, score


@app.route("/", methods=["GET", "POST"])
def home():
    url = ""
    r = None
    if request.method == "POST":
        if not csrf_ok():
            flash("Session expired. Please try again.", "warn")
            return redirect(url_for("home"))
        url = request.form.get("url", "").strip()
        if url:
            verdict, reasons, score = check_url(url)
            r = {
                "verdict": verdict,
                "reasons": reasons,
                "score": score,
                "level": LEVELS[verdict],
                "dash": round(min(score / 6, 1) * 251.3, 1),
            }
            if session.get("uid"):
                with sqlite3.connect(DB) as con:
                    con.execute(
                        "INSERT INTO checks (url, verdict, created, user_id) VALUES (?, ?, ?, ?)",
                        (url, verdict, datetime.now().strftime("%Y-%m-%d %H:%M"), session["uid"]),
                    )
    return page("Checker", "home", CHECKER, url=url, r=r)


@app.route("/history")
def history():
    uid = session.get("uid")
    if not uid:
        flash("Please log in to see your history.", "warn")
        return redirect(url_for("login"))
    with sqlite3.connect(DB) as con:
        rows = con.execute(
            "SELECT url, verdict, created FROM checks WHERE user_id = ? ORDER BY id DESC LIMIT 20",
            (uid,),
        ).fetchall()
        counts = dict(
            con.execute(
                "SELECT verdict, COUNT(*) FROM checks WHERE user_id = ? GROUP BY verdict", (uid,)
            ).fetchall()
        )
    total = sum(counts.values())
    segs = []
    offset = 25.0
    for name in ["Looks safe", "Be careful", "Suspicious"]:
        n = counts.get(name, 0)
        pct = round(n * 100 / total, 2) if total else 0
        segs.append({"name": name, "cls": LEVELS[name], "n": n, "pct": pct, "offset": round(offset, 2)})
        offset -= pct
    return page("History", "history", HISTORY, rows=rows, total=total, segs=segs, levels=LEVELS)


@app.route("/register", methods=["GET", "POST"])
def register():
    username, error = "", None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        if not csrf_ok():
            error = "Session expired. Please try again."
        elif not USERNAME_RE.match(username):
            error = "Username must be 3-20 letters, numbers or underscore."
        elif len(password) < 6:
            error = "Password must be at least 6 characters."
        elif password != confirm:
            error = "The two passwords do not match."
        else:
            try:
                with sqlite3.connect(DB) as con:
                    cur = con.execute(
                        "INSERT INTO users (username, password_hash, created) VALUES (?, ?, ?)",
                        (username, generate_password_hash(password),
                         datetime.now().strftime("%Y-%m-%d %H:%M")),
                    )
                    uid = cur.lastrowid
                session.clear()
                session["uid"] = uid
                session["username"] = username
                flash("Account created. Welcome, " + username + "!", "ok")
                return redirect(url_for("home"))
            except sqlite3.IntegrityError:
                error = "This username is already taken."
    return page("Register", "register", AUTH, mode="register", error=error, username=username)


@app.route("/login", methods=["GET", "POST"])
def login():
    username, error = "", None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not csrf_ok():
            error = "Session expired. Please try again."
        else:
            with sqlite3.connect(DB) as con:
                row = con.execute(
                    "SELECT id, username, password_hash FROM users WHERE username = ?",
                    (username,),
                ).fetchone()
            if row and check_password_hash(row[2], password):
                session.clear()
                session["uid"] = row[0]
                session["username"] = row[1]
                flash("Logged in as " + row[1] + ".", "ok")
                return redirect(url_for("home"))
            error = "Wrong username or password."
    return page("Login", "login", AUTH, mode="login", error=error, username=username)


@app.route("/logout")
def logout():
    session.clear()
    flash("You are logged out.", "ok")
    return redirect(url_for("home"))


@app.route("/how")
def how():
    return page("How it Works", "how", HOW)


@app.route("/tips")
def tips():
    return page("Security Tips", "tips", TIPS)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
