#!/usr/bin/env python3
"""
SecureCorp Internal Portal
Internal business application for lab testing.
"""
import os
import sqlite3
import subprocess
import secrets
import base64
from flask import Flask, request, render_template_string, redirect, session, g

app = Flask(__name__)

# 🔧 FIX 1: Secret key из переменной окружения (иначе сессии сбросятся при рестарте)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# 🔧 FIX 2: Путь к БД. На Render используем persistent disk (/data) или локально
DB_PATH = os.environ.get("DATABASE_PATH", "securecorp.db")


# ============================================================
# SECURITY: Restrict to internal network only
# ============================================================
@app.before_request
def check_source():
    # 🔧 FIX 3: Отключаем IP-проверку для Render, иначе всё заблокируется
    # В реальной сети проверка работала бы, но облачные IP не входят в 192.168.x.x
    if os.environ.get("FLASK_ENV") == "production":
        return  # пропускаем проверку в облаке
    
    ip = request.remote_addr
    if not (ip.startswith(("127.0.0.1", "192.168.", "10.0.", "172.16."))):
        return "Access denied", 403


# ============================================================
# DATABASE
# ============================================================
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db:
        db.close()


def init_db():
    # 🔧 FIX 4: Инициализируем БД только если она пуста
    # Иначе при каждом рестарте Render все данные будут стираться
    db = sqlite3.connect(DB_PATH)
    c = db.cursor()
    
    # Проверяем, есть ли уже таблицы
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='employees'")
    if c.fetchone():
        db.close()
        return  # БД уже инициализирована
    
    c.execute("""
        CREATE TABLE employees (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT,
            department TEXT,
            clearance INTEGER DEFAULT 1
        )
    """)
    c.executemany("INSERT INTO employees VALUES (?, ?, ?, ?, ?, ?)", [
        (1, "admin", "Xk9$mP2vL8qR", "admin@securecorp.local", "IT Security", 5),
        (2, "j.doe", "Summer2024!", "j.doe@securecorp.local", "Finance", 2),
        (3, "m.smith", "Password123", "m.smith@securecorp.local", "HR", 2),
        (4, "r.johnson", "Qwerty!234", "r.johnson@securecorp.local", "Engineering", 3),
    ])
    
    c.execute("""
        CREATE TABLE documents (
            id INTEGER PRIMARY KEY,
            owner_id INTEGER,
            title TEXT,
            content TEXT,
            classification TEXT
        )
    """)
    c.executemany("INSERT INTO documents VALUES (?, ?, ?, ?, ?)", [
        (1, 1, "Security Audit Q3", "Internal audit results. Critical vulnerabilities found in legacy systems. API keys exposed in frontend code: AKIAIOSFODNN7EXAMPLE", "CONFIDENTIAL"),
        (2, 2, "Budget Report", "Q3 budget allocation: $2.4M for infrastructure, $800K for R&D.", "INTERNAL"),
        (3, 3, "Employee Records", "Salary data for all employees. Admin: $180K, Engineers: $140K average.", "RESTRICTED"),
        (4, 4, "Project Phoenix", "New product codename Phoenix. Launch date: 2025-Q1. Patent pending.", "TOP SECRET"),
    ])
    
    db.commit()
    db.close()

# ============================================================
# TEMPLATES
# ============================================================
LAYOUT = """
<!DOCTYPE html>
<html>
<head>
    <title>SecureCorp Portal</title>
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body { font-family:'Segoe UI',Tahoma,sans-serif; background:#f5f7fa; color:#333; }
        .header { background:#2c3e50; color:white; padding:1rem 2rem; display:flex; justify-content:space-between; align-items:center; }
        .header h1 { font-size:1.5rem; }
        .nav a { color:#ecf0f1; margin-left:1.5rem; text-decoration:none; }
        .nav a:hover { color:#3498db; }
        .container { max-width:1200px; margin:2rem auto; padding:0 2rem; }
        .card { background:white; border-radius:8px; box-shadow:0 2px 10px rgba(0,0,0,0.1); padding:2rem; margin-bottom:2rem; }
        .btn { background:#3498db; color:white; padding:0.7rem 1.5rem; border:none; border-radius:4px; cursor:pointer; font-size:1rem; text-decoration:none; display:inline-block; }
        .btn:hover { background:#2980b9; }
        input, textarea { width:100%; padding:0.7rem; margin:0.5rem 0; border:1px solid #ddd; border-radius:4px; }
        table { width:100%; border-collapse:collapse; margin-top:1rem; }
        th, td { padding:0.8rem; text-align:left; border-bottom:1px solid #ddd; }
        th { background:#f8f9fa; }
        .alert { padding:1rem; border-radius:4px; margin-bottom:1rem; }
        .alert-error { background:#ffe6e6; border:1px solid #ff6b6b; color:#c0392b; }
        .alert-success { background:#e6ffe6; border:1px solid #51cf66; }
        .badge { padding:0.2rem 0.6rem; border-radius:12px; font-size:0.8rem; font-weight:bold; }
        .badge-confidential { background:#ff6b6b; color:white; }
        .badge-internal { background:#ffd93d; }
        .badge-restricted { background:#ff922b; color:white; }
        .badge-topsecret { background:#000; color:white; }
        pre { background:#f8f9fa; padding:1rem; overflow-x:auto; border-radius:4px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🏢 SecureCorp Internal Portal</h1>
        <div class="nav">
            {% if session.user %}
                <a href="/dashboard">Dashboard</a>
                <a href="/documents">Documents</a>
                <a href="/tools">Tools</a>
                <a href="/profile">Profile</a>
                <a href="/logout">Logout ({{ session.user }})</a>
            {% else %}
                <a href="/login">Login</a>
            {% endif %}
        </div>
    </div>
    <div class="container">
        {{ content | safe }}
    </div>
</body>
</html>
"""

def render(content):
    return render_template_string(LAYOUT, content=content)

# ============================================================
# AUTH
# ============================================================
@app.route("/")
def index():
    if session.get("user"):
        return redirect("/dashboard")
    return redirect("/login")

@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        
        db = get_db()
        query = f"SELECT * FROM employees WHERE username='{username}' AND password='{password}'"
        
        try:
            user = db.execute(query).fetchone()
            if user:
                session["user"] = user["username"]
                session["user_id"] = user["id"]
                session["clearance"] = user["clearance"]
                return redirect("/dashboard")
            else:
                error = "Invalid credentials"
        except Exception as e:
            error = "Authentication error"
    
    error_html = ""
    if error:
        error_html = f'<div class="alert alert-error">{error}</div>'
    
    content = f"""
    <div class="card" style="max-width:400px; margin:3rem auto;">
        <h2>Employee Login</h2>
        {error_html}
        <form method="POST">
            <label>Username</label>
            <input type="text" name="username" required>
            <label>Password</label>
            <input type="password" name="password" required>
            <button class="btn" type="submit">Sign In</button>
        </form>
    </div>
    """
    return render(content)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

# ============================================================
# DASHBOARD
# ============================================================
@app.route("/dashboard")
def dashboard():
    if not session.get("user"):
        return redirect("/login")
    
    db = get_db()
    user = db.execute("SELECT * FROM employees WHERE id=?", (session["user_id"],)).fetchone()
    documents = db.execute("SELECT * FROM documents LIMIT 3").fetchall()
    
    docs_rows = ""
    for doc in documents:
        badge_class = doc['classification'].lower().replace(' ', '')
        docs_rows += f"""
        <tr>
            <td>{doc['title']}</td>
            <td><span class="badge badge-{badge_class}">{doc['classification']}</span></td>
            <td><a href="/documents/{doc['id']}">View</a></td>
        </tr>
        """
    
    content = f"""
    <div class="card">
        <h2>Welcome back, {user['username']}!</h2>
        <p>Department: {user['department']} | Clearance Level: {user['clearance']}</p>
    </div>
    
    <div class="card">
        <h3>Quick Search</h3>
        <form action="/search" method="GET">
            <input type="text" name="q" placeholder="Search documents, employees...">
            <button class="btn" type="submit">Search</button>
        </form>
    </div>
    
    <div class="card">
        <h3>Recent Documents</h3>
        <table>
            <tr><th>Title</th><th>Classification</th><th>Action</th></tr>
            {docs_rows}
        </table>
    </div>
    """
    return render(content)

# ============================================================
# SEARCH (XSS)
# ============================================================
@app.route("/search")
def search():
    if not session.get("user"):
        return redirect("/login")
    
    query = request.args.get("q", "")
    results_html = ""
    
    if query:
        db = get_db()
        docs = db.execute("SELECT * FROM documents WHERE title LIKE ? OR content LIKE ?", 
                         (f"%{query}%", f"%{query}%")).fetchall()
        
        if docs:
            results_html = f"<h3>Search results for: {query}</h3><table><tr><th>Title</th><th>Classification</th></tr>"
            for doc in docs:
                results_html += f"<tr><td><a href='/documents/{doc['id']}'>{doc['title']}</a></td><td>{doc['classification']}</td></tr>"
            results_html += "</table>"
        else:
            results_html = f"<p>No results found for: {query}</p>"
    
    content = f"""
    <div class="card">
        <h2>Search Portal</h2>
        <form>
            <input type="text" name="q" value="{query}" placeholder="Search...">
            <button class="btn" type="submit">Search</button>
        </form>
        {results_html}
    </div>
    """
    return render(content)

# ============================================================
# DOCUMENTS (IDOR)
# ============================================================
@app.route("/documents")
def documents_list():
    if not session.get("user"):
        return redirect("/login")
    
    db = get_db()
    docs = db.execute("SELECT * FROM documents").fetchall()
    
    rows = ""
    for doc in docs:
        badge_class = doc['classification'].lower().replace(' ', '')
        rows += f"""
        <tr>
            <td>{doc['id']}</td>
            <td>{doc['title']}</td>
            <td><span class="badge badge-{badge_class}">{doc['classification']}</span></td>
            <td><a href="/documents/{doc['id']}">View</a></td>
        </tr>
        """
    
    content = f"""
    <div class="card">
        <h2>Document Repository</h2>
        <table>
            <tr><th>ID</th><th>Title</th><th>Classification</th><th>Action</th></tr>
            {rows}
        </table>
    </div>
    """
    return render(content)

@app.route("/documents/<int:doc_id>")
def view_document(doc_id):
    if not session.get("user"):
        return redirect("/login")
    
    db = get_db()
    doc = db.execute(f"SELECT * FROM documents WHERE id={doc_id}").fetchone()
    
    if not doc:
        content = "<div class='card'><h2>Document not found</h2></div>"
        return render(content)
    
    badge_class = doc['classification'].lower().replace(' ', '')
    content = f"""
    <div class="card">
        <h2>{doc['title']}</h2>
        <p><span class="badge badge-{badge_class}">{doc['classification']}</span></p>
        <hr style="margin:1rem 0;">
        <p>{doc['content']}</p>
        <br>
        <a href="/documents" class="btn">Back to Documents</a>
    </div>
    """
    return render(content)

# ============================================================
# TOOLS (Command Injection)
# ============================================================
@app.route("/tools", methods=["GET", "POST"])
def tools():
    if not session.get("user"):
        return redirect("/login")
    
    output = ""
    if request.method == "POST":
        action = request.form.get("action")
        target = request.form.get("target", "")
        
        if action == "ping":
            try:
                result = subprocess.run(
                    f"ping -c 3 {target}",
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=15
                )
                output = result.stdout + result.stderr
            except Exception as e:
                output = str(e)
        
        elif action == "dns":
            try:
                result = subprocess.run(
                    f"nslookup {target}",
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                output = result.stdout + result.stderr
            except Exception as e:
                output = str(e)
    
    output_html = ""
    if output:
        output_html = f"""
        <div class="card">
            <h3>Output</h3>
            <pre>{output}</pre>
        </div>
        """
    
    content = f"""
    <div class="card">
        <h2>Network Diagnostics</h2>
        <form method="POST">
            <label>Target Host/IP</label>
            <input type="text" name="target" required>
            <br><br>
            <button class="btn" name="action" value="ping">Ping Test</button>
            <button class="btn" name="action" value="dns">DNS Lookup</button>
        </form>
    </div>
    {output_html}
    """
    return render(content)

# ============================================================
# PROFILE (Path Traversal)
# ============================================================
@app.route("/profile")
def profile():
    if not session.get("user"):
        return redirect("/login")
    
    db = get_db()
    user = db.execute("SELECT * FROM employees WHERE id=?", (session["user_id"],)).fetchone()
    
    avatar = request.args.get("avatar", "default.png")
    avatar_path = os.path.join("avatars", avatar)
    
    try:
        with open(avatar_path, "rb") as f:
            avatar_data = "data:image/png;base64," + base64.b64encode(f.read()).decode()
    except:
        avatar_data = f"https://ui-avatars.com/api/?name={user['username']}"
    
    content = f"""
    <div class="card">
        <h2>Employee Profile</h2>
        <img src="{avatar_data}" style="width:100px; height:100px; border-radius:50%;">
        <table>
            <tr><th>Username</th><td>{user['username']}</td></tr>
            <tr><th>Email</th><td>{user['email']}</td></tr>
            <tr><th>Department</th><td>{user['department']}</td></tr>
            <tr><th>Clearance</th><td>{user['clearance']}</td></tr>
        </table>
    </div>
    
    <div class="card">
        <h3>Change Avatar</h3>
        <form method="GET">
            <input type="text" name="avatar" value="{avatar}" placeholder="filename.png">
            <button class="btn" type="submit">Update</button>
        </form>
    </div>
    """
    return render(content)

# ============================================================
if __name__ == "__main__":
    os.makedirs("avatars", exist_ok=True)
    default_avatar_path = "avatars/default.png"
    if not os.path.exists(default_avatar_path):
        with open(default_avatar_path, "wb") as f:
            f.write(b'\x89PNG\r\n\x1a\n')
    init_db()
    print("SecureCorp Portal started")
    print("Internal use only")
    app.run(host="0.0.0.0", port=5000, debug=False)