
from flask import Flask, request, jsonify
import sqlite3, os, datetime, base64, requests
APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "comptes.db")
GH_TOKEN = os.environ.get("GH_TOKEN", "")
GH_REPO  = "Lucas2882-byte/login_ip"
GH_PATH  = "comptes.db"
GH_BRANCH = "main"
GH_API = f"https://api.github.com/repos/{GH_REPO}/contents/{GH_PATH}"
app = Flask(__name__)
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            public_ip TEXT,
            local_ip TEXT,
            user_agent TEXT,
            ts TEXT
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS bans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            ip TEXT,
            ts TEXT
        )""")
        conn.commit()
def upload_db_to_github():
    if not GH_TOKEN:
        return False, "GH_TOKEN missing"
    headers = {"Authorization": f"Bearer {GH_TOKEN}", "Accept": "application/vnd.github.v3+json"}
    get_resp = requests.get(GH_API, headers=headers)
    sha = get_resp.json().get("sha") if get_resp.status_code == 200 else None
    with open(DB_PATH, "rb") as f:
        content_b64 = base64.b64encode(f.read()).decode()
    data = {"message": f"update {GH_PATH}", "content": content_b64, "branch": GH_BRANCH}
    if sha:
        data["sha"] = sha
    put_resp = requests.put(GH_API, headers=headers, json=data)
    return (put_resp.status_code in (200,201)), put_resp.text[:400]
@app.route("/report", methods=["POST"])
def report():
    payload = request.get_json() or {}
    username = payload.get("username")
    public_ip = payload.get("public_ip")
    local_ip = payload.get("local_ip")
    ua = payload.get("user_agent") or request.headers.get("User-Agent","")
    ts = payload.get("timestamp") or datetime.datetime.utcnow().isoformat()
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("INSERT INTO connections (username, public_ip, local_ip, user_agent, ts) VALUES (?, ?, ?, ?, ?)", (username, public_ip, local_ip, ua, ts))
        conn.commit()
    return jsonify({"ok": True}), 201
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5001)
