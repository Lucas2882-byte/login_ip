import os
import base64  # pour stocker le hash bcrypt dans la BDD (pas pour GitHub)
import streamlit as st
import sqlite3
import bcrypt
from datetime import datetime
import subprocess, tempfile, shutil
from pathlib import Path
from urllib.parse import urlparse, quote

DB_PATH = "users.db"

# ---------- DB helpers ----------
def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()
    return conn

def user_exists(conn, username: str) -> bool:
    cur = conn.execute("SELECT 1 FROM users WHERE username = ?", (username.lower(),))
    return cur.fetchone() is not None

def email_exists(conn, email: str) -> bool:
    cur = conn.execute("SELECT 1 FROM users WHERE email = ?", (email.lower(),))
    return cur.fetchone() is not None

def create_user(conn, username: str, email: str, password: str):
    username = username.strip().lower()
    email = email.strip().lower()
    pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    pw_hash_b64 = base64.b64encode(pw_hash).decode("utf-8")
    conn.execute(
        "INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
        (username, email, pw_hash_b64, datetime.utcnow().isoformat()+"Z"),
    )
    conn.commit()

def verify_user(conn, username_or_email: str, password: str):
    key = username_or_email.strip().lower()
    cur = conn.execute(
        "SELECT id, username, email, password_hash, created_at FROM users WHERE username = ? OR email = ?",
        (key, key),
    )
    row = cur.fetchone()
    if not row:
        return None
    uid, username, email, pw_hash_b64, created_at = row
    try:
        pw_hash = base64.b64decode(pw_hash_b64.encode("utf-8"))
    except Exception:
        return None
    if bcrypt.checkpw(password.encode("utf-8"), pw_hash):
        return {"id": uid, "username": username, "email": email, "created_at": created_at}
    return None

def seed_from_config(conn):
    """
    Optionnel : créer un compte par défaut à partir des secrets/env.
    Attendus : SEED_USERNAME, SEED_EMAIL, SEED_PASSWORD
    """
    def get(name, default=None):
        try:
            return st.secrets.get(name, None) or os.environ.get(name, default)
        except Exception:
            return os.environ.get(name, default)

    su = get("SEED_USERNAME")
    se = get("SEED_EMAIL")
    sp = get("SEED_PASSWORD")

    if su and se and sp and not user_exists(conn, su) and not email_exists(conn, se):
        try:
            create_user(conn, su, se, sp)
            st.sidebar.success(f"Seeded default user '{su}'.")
            ok, msg = push_db_to_github_via_git()
            st.sidebar.success(msg) if ok else st.sidebar.info(msg)
        except Exception as e:
            st.sidebar.warning(f"Seeding failed: {e}")

# ---------- Git sync (via git CLI, sans base64) ----------
def _git_cfg():
    def get(name, default=None):
        try:
            return st.secrets.get(name, None) or os.environ.get(name, default)
        except Exception:
            return os.environ.get(name, default)

    remote = get("GIT_REMOTE")
    token  = get("GIT_TOKEN")
    repo   = get("GIT_REPO")  # attendu: "owner/repo" (tolère aussi une URL, on normalise)
    branch = get("GIT_BRANCH", "main")
    path_in_repo = get("GIT_PATH", "users.db")
    cname  = get("GIT_COMMIT_NAME", "streamlit-bot")
    cemail = get("GIT_COMMIT_EMAIL", "bot@example.com")

    # Si on n’a pas de remote explicite, on le fabrique à partir du token + repo
    if not remote and token and repo:
        repostr = repo.strip()

        # Autorise une URL complète dans GIT_REPO et en extrait owner/repo
        if repostr.startswith(("http://", "https://")):
            u = urlparse(repostr)
            repostr = u.path.strip("/")  # ex: "owner/repo" ou "owner/repo.git"

        # Retire un éventuel suffixe .git
        if repostr.endswith(".git"):
            repostr = repostr[:-4]

        # Encode le token pour éviter problèmes de caractères spéciaux
        token_enc = quote(token, safe="")
        remote = f"https://x-access-token:{token_enc}@github.com/{repostr}.git"

    if not remote:
        return None

    return {
        "remote": remote,
        "branch": branch,
        "path": path_in_repo,
        "commit_name": cname,
        "commit_email": cemail,
    }

def _run(cmd, cwd=None):
    try:
        res = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=120)
        return res.returncode, res.stdout.strip(), res.stderr.strip()
    except Exception as e:
        return 1, "", str(e)

def push_db_to_github_via_git():
    """
    Clone le repo, copie users.db vers GIT_PATH, commit & push.
    Nécessite 'git' installé et des credentials dans l'URL distante.
    """
    cfg = _git_cfg()
    if not cfg:
        return False, "GitHub non configuré (GIT_REMOTE ou GIT_TOKEN+GIT_REPO manquants)."
    if not os.path.exists(DB_PATH):
        return False, "users.db introuvable."

    tmpdir = tempfile.mkdtemp(prefix="st_git_")
    try:
        # 1) clone sur la branche (avec fallback si la branche n'existe pas encore)
        code, out, err = _run(["git", "clone", "--depth", "1", "-b", cfg["branch"], cfg["remote"], tmpdir])
        if code != 0:
            # fallback : clone la branche par défaut puis crée/checkout la branche demandée
            code2, out2, err2 = _run(["git", "clone", "--depth", "1", cfg["remote"], tmpdir])
            if code2 != 0:
                return False, f"git clone a échoué: {err or out or err2 or out2}"
            _run(["git", "checkout", "-B", cfg["branch"]], cwd=tmpdir)

        # 2) config user
        _run(["git", "config", "user.name", cfg["commit_name"]], cwd=tmpdir)
        _run(["git", "config", "user.email", cfg["commit_email"]], cwd=tmpdir)
        _run(["git", "config", "--global", "--add", "safe.directory", tmpdir], cwd=tmpdir)

        # 3) copie du fichier
        dest = Path(tmpdir) / cfg["path"]
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(DB_PATH, dest)

        # 4) add/commit/push
        code, out, err = _run(["git", "add", cfg["path"]], cwd=tmpdir)
        if code != 0:
            return False, f"git add a échoué: {err or out}"

        msg = "chore(db): update users.db from app"
        code, out, err = _run(["git", "commit", "-m", msg], cwd=tmpdir)
        if code != 0:
            if "nothing to commit" in (out + err).lower():
                return True, "Aucune modification à pousser."
            return False, f"git commit a échoué: {err or out}"

        code, out, err = _run(["git", "push", "origin", cfg["branch"]], cwd=tmpdir)
        if code != 0:
            return False, f"git push a échoué: {err or out}"

        return True, "BDD poussée sur GitHub (git push)."
    finally:
        try:
            shutil.rmtree(tmpdir, ignore_errors=True)
        except Exception:
            pass

# ---------- UI ----------
st.set_page_config(page_title="Streamlit Auth Demo", page_icon="🔐", layout="centered")

with st.sidebar:
    st.title("🔐 Auth Demo")
    st.write("Login / register avec SQLite + bcrypt.")
    st.caption("Démo. Pour la prod, utilisez une BDD gérée + secrets.")

conn = get_conn()
seed_from_config(conn)

if "user" not in st.session_state:
    st.session_state.user = None

def logout():
    st.session_state.user = None
    st.success("Logged out.")

# Logged-in
if st.session_state.user:
    user = st.session_state.user
    st.success(f"Bienvenue, **{user['username']}** !")
    st.write("Profil :")
    with st.container(border=True):
        st.write(f"**Username:** {user['username']}")
        st.write(f"**Email:** {user['email']}")
        st.write(f"**Created:** {user['created_at']}")
    if st.button("Log out", type="primary"):
        logout()
    st.divider()
    st.write("✅ Contenu protégé ici.")
else:
    tabs = st.tabs(["Sign in", "Create account"])

    # Sign in
    with tabs[0]:
        st.subheader("Sign in")
        si_id = st.text_input("Username or email", key="si_user")
        si_pw = st.text_input("Password", type="password", key="si_pw")
        if st.button("Sign in", type="primary"):
            if not si_id or not si_pw:
                st.error("Please fill in both fields.")
            else:
                user = verify_user(conn, si_id, si_pw)
                if user:
                    st.session_state.user = user
                    st.rerun()
                else:
                    st.error("Invalid credentials.")

    # Create account
    with tabs[1]:
        st.subheader("Create account")
        ca_username = st.text_input("Username").strip().lower()
        ca_email = st.text_input("Email").strip().lower()
        ca_pw = st.text_input("Password", type="password")
        ca_pw2 = st.text_input("Confirm password", type="password")
        if st.button("Create account", type="primary"):
            if not ca_username or not ca_email or not ca_pw or not ca_pw2:
                st.error("All fields are required.")
            elif len(ca_username) < 3:
                st.error("Username must be at least 3 characters.")
            elif "@" not in ca_email or "." not in ca_email:
                st.error("Please enter a valid email.")
            elif ca_pw != ca_pw2:
                st.error("Passwords do not match.")
            elif len(ca_pw) < 8:
                st.error("Password must be at least 8 characters.")
            elif user_exists(conn, ca_username):
                st.error("This username is already taken.")
            elif email_exists(conn, ca_email):
                st.error("An account with this email already exists.")
            else:
                try:
                    create_user(conn, ca_username, ca_email, ca_pw)
                    ok, msg = push_db_to_github_via_git()
                    st.sidebar.success(msg) if ok else st.sidebar.info(msg)
                    st.success("Account created! You can now sign in.")
                except sqlite3.IntegrityError:
                    st.error("Username or email already exists.")
                except Exception as e:
                    st.error(f"Error creating account: {e}")
