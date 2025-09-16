
import streamlit as st
import sqlite3
import bcrypt
from datetime import datetime

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

# ---------- UI ----------
st.set_page_config(page_title="Streamlit Auth Demo", page_icon="🔐", layout="centered")

# Simple theming/help card
with st.sidebar:
    st.title("🔐 Auth Demo")
    st.write("Login / register example with SQLite + bcrypt.")
    st.caption("This is a demo. For production, use a managed database and secrets.")

# Initialize DB connection
conn = get_conn()

# Session bootstrap
if "user" not in st.session_state:
    st.session_state.user = None

def logout():
    st.session_state.user = None
    st.success("Logged out.")

# If logged in, show a simple app page
if st.session_state.user:
    user = st.session_state.user
    st.success(f"Welcome, **{user['username']}**!")
    st.write("You're logged in. Here's your profile:")
    with st.container(border=True):
        st.write(f"**Username:** {user['username']}")
        st.write(f"**Email:** {user['email']}")
        st.write(f"**Created:** {user['created_at']}")
    if st.button("Log out", type="primary"):
        logout()
    st.divider()
    st.write("✅ Protected content goes here.")
else:
    tabs = st.tabs(["Sign in", "Create account"])

    # Sign in tab
    with tabs[0]:
        st.subheader("Sign in")
        si_id = st.text_input("Username or email", key="si_user")
        si_pw = st.text_input("Password", type="password", key="si_pw")
        col1, col2 = st.columns([1,1])
        with col1:
            submit = st.button("Sign in", type="primary")
        with col2:
            st.caption("")
        if submit:
            if not si_id or not si_pw:
                st.error("Please fill in both fields.")
            else:
                user = verify_user(conn, si_id, si_pw)
                if user:
                    st.session_state.user = user
                    st.rerun()
                else:
                    st.error("Invalid credentials.")

    # Create account tab
    with tabs[1]:
        st.subheader("Create account")
        ca_username = st.text_input("Username").strip().lower()
        ca_email = st.text_input("Email").strip().lower()
        ca_pw = st.text_input("Password", type="password")
        ca_pw2 = st.text_input("Confirm password", type="password")
        if st.button("Create account", type="primary"):
            # Basic validation
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
                    st.success("Account created! You can now sign in.")
                except sqlite3.IntegrityError:
                    st.error("Username or email already exists.")
                except Exception as e:
                    st.error(f"Error creating account: {e}")
