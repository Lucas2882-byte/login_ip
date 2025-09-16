
import streamlit as st
import sqlite3
import hashlib
from datetime import datetime
from pathlib import Path

# --- Place always the DB next to this file ---
APP_DIR = Path(__file__).resolve().parent
DB_PATH = APP_DIR / "comptes.db"

def get_conn():
    return sqlite3.connect(DB_PATH.as_posix(), check_same_thread=False)

def init_db():
    with get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS comptes (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              nom_utilisateur TEXT UNIQUE NOT NULL,
              mot_de_passe_hash TEXT NOT NULL,
              role TEXT DEFAULT 'user',
              created_at TEXT NOT NULL
            )
        """)
        conn.commit()

def hasher_mot_de_passe(mdp: str) -> str:
    return hashlib.sha256(mdp.encode("utf-8")).hexdigest()

def creer_compte(username: str, password: str, role: str = "user"):
    if not username or not password:
        return False, "Veuillez renseigner un identifiant et un mot de passe."
    if len(password) < 6:
        return False, "Mot de passe trop court (6 caractères min.)."
    try:
        with get_conn() as conn:
            conn.execute(
                "INSERT INTO comptes (nom_utilisateur, mot_de_passe_hash, role, created_at) VALUES (?, ?, ?, ?)",
                (username.strip(), hasher_mot_de_passe(password), role, datetime.utcnow().isoformat()),
            )
            conn.commit()
        return True, "Compte créé ✅"
    except sqlite3.IntegrityError:
        return False, "Ce nom d'utilisateur existe déjà."

def verifier_utilisateur(username: str, password: str):
    with get_conn() as conn:
        cur = conn.execute(
            "SELECT mot_de_passe_hash, role FROM comptes WHERE nom_utilisateur = ?",
            (username.strip(),),
        )
        row = cur.fetchone()
    if not row:
        return False, None
    hash_stocke, role = row
    ok = (hasher_mot_de_passe(password) == hash_stocke)
    return ok, (role if ok else None)

def get_all_users():
    with get_conn() as conn:
        cur = conn.execute("SELECT id, nom_utilisateur, role, created_at FROM comptes ORDER BY id")
        return cur.fetchall()

st.set_page_config(page_title="Login simple", layout="centered")
init_db()

if "connecte" not in st.session_state:
    st.session_state.connecte = False
if "utilisateur" not in st.session_state:
    st.session_state.utilisateur = None
if "role" not in st.session_state:
    st.session_state.role = None

st.title("🔐 Auth minimale (Streamlit + SQLite)")

# --- Debug panel to verify DB path & users ---
with st.expander("🧰 Debug (chemin DB & utilisateurs)"):
    st.code(f"DB_PATH = {DB_PATH.as_posix()}")
    users = get_all_users()
    if users:
        st.write("Utilisateurs existants :")
        st.table(users)
    else:
        st.info("Aucun utilisateur pour l'instant.")

if not st.session_state.connecte:
    tab_login, tab_register = st.tabs(["Se connecter", "Créer un compte"])

    with tab_login:
        nom = st.text_input("Nom d'utilisateur", key="login_user")
        mdp = st.text_input("Mot de passe", type="password", key="login_pwd")
        if st.button("Se connecter"):
            ok, role = verifier_utilisateur(nom, mdp)
            if ok:
                st.session_state.connecte = True
                st.session_state.utilisateur = nom.strip()
                st.session_state.role = role or "user"
                st.success(f"Bienvenue {st.session_state.utilisateur} 👋 (rôle : {st.session_state.role})")
                st.rerun()
            else:
                st.error("Identifiants incorrects ❌")

    with tab_register:
        new_user = st.text_input("Nom d'utilisateur", key="reg_user")
        new_pwd = st.text_input("Mot de passe", type="password", key="reg_pwd")
        new_pwd2 = st.text_input("Confirmer le mot de passe", type="password", key="reg_pwd2")
        role = st.selectbox("Rôle (optionnel)", ["user", "admin"], index=0)
        if st.button("Créer le compte"):
            if new_pwd != new_pwd2:
                st.error("Les mots de passe ne correspondent pas.")
            else:
                ok, msg = creer_compte(new_user, new_pwd, role)
                (st.success if ok else st.error)(msg)
                st.rerun()

else:
    st.success(f"Connecté en tant que **{st.session_state.utilisateur}** (rôle : **{st.session_state.role}**) ✅")
    st.write("👉 Place ici ton application protégée.")
    if st.button("Se déconnecter"):
        st.session_state.connecte = False
        st.session_state.utilisateur = None
        st.session_state.role = None
        st.rerun()
