
import streamlit as st
import sqlite3, hashlib, base64, requests, os
from datetime import datetime
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
DB_PATH = APP_DIR / "comptes.db"

# ---- GitHub config (préconfiguré pour votre repo) ----
GH_REPO   = "Lucas2882-byte/login_ip"
GH_BRANCH = "main"
GH_PATH   = "comptes.db"
GH_API    = f"https://api.github.com/repos/{GH_REPO}/contents/{GH_PATH}"

# Token via secrets (sécurité)
GH_TOKEN  = st.secrets.get("GH_TOKEN", "")

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

def file_digest(path: Path) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except FileNotFoundError:
        return ""

def upload_db_to_github():
    if not GH_TOKEN:
        return False, "GH_TOKEN manquant dans les secrets"
    headers = {
        "Authorization": f"Bearer {GH_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
    }
    # 1) Récupérer SHA (si le fichier existe déjà)
    sha = None
    get_resp = requests.get(GH_API, headers=headers)
    if get_resp.status_code == 200:
        try:
            sha = get_resp.json().get("sha")
        except Exception:
            sha = None
    elif get_resp.status_code not in (404,):
        return False, f"GET:{get_resp.status_code} {get_resp.text[:200]}"
    # 2) Lire la DB
    try:
        with open(DB_PATH, "rb") as f:
            content_b64 = base64.b64encode(f.read()).decode()
    except FileNotFoundError:
        return False, "comptes.db introuvable"
    # 3) Créer/MàJ
    data = {
        "message": f"update {GH_PATH} ({datetime.utcnow().isoformat()}Z)",
        "content": content_b64,
        "branch": GH_BRANCH,
    }
    if sha:
        data["sha"] = sha
    put_resp = requests.put(GH_API, headers=headers, json=data)
    if put_resp.status_code in (200, 201):
        return True, "Poussé"
    return False, f"PUT:{put_resp.status_code} {put_resp.text[:200]}"

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
        st.session_state["_db_dirty"] = True  # marque la DB comme modifiée
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

# ----------------------------------
# App
# ----------------------------------
st.set_page_config(page_title="Login + AutoPush GitHub", layout="centered")
init_db()

# État
if "connecte" not in st.session_state:
    st.session_state.connecte = False
if "utilisateur" not in st.session_state:
    st.session_state.utilisateur = None
if "role" not in st.session_state:
    st.session_state.role = None
if "_last_digest" not in st.session_state:
    st.session_state._last_digest = file_digest(DB_PATH)
if "_db_dirty" not in st.session_state:
    st.session_state._db_dirty = False

st.title("🔐 Auth + AutoPush GitHub (SQLite)")

# --- Auto push si la DB a changé depuis le dernier digest
current_digest = file_digest(DB_PATH)
if GH_TOKEN and current_digest and current_digest != st.session_state._last_digest:
    ok, msg = upload_db_to_github()
    st.session_state._last_digest = current_digest
    # Indication discrète (évite le spam d'UI)
    st.toast(f"Sync GitHub: {'✅' if ok else '⚠️'} {msg}")

with st.expander("🧰 Debug & Config GitHub", expanded=False):
    st.write({
        "DB_PATH": DB_PATH.as_posix(),
        "GH_REPO": GH_REPO,
        "GH_BRANCH": GH_BRANCH,
        "GH_PATH": GH_PATH,
        "GH_TOKEN_present": bool(GH_TOKEN),
        "last_digest": st.session_state._last_digest,
        "current_digest": current_digest,
    })
    if st.button("🔄 Forcer push maintenant"):
        ok, msg = upload_db_to_github()
        st.write("Résultat push:", ok, msg)
        st.session_state._last_digest = file_digest(DB_PATH)

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
                # Rerun pour déclencher le check digest -> autopush
                st.rerun()

else:
    st.success(f"Connecté en tant que **{st.session_state.utilisateur}** (rôle : **{st.session_state.role}**) ✅")
    st.write("👉 Place ici ton application protégée.")
    if st.button("Se déconnecter"):
        st.session_state.connecte = False
        st.session_state.utilisateur = None
        st.session_state.role = None
        st.rerun()
