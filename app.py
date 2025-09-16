
import streamlit as st
import sqlite3, hashlib
from datetime import datetime
from pathlib import Path

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
        conn.execute("""
            CREATE TABLE IF NOT EXISTS connections (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              username TEXT,
              public_ip TEXT,
              local_ip TEXT,
              ts TEXT
            )
        """)
        conn.commit()

def hash_pwd(pwd: str) -> str:
    return hashlib.sha256(pwd.encode('utf-8')).hexdigest()

def create_account(username: str, password: str, role: str = "user"):
    if not username or not password:
        return False, "Identifiant et mot de passe requis."
    if len(password) < 6:
        return False, "Mot de passe trop court (>=6)."
    try:
        with get_conn() as conn:
            conn.execute("INSERT INTO comptes (nom_utilisateur, mot_de_passe_hash, role, created_at) VALUES (?, ?, ?, ?)", (username.strip(), hash_pwd(password), role, datetime.utcnow().isoformat()))
            conn.commit()
        return True, "Compte créé ✅"
    except sqlite3.IntegrityError:
        return False, "Nom d'utilisateur déjà utilisé."

def verify_user(username: str, password: str):
    with get_conn() as conn:
        cur = conn.execute("SELECT mot_de_passe_hash, role FROM comptes WHERE nom_utilisateur = ?", (username.strip(),))
        row = cur.fetchone()
    if not row:
        return False, None
    stored_hash, role = row
    ok = (hash_pwd(password) == stored_hash)
    return ok, (role if ok else None)

# UI
st.set_page_config(page_title="IP Login", layout="centered")
init_db()

if "connected" not in st.session_state:
    st.session_state.connected = False
if "user" not in st.session_state:
    st.session_state.user = None
if "role" not in st.session_state:
    st.session_state.role = None

st.title("🔐 Connexion & affichage IP")

if not st.session_state.connected:
    login_tab, reg_tab = st.tabs(["Se connecter", "Créer un compte"])
    with login_tab:
        user = st.text_input("Nom d'utilisateur", key="login_user")
        pwd = st.text_input("Mot de passe", type="password", key="login_pwd")
        if st.button("Se connecter"):
            ok, role = verify_user(user, pwd)
            if ok:
                st.session_state.connected = True
                st.session_state.user = user.strip()
                st.session_state.role = role or "user"
                st.success(f"Connecté en tant que {st.session_state.user} (rôle: {st.session_state.role})")
                st.experimental_rerun()
            else:
                st.error("Identifiants incorrects")
    with reg_tab:
        new_user = st.text_input("Nom d'utilisateur", key="reg_user")
        new_pwd = st.text_input("Mot de passe", type="password", key="reg_pwd")
        new_pwd2 = st.text_input("Confirmer mot de passe", type="password", key="reg_pwd2")
        role = st.selectbox("Rôle", ["user", "admin"], index=0)
        if st.button("Créer le compte"):
            if new_pwd != new_pwd2:
                st.error("Les mots de passe ne correspondent pas")
            else:
                ok, msg = create_account(new_user, new_pwd, role)
                (st.success if ok else st.error)(msg)
else:
    st.success(f"Connecté : **{st.session_state.user}** (rôle: **{st.session_state.role}**)")
    st.markdown("### Informations IP (récupérées côté client)")
    st.markdown("L'IP publique est celle visible par internet (box/VPN). L'IP locale peut ne pas être disponible selon le navigateur.")

    # Inject JS that fetches public IP and attempts local IP via WebRTC. It displays them client-side.
    import streamlit.components.v1 as components
    username = st.session_state.user.replace('"', '\"')
    html = f"""
    <div id="ip-box" style="background:#0b1220;color:white;padding:12px;border-radius:8px;max-width:820px;">
      <div id="status">Récupération des IP...</div>
      <pre id="out" style="white-space:pre-wrap;margin-top:8px;"></pre>
    </div>
    <script>
    function dump(s){ document.getElementById('out').innerText = s + "\n" + document.getElementById('out').innerText; }
    function status(s){ document.getElementById('status').innerText = s; dump('STATUS: ' + s); }

    async function getPublicIP(){
      const services = ['https://api.ipify.org?format=json','https://ifconfig.co/json','https://ip.seeip.org/jsonip?'];
      for(const url of services){
        try{
          status('Fetch public IP from ' + url);
          const r = await fetch(url, {cache:'no-store'});
          if(!r.ok) throw new Error('http:'+r.status);
          const j = await r.json();
          const ip = j.ip || j.query || j.address || null;
          if(ip) return {ip, service:url};
        }catch(e){ dump('error fetching ' + url + ' -> ' + e.toString()); continue; }
      }
      return {ip:null};
    }

    async function getLocalIP(){
      try{
        status('Tentative WebRTC...');
        const pc = new RTCPeerConnection({iceServers:[]});
        pc.createDataChannel('');
        const offer = await pc.createOffer();
        await pc.setLocalDescription(offer);
        const s = offer.sdp.split('\n');
        for(const line of s){
          if(line.indexOf('a=candidate:') === 0){
            const parts = line.split(' ');
            const ip = parts[4];
            if(ip) { pc.close(); return ip; }
          }
        }
        pc.close();
      }catch(e){ dump('webrtc error: ' + e.toString()); }
      return null;
    }

    (async ()=>{
      status('Début');
      const pub = await getPublicIP();
      const local = await getLocalIP();
      status('Terminé');
      const out = `Utilisateur: {username}\nPublic IP: ${pub.ip || 'non trouvée'} (via ${pub.service || 'n/a'})\nLocal IP: ${local || 'non trouvée'}\n`;
      document.getElementById('out').innerText = out + document.getElementById('out').innerText;
    })();
    </script>
    """
    components.html(html, height=220)

    if st.button("Se déconnecter"):
        st.session_state.connected = False
        st.session_state.user = None
        st.session_state.role = None
        st.experimental_rerun()
