# Streamlit Login Demo 🔐

Minimal Streamlit app showing **sign up** and **login** with **SQLite + bcrypt**.

## Features
- Create account: username, email, strong password (≥ 8 chars)
- Secure password hashing with `bcrypt`
- Local SQLite database (`users.db`)
- Session-based login state with `st.session_state`
- Simple protected area once logged in

## Run locally

```bash
pip install -r requirements.txt
streamlit run app.py
```

The app will create `users.db` on first run.

## Deploy on Streamlit Community Cloud

1. Push this folder to a GitHub repo.
2. On https://share.streamlit.io/ create a new app, pick your repo, select `app.py` as the entry point.
3. Add nothing to secrets for this demo (uses local SQLite). For production, use a real DB and store credentials in **Secrets**.
4. Click **Deploy**.

## Notes
- This demo stores data in a local file and is for testing only.
- For production: use a managed DB (e.g., Postgres), add email verification, rate limiting, and secrets management.
