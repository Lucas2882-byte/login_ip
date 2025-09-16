
Full project bundle
===================

Files included:
- app.py                 : minimal Streamlit auth app (debug panel)
- app_github_preconfigured.py : Streamlit app that pushes DB to GitHub (requires GH_TOKEN in secrets)
- app_github_auto.py     : Streamlit app that auto-pushes DB when it changes
- reporter.py            : Flask endpoint to receive IP reports and store in connections table
- comptes.db             : SQLite database (seeded with admin/demo accounts)
- client_report_snippet.html : example JS snippet to inject in Streamlit to report client IPs to reporter
- requirements.txt       : pip requirements

How to run Streamlit app:
1. unzip the bundle
2. pip install -r requirements.txt
3. streamlit run app.py  (or any other app_*.py)

How to run reporter (Flask):
1. export GH_TOKEN=... (optional, only if you want reporter to push DB to GitHub)
2. python reporter.py
3. reporter runs on port 5001 by default (POST /report)

Security notes:
- Put GH_TOKEN only in Streamlit secrets or environment variables (never commit it)
- Inform users in privacy policy if you log IP addresses
