SCAMCHECK KENYA V4

This version adds optional threat-intelligence lookups.

1. Install:
   pip install -r requirements.txt

2. Set server environment variables:
   VIRUSTOTAL_API_KEY=...
   URLSCAN_API_KEY=...
   ENABLE_EXTERNAL_URL_SCANS=true

3. Run:
   python app.py

4. Open:
   http://127.0.0.1:5000

Privacy design:
- The app does NOT submit URLs for new VirusTotal scans.
- It only requests an existing VirusTotal URL report.
- urlscan is used only for domain search when enabled.
- Do not send private/confidential/PII content to external providers.

Production next:
- secure secret storage
- rate limiting
- abuse prevention
- database
- authentication
- verified business profiles
- Android/iOS client
- billing
- additional trusted feeds
- independent security review
