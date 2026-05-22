# OSINT Dashboard

A self-hosted threat intelligence dashboard that aggregates indicators of compromise (IPs, domains, URLs, file hashes) from public OSINT feeds, scores them, and turns them into ready-to-deploy detection rules. Built with a Flask + SQLite backend and a React frontend.


# My Website:
https://osint-app-1-am7p.onrender.com/
Note that some features may not work due to cost issues as discussed.

## Features

- **Automated collection** from four threat feeds every 12 hours: URLhaus, AbuseIPDB, AlienVault OTX, VirusTotal.
- **Multi-factor threat scoring** combining feed confidence, tag severity, cross-source corroboration, and recency.
- **Live indicator lookup** against AbuseIPDB, OTX, Shodan, crt.sh, WHOIS, SecurityTrails, and IntelligenceX - plus the local database.
- **Email breach checks** via Have I Been Pwned, XposedOrNot (free, no key), and EmailRep.
- **AI-generated threat briefings** with automatic Gemini -> Groq fallback.
- **Snort and YARA rule generation** from templates (instant) or via AI, including bulk protection scripts (iptables, DNS sinkhole, CSV blocklist) for any time window.
- **Encrypted user API key storage** - keys are saved server-side with Fernet, scoped to the user's session, never to disk in plaintext.
- **Filterable, sortable, paginated threat table** with source and score filters.

## Stack

- **Backend:** Python 3, Flask, SQLite, `requests`, `python-whois`, `cryptography`, `google-genai`, `groq`
- **Frontend:** React 19, axios, recharts
- **Storage:** SQLite (`backend/osint.db`) for indicators, separate encrypted SQLite (`backend/user_keys.db`) for user-provided API keys

## Project layout

```
osint-dashboard/
├ backend/
│   ├ app.py          # Flask API + routes
│   ├ collector.py    # Feed collectors (URLhaus, AbuseIPDB, OTX, VirusTotal)
│   ├ processor.py    # Threat scoring algorithm
│   ├ database.py     # SQLite schema + connection
│   └ osint.db        # Local indicator database
├ frontend/           # React app (Create React App)
└ venv/               # Python virtualenv
```

## Setup

### 1. Backend

```powershell
python -m venv venv
venv\Scripts\activate
pip install flask flask-cors requests python-dotenv cryptography google-genai groq python-whois
```

Create `backend/.env` with whichever feed keys you have. All are optional - the app falls back gracefully when a key is missing:

```
URLHAUS_API_KEY=...
ABUSEIPDB_API_KEY=...
OTX_API_KEY=...
VIRUSTOTAL_API_KEY=...
GEMINI_API_KEY=...
GROQ_API_KEY=...
HIBP_API_KEY=...
SHODAN_API_KEY=...
SECURITYTRAILS_API_KEY=...
INTELX_API_KEY=...
FLASK_SECRET_KEY=...
```

Initialise the database (only required the first time):

```powershell
cd backend
python database.py
```

### 2. Frontend

```powershell
cd frontend
npm install
```

## Running

The backend uses a relative path for `osint.db`, so it must be started **from the `backend/` directory** to find the existing database:

```powershell
cd backend
..\venv\Scripts\python.exe app.py
```

In a second terminal:

```powershell
cd frontend
npm start
```

- Backend: http://127.0.0.1:5000
- Frontend: http://localhost:3000

On startup the backend immediately collects from all four feeds, then repeats every 12 hours.

## API

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/health` | Health check |
| GET | `/api/threats` | List indicators (filter by `type`, `source`, `active`, `limit`) |
| GET | `/api/stats` | Totals, breakdown by source / type / score |
| GET | `/api/lookup?value=...` | Local DB + live lookup across all configured providers |
| GET | `/api/breach-lookup?email=...` | HIBP + XposedOrNot + EmailRep |
| GET | `/api/alerts` | New high-score indicators (defaults to last 24h) |
| GET | `/api/resolve?domain=...` | DNS resolve a domain to IP |
| POST | `/api/ai-summary` | AI-generated threat landscape briefing |
| POST | `/api/template-rules` | Snort + YARA + firewall rec for a single indicator |
| POST | `/api/generate-rules` | AI-generated detection rules for a single indicator |
| POST | `/api/bulk-protect` | Combined Snort/YARA/iptables/CSV script for a time window |
| GET/POST/DELETE | `/api/keys` | Manage user-provided, encrypted API keys |
| POST | `/api/validate-key` | Test a key against the live provider before saving |

## Threat scoring

Scores are 0-100 and combine:

- AbuseIPDB confidence (×0.35)
- VirusTotal malicious-detection ratio (×0.40)
- Severe tags (malware, c2, ransomware, trojan, rat, exploit, apt) -> +25; moderate (phishing, botnet, miner, spam) -> +15
- Tag volume (+3 per tag, capped at +15)
- Cross-source corroboration (3+ sources +15, 2 sources +10)
- Recency (≤1 day +15, ≤7 days +10, ≤30 days +5)

Rescore everything from scratch:

```powershell
cd backend
python processor.py
```
