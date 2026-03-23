# 🛡 WebGuard — Automated Website Data Exposure Detection Tool

**M.Sc. Information Security & Digital Forensics Project**
St. Peter's Institute of Higher Education and Research

---

## 📁 Project Structure

```
webguard/
├── backend/
│   ├── app.py                  ← FastAPI main server
│   ├── modules/
│   │   ├── subdomain.py        ← Subdomain enumeration
│   │   ├── google_dork.py      ← Google dorking / OSINT
│   │   ├── shodan_scan.py      ← Shodan port & service scan
│   │   ├── cloud_bucket.py     ← S3 bucket exposure check
│   │   ├── hidden_paths.py     ← Hidden path scanner
│   │   ├── cve_lookup.py       ← CVE mapping (NVD/Shodan)
│   │   ├── risk_score.py       ← Risk scoring engine
│   │   └── report_generator.py ← JSON / CSV / PDF reports
│   └── utils/
│       └── db.py               ← SQLite scan history
├── frontend/
│   └── index.html              ← Full UI (open in browser)
├── reports/                    ← Generated reports saved here
├── requirements.txt
└── README.md
```

---

## ⚙️ Setup on Mac with VS Code

### Step 1 — Open the Project
```bash
# Open VS Code in the webguard folder
code /path/to/webguard
```

### Step 2 — Create Virtual Environment
Open the VS Code **Terminal** (`Ctrl + \``) and run:
```bash
cd backend
python3 -m venv venv
source venv/bin/activate
```

### Step 3 — Install Dependencies
```bash
pip install -r ../requirements.txt
```

### Step 4 — Run the Backend
```bash
uvicorn app:app --reload --host 0.0.0.0 --port 8000
```

Or press **F5** in VS Code (uses `.vscode/launch.json`).

You should see:
```
INFO: Uvicorn running on http://0.0.0.0:8000
```

### Step 5 — Open the Frontend
- Open `frontend/index.html` directly in your browser
- OR install the VS Code **Live Server** extension and click **Open with Live Server**

---

## 🔑 API Keys Needed

| Key | Where to Get | Required For |
|-----|-------------|-------------|
| **Shodan API Key** | https://account.shodan.io | Port scanning, services, CVEs |
| **Google Custom Search API** | https://console.developers.google.com | Google dorking |
| **Google CX (Search Engine ID)** | https://programmablesearchengine.google.com | Google dorking |
| **NVD API Key** (optional) | https://nvd.nist.gov/developers/request-an-api-key | Faster CVE lookup |

> Enter these keys in the WebGuard UI — they are NOT stored anywhere permanently.

---

## 🚀 How to Use

1. Start the backend server (Step 4 above)
2. Open `frontend/index.html` in your browser
3. Enter a domain (e.g., `example.com`)
4. Paste your API keys
5. Toggle modules on/off as needed
6. Click **⚡ START SCAN**
7. Watch real-time progress
8. Download results as **JSON**, **CSV**, or **PDF**

---

## 📊 What WebGuard Detects

| Module | What It Finds |
|--------|--------------|
| Subdomain Enum | Active subdomains via crt.sh, HackerTarget, DNS brute-force |
| Google Dorking | Exposed `.env`, `.sql`, backup, config, admin panels |
| Shodan | Open ports, running services, banners, known CVEs |
| S3 Bucket | Public/exposed Amazon S3 buckets |
| Hidden Paths | Admin panels, phpinfo, git config, debug endpoints |
| CVE Mapping | Matches detected services to NVD vulnerability database |
| Risk Score | 0–100 risk score with level: LOW / MEDIUM / HIGH / CRITICAL |

---

## ⚠️ Legal Notice

WebGuard is for **educational and authorized security testing only**.  
Only scan domains you **own** or have **written permission** to test.  
Unauthorized scanning may violate laws.

---

## 🧑‍💻 Developer
**Jagadeesan M (SP24ISP002)**  
M.Sc. Information Security & Digital Forensics  
St. Peter's Institute of Higher Education and Research, Chennai
