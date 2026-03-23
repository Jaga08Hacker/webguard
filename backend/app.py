from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
import uuid, json, os, time
from datetime import datetime

from modules.subdomain import find_subdomains
from modules.google_dork import run_google_dorking
from modules.shodan_scan import run_shodan_scan
from modules.cve_lookup import map_cve
from modules.cloud_bucket import check_s3_buckets
from modules.hidden_paths import scan_hidden_paths
from modules.risk_score import calculate_risk
from modules.report_generator import generate_report
from utils.db import init_db, save_scan, get_all_scans, get_scan_by_id

app = FastAPI(title="WebGuard API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

init_db()

# In-memory scan status tracker
scan_status = {}

class ScanRequest(BaseModel):
    domain: str
    shodan_key: str = ""
    google_key: str = ""
    google_cx: str = ""
    nvd_key: str = ""
    enable_shodan: bool = True
    enable_google: bool = True
    enable_s3: bool = True
    enable_hidden: bool = True

@app.get("/")
def root():
    return {"message": "WebGuard API is running", "version": "1.0.0"}

@app.post("/scan")
async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())
    scan_status[scan_id] = {
        "status": "running",
        "progress": 0,
        "current_step": "Initializing...",
        "started_at": datetime.now().isoformat()
    }
    background_tasks.add_task(run_scan, scan_id, req)
    return {"scan_id": scan_id, "status": "started"}

@app.get("/scan/{scan_id}/status")
def get_scan_status(scan_id: str):
    if scan_id not in scan_status:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan_status[scan_id]

@app.get("/scan/{scan_id}/results")
def get_scan_results(scan_id: str):
    result = get_scan_by_id(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Results not found")
    return json.loads(result["data"])

@app.get("/scan/{scan_id}/report/{fmt}")
def download_report(scan_id: str, fmt: str):
    result = get_scan_by_id(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")
    data = json.loads(result["data"])
    path = generate_report(scan_id, data, fmt)
    if not path or not os.path.exists(path):
        raise HTTPException(status_code=500, detail="Report generation failed")
    return FileResponse(path, filename=os.path.basename(path))

@app.get("/history")
def get_history():
    scans = get_all_scans()
    return scans

async def run_scan(scan_id: str, req: ScanRequest):
    try:
        results = {
            "scan_id": scan_id,
            "domain": req.domain,
            "timestamp": datetime.now().isoformat(),
            "subdomains": [],
            "google_dorks": [],
            "shodan": {},
            "s3_buckets": [],
            "hidden_paths": [],
            "cves": [],
            "risk_score": 0,
            "risk_level": "Unknown"
        }

        def update(step, progress):
            scan_status[scan_id]["current_step"] = step
            scan_status[scan_id]["progress"] = progress

        update("Enumerating subdomains...", 10)
        results["subdomains"] = find_subdomains(req.domain)

        update("Running Google Dorking...", 28)
        if req.enable_google and req.google_key:
            results["google_dorks"] = run_google_dorking(req.domain, req.google_key, req.google_cx)

        update("Scanning with Shodan...", 45)
        if req.enable_shodan and req.shodan_key:
            results["shodan"] = run_shodan_scan(req.domain, req.shodan_key)

        update("Checking S3 Buckets...", 60)
        if req.enable_s3:
            results["s3_buckets"] = check_s3_buckets(req.domain)

        update("Scanning hidden paths...", 72)
        if req.enable_hidden:
            results["hidden_paths"] = scan_hidden_paths(req.domain)

        update("Mapping CVEs...", 85)
        results["cves"] = map_cve(results.get("shodan", {}), req.nvd_key)

        update("Calculating risk score...", 95)
        risk = calculate_risk(results)
        results["risk_score"] = risk["score"]
        results["risk_level"] = risk["level"]
        results["risk_breakdown"] = risk["breakdown"]

        save_scan(scan_id, req.domain, results)

        scan_status[scan_id]["status"] = "completed"
        scan_status[scan_id]["progress"] = 100
        scan_status[scan_id]["current_step"] = "Scan complete!"

    except Exception as e:
        scan_status[scan_id]["status"] = "error"
        scan_status[scan_id]["error"] = str(e)
