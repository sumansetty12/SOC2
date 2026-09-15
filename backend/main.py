"""
SOC 2 Evidence Collector — FastAPI backend.

Provides endpoints to trigger evidence collection from AWS and GitHub,
and serves the results to the frontend dashboard.
"""

import os
import json
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse

from collectors.aws_collector import AWSEvidenceCollector
from collectors.github_collector import GitHubEvidenceCollector

app = FastAPI(title="SOC 2 Evidence Collector")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.post("/api/collect/aws")
def collect_aws(region: str = "us-east-1"):
    try:
        collector = AWSEvidenceCollector(region_name=region)
        report = collector.collect_all()
        _save_report("aws", report)
        return report
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AWS collection failed: {str(e)}")


@app.post("/api/collect/github")
def collect_github(org: str, token: str):
    try:
        collector = GitHubEvidenceCollector(token=token, org=org)
        report = collector.collect_all()
        _save_report("github", report)
        return report
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"GitHub collection failed: {str(e)}")


@app.get("/api/reports/latest")
def get_latest_reports():
    """Return the most recent AWS and GitHub reports, if they exist."""
    result = {}
    for source in ["aws", "github"]:
        path = os.path.join(REPORTS_DIR, f"{source}_latest.json")
        if os.path.exists(path):
            with open(path) as f:
                result[source] = json.load(f)
    return result


def _save_report(source: str, report: dict):
    path = os.path.join(REPORTS_DIR, f"{source}_latest.json")
    with open(path, "w") as f:
        json.dump(report, f, indent=2)

    # Also save a timestamped copy for history
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    history_path = os.path.join(REPORTS_DIR, f"{source}_{timestamp}.json")
    with open(history_path, "w") as f:
        json.dump(report, f, indent=2)


# Serve the frontend dashboard
frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.exists(frontend_path):
    app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")
