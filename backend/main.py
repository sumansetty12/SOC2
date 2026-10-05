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

from pydantic import BaseModel
from collectors.aws_collector import AWSEvidenceCollector
from collectors.github_collector import GitHubEvidenceCollector
import db as history_db
import monitoring
import remediation
import pdf_export
from fastapi.responses import Response

app = FastAPI(title="SOC 2 Evidence Collector")
history_db.init_db()

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


class MonitoringStartRequest(BaseModel):
    region: str = "us-east-1"
    github_org: str | None = None
    github_token: str | None = None
    poll_interval_minutes: int = 5
    lookback_minutes: int = 15


@app.post("/api/monitoring/start")
def start_monitoring(req: MonitoringStartRequest):
    try:
        monitoring.start(
            region=req.region,
            github_org=req.github_org,
            github_token=req.github_token,
            poll_interval_minutes=req.poll_interval_minutes,
            lookback_minutes=req.lookback_minutes,
        )
        return monitoring.get_status()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start monitoring: {str(e)}")


@app.post("/api/monitoring/stop")
def stop_monitoring():
    monitoring.stop()
    return monitoring.get_status()


@app.get("/api/monitoring/status")
def monitoring_status():
    return monitoring.get_status()


@app.get("/api/monitoring/history")
def monitoring_history(limit: int = 20):
    return {
        "poll_runs": history_db.get_recent_polls(limit),
        "check_history": history_db.get_check_history(limit),
    }


@app.get("/api/remediation/free")
def remediation_free(source: str, category: str):
    return {"guidance": remediation.get_free_guidance(source, category)}


class AIRemediationRequest(BaseModel):
    source: str
    category: str
    finding_detail: dict
    api_key: str
    provider: str = "anthropic"


@app.post("/api/remediation/ai")
def remediation_ai(req: AIRemediationRequest):
    result = remediation.get_ai_guidance(req.source, req.category, req.finding_detail, req.api_key, req.provider)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


class ReportRequest(BaseModel):
    api_key: str
    provider: str = "anthropic"


@app.post("/api/report/generate")
def generate_report(req: ReportRequest):
    reports = get_latest_reports()
    aws_report = reports.get("aws", {})
    github_report = reports.get("github", {})
    if not aws_report and not github_report:
        raise HTTPException(status_code=400, detail="No AWS or GitHub evidence collected yet — run a collection first.")

    result = remediation.generate_security_report(aws_report, github_report, req.api_key, req.provider)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


class PDFExportRequest(BaseModel):
    report_text: str
    provider: str = "anthropic"


@app.post("/api/report/pdf")
def export_report_pdf(req: PDFExportRequest):
    try:
        pdf_bytes = pdf_export.generate_report_pdf(req.report_text, generated_with=req.provider)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {str(e)}")

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=soc2-security-report.pdf"},
    )


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
