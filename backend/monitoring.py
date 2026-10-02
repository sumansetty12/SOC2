"""
Continuous Monitoring scheduler.

Runs a background poll on an interval. On each poll:
  - AWS: checks CloudTrail for SOC2-relevant events in the lookback window.
    If any are found, triggers a full AWS collection and records it as a
    "triggered" check in history. If nothing relevant happened (the common
    case), no full re-check runs — this is the efficiency gain over blind
    polling.
  - GitHub: checks each repo's current branch-protection status and diffs
    it against the last known state stored in SQLite. A state change
    triggers a recorded check; no change means nothing is written beyond
    the state table.

In-memory only: AWS credentials are picked up from the normal boto3 chain
(same as manual collection). The GitHub org/token are kept in memory only
for the lifetime of the running process — never written to disk — since
monitoring must be explicitly started with them each time the server runs.
"""
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime, timezone

import db
from collectors.cloudtrail_monitor import CloudTrailMonitor
from collectors.aws_collector import AWSEvidenceCollector
from collectors.github_collector import GitHubEvidenceCollector

_scheduler = BackgroundScheduler()
_state = {
    "running": False,
    "region": "us-east-1",
    "github_org": None,
    "github_token": None,
    "lookback_minutes": 15,
    "poll_interval_minutes": 5,
    "last_poll_at": None,
}


def _poll_aws():
    monitor = CloudTrailMonitor(region=_state["region"])
    result = monitor.poll_recent_events(lookback_minutes=_state["lookback_minutes"])
    events_found = result.get("events_found", 0)
    triggered = events_found > 0

    db.record_poll_run("aws", events_found, triggered)
    _state["last_poll_at"] = datetime.now(timezone.utc).isoformat()

    if triggered:
        collector = AWSEvidenceCollector(region_name=_state["region"])
        report = collector.collect_all()
        event_names = ", ".join(sorted({e["event_name"] for e in result["events"]}))
        db.record_check(
            source="aws",
            trigger_reason=f"CloudTrail activity detected: {event_names}",
            result=report,
            summary=f"{events_found} relevant event(s) detected — re-ran AWS checks",
        )


def _poll_github():
    if not _state["github_org"] or not _state["github_token"]:
        return

    collector = GitHubEvidenceCollector(token=_state["github_token"], org=_state["github_org"])
    report = collector.collect_all()
    events_found = 0

    change_mgmt = report.get("change_management", {}).get("details", [])
    for repo_result in change_mgmt:
        repo_name = repo_result.get("repo")
        if not repo_name:
            continue
        current_protected = bool(repo_result.get("branch_protected"))
        prior = db.get_github_repo_state(repo_name)

        if prior is None:
            # First time seeing this repo — record baseline, not a change.
            db.set_github_repo_state(repo_name, current_protected)
            continue

        if bool(prior["last_branch_protected"]) != current_protected:
            events_found += 1
            db.record_check(
                source="github",
                trigger_reason=f"Branch protection changed for {repo_name}",
                result=repo_result,
                summary=f"{repo_name}: branch_protected changed to {current_protected}",
            )
            db.set_github_repo_state(repo_name, current_protected)

    db.record_poll_run("github", events_found, events_found > 0)
    _state["last_poll_at"] = datetime.now(timezone.utc).isoformat()


def start(region: str, github_org: str = None, github_token: str = None,
          poll_interval_minutes: int = 5, lookback_minutes: int = 15):
    db.init_db()
    _state.update({
        "region": region,
        "github_org": github_org,
        "github_token": github_token,
        "poll_interval_minutes": poll_interval_minutes,
        "lookback_minutes": lookback_minutes,
        "running": True,
    })

    _scheduler.remove_all_jobs()
    _scheduler.add_job(_poll_aws, "interval", minutes=poll_interval_minutes, id="poll_aws")
    if github_org and github_token:
        _scheduler.add_job(_poll_github, "interval", minutes=poll_interval_minutes, id="poll_github")

    if not _scheduler.running:
        _scheduler.start()


def stop():
    _scheduler.remove_all_jobs()
    _state["running"] = False
    # Keep github_token out of memory once stopped.
    _state["github_token"] = None


def get_status() -> dict:
    return {
        "running": _state["running"],
        "region": _state["region"],
        "github_monitoring_active": bool(_state["github_org"] and _state["running"]),
        "poll_interval_minutes": _state["poll_interval_minutes"],
        "lookback_minutes": _state["lookback_minutes"],
        "last_poll_at": _state["last_poll_at"],
    }
