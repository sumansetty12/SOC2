"""
CloudTrail event poller for Continuous Monitoring.

Design note: true event-driven monitoring (AWS EventBridge pushing to a
webhook) requires a publicly reachable URL, which a self-hosted tool
running on localhost doesn't have. Instead, this polls CloudTrail's
lookup_events API on a schedule, but only for a small set of
SOC2-relevant event names — so it's a targeted query, not a blind
full re-scan of every AWS resource on every poll. A re-check of the
full collector is only triggered when something relevant actually
happened.

Read-only: lookup_events only reads CloudTrail's log, never modifies
anything.
"""
import boto3
from datetime import datetime, timedelta, timezone
from botocore.exceptions import ClientError

# Event names that map to the SOC2 controls this tool checks.
# Keeping this list narrow is what makes polling efficient — we're not
# scanning all CloudTrail activity, just the handful of event types that
# could change a CC6.1 / CC6.6 / CC7.2 finding.
RELEVANT_EVENT_NAMES = [
    "CreateUser", "DeleteUser",
    "CreateAccessKey", "DeleteAccessKey",
    "EnableMFADevice", "DeactivateMFADevice",
    "PutBucketPolicy", "DeleteBucketPolicy",
    "PutPublicAccessBlock", "DeletePublicAccessBlock",
    "StopLogging", "StartLogging", "UpdateTrail", "DeleteTrail",
]


class CloudTrailMonitor:
    def __init__(self, region: str = "us-east-1"):
        self.region = region

    def poll_recent_events(self, lookback_minutes: int = 15) -> dict:
        """
        Check for SOC2-relevant CloudTrail events in the last `lookback_minutes`.
        Returns the list of matching events found (empty if nothing relevant
        happened, which is the common case on most polls).
        """
        try:
            client = boto3.client("cloudtrail", region_name=self.region)
            start_time = datetime.now(timezone.utc) - timedelta(minutes=lookback_minutes)

            found_events = []
            errors = []
            for event_name in RELEVANT_EVENT_NAMES:
                try:
                    resp = client.lookup_events(
                        LookupAttributes=[
                            {"AttributeKey": "EventName", "AttributeValue": event_name}
                        ],
                        StartTime=start_time,
                        EndTime=datetime.now(timezone.utc),
                        MaxResults=5,
                    )
                    for e in resp.get("Events", []):
                        found_events.append({
                            "event_name": e.get("EventName"),
                            "event_time": e.get("EventTime").isoformat() if e.get("EventTime") else None,
                            "username": e.get("Username"),
                            "resources": [r.get("ResourceName") for r in e.get("Resources", [])],
                        })
                except ClientError as e:
                    # IMPORTANT: a lookup failure (e.g. AccessDenied because
                    # cloudtrail:LookupEvents isn't granted) must NOT be
                    # silently treated as "no activity" — that produces a
                    # false-clean result indistinguishable from an honest
                    # zero. Record it explicitly instead.
                    code = e.response.get("Error", {}).get("Code", "Unknown")
                    errors.append({"event_name": event_name, "error_code": code})

            # If every single lookup failed (e.g. missing IAM permission),
            # treat this poll as erroed, not as a clean "0 events found".
            all_failed = len(errors) == len(RELEVANT_EVENT_NAMES)

            return {
                "polled_at": datetime.now(timezone.utc).isoformat(),
                "lookback_minutes": lookback_minutes,
                "events_found": len(found_events),
                "events": found_events,
                "errors": errors,
                "status": "ERROR" if all_failed else ("PARTIAL" if errors else "OK"),
            }
        except Exception as e:
            return {"error": str(e), "events_found": 0, "events": []}
