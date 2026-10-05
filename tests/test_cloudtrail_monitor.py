"""
Tests for collectors/cloudtrail_monitor.py — specifically the permission-
error-surfacing behavior (the bug we found and fixed: an AccessDenied
error must never be silently reported as "0 events found").
"""
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError
from collectors.cloudtrail_monitor import CloudTrailMonitor, RELEVANT_EVENT_NAMES


def test_all_lookups_denied_reports_error_status():
    mock_client = MagicMock()
    mock_client.lookup_events.side_effect = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "denied"}}, "LookupEvents"
    )

    with patch("boto3.client", return_value=mock_client):
        result = CloudTrailMonitor().poll_recent_events(lookback_minutes=15)

    assert result["status"] == "ERROR"
    assert result["events_found"] == 0
    assert len(result["errors"]) == len(RELEVANT_EVENT_NAMES)


def test_successful_poll_with_no_activity_reports_ok_status():
    mock_client = MagicMock()
    mock_client.lookup_events.return_value = {"Events": []}

    with patch("boto3.client", return_value=mock_client):
        result = CloudTrailMonitor().poll_recent_events(lookback_minutes=15)

    assert result["status"] == "OK"
    assert result["events_found"] == 0
    assert result["errors"] == []


def test_successful_poll_with_real_event_detected():
    import datetime

    mock_client = MagicMock()

    def fake_lookup(LookupAttributes, **kwargs):
        event_name = LookupAttributes[0]["AttributeValue"]
        if event_name == "DeleteUser":
            return {"Events": [{
                "EventName": "DeleteUser",
                "EventTime": datetime.datetime.now(datetime.timezone.utc),
                "Username": "test-admin",
                "Resources": [{"ResourceName": "april-01"}],
            }]}
        return {"Events": []}

    mock_client.lookup_events.side_effect = fake_lookup

    with patch("boto3.client", return_value=mock_client):
        result = CloudTrailMonitor().poll_recent_events(lookback_minutes=15)

    assert result["status"] == "OK"
    assert result["events_found"] == 1
    assert result["events"][0]["event_name"] == "DeleteUser"
