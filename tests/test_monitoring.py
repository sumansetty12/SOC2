"""
Tests for monitoring.py's polling logic. We mock the collectors so these
run without real AWS/GitHub credentials, but the actual diffing and
error-handling logic under test is real, not mocked.
"""
import os
import pytest
from unittest.mock import patch, MagicMock

import db
import monitoring


@pytest.fixture(autouse=True)
def fresh_db(monkeypatch, tmp_path):
    test_db_path = str(tmp_path / "test_soc2_history.db")
    monkeypatch.setattr(db, "DB_PATH", test_db_path)
    db.init_db()
    yield
    if os.path.exists(test_db_path):
        os.remove(test_db_path)


def test_github_poll_first_time_is_baseline_not_a_change():
    """A repo seen for the first time should never be reported as a change."""
    monitoring._state["github_org"] = "testorg"
    monitoring._state["github_token"] = "testtoken"

    mock_collector = MagicMock()
    mock_collector.collect_all.return_value = {
        "change_management": {"details": [{"repo": "SOC2", "branch_protected": False}]}
    }

    with patch("monitoring.GitHubEvidenceCollector", return_value=mock_collector):
        monitoring._poll_github()

    history = db.get_check_history()
    assert len(history) == 0, "first-time baseline must not be recorded as a change"


def test_github_poll_detects_real_change():
    monitoring._state["github_org"] = "testorg"
    monitoring._state["github_token"] = "testtoken"

    mock_collector = MagicMock()

    # Poll 1: establish baseline (unprotected)
    mock_collector.collect_all.return_value = {
        "change_management": {"details": [{"repo": "SOC2", "branch_protected": False}]}
    }
    with patch("monitoring.GitHubEvidenceCollector", return_value=mock_collector):
        monitoring._poll_github()
    assert len(db.get_check_history()) == 0

    # Poll 2: same state, should still not trigger
    with patch("monitoring.GitHubEvidenceCollector", return_value=mock_collector):
        monitoring._poll_github()
    assert len(db.get_check_history()) == 0

    # Poll 3: real change (protection enabled) — should trigger
    mock_collector.collect_all.return_value = {
        "change_management": {"details": [{"repo": "SOC2", "branch_protected": True}]}
    }
    with patch("monitoring.GitHubEvidenceCollector", return_value=mock_collector):
        monitoring._poll_github()
    history = db.get_check_history()
    assert len(history) == 1
    assert "SOC2" in history[0]["summary"]

    # Poll 4: stable again, should not double-count
    with patch("monitoring.GitHubEvidenceCollector", return_value=mock_collector):
        monitoring._poll_github()
    assert len(db.get_check_history()) == 1


def test_aws_poll_error_is_recorded_not_silently_treated_as_clean():
    """
    The critical regression test for the CloudTrail permission bug: an
    all-lookups-failed poll must be recorded as a visible ERROR entry,
    never as a clean '0 events found' result.
    """
    mock_monitor = MagicMock()
    mock_monitor.poll_recent_events.return_value = {
        "events_found": 0,
        "events": [],
        "errors": [{"event_name": "CreateUser", "error_code": "AccessDeniedException"}],
        "status": "ERROR",
    }

    with patch("monitoring.CloudTrailMonitor", return_value=mock_monitor):
        monitoring._poll_aws()

    history = db.get_check_history()
    assert len(history) == 1
    assert history[0]["summary"].startswith("ERROR")
    assert "AccessDeniedException" in history[0]["summary"]


def test_aws_poll_clean_zero_events_does_not_create_false_check():
    mock_monitor = MagicMock()
    mock_monitor.poll_recent_events.return_value = {
        "events_found": 0,
        "events": [],
        "errors": [],
        "status": "OK",
    }

    with patch("monitoring.CloudTrailMonitor", return_value=mock_monitor):
        monitoring._poll_aws()

    # A clean, genuine "nothing happened" poll should not write a check-history row.
    assert len(db.get_check_history()) == 0
    polls = db.get_recent_polls()
    assert len(polls) == 1
    assert polls[0]["events_found"] == 0
