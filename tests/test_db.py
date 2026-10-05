"""
Tests for db.py — the SQLite layer backing Continuous Monitoring history.
"""
import os
import pytest
import db


@pytest.fixture(autouse=True)
def fresh_db(monkeypatch, tmp_path):
    """Each test gets its own throwaway SQLite file, never the real one."""
    test_db_path = str(tmp_path / "test_soc2_history.db")
    monkeypatch.setattr(db, "DB_PATH", test_db_path)
    db.init_db()
    yield
    if os.path.exists(test_db_path):
        os.remove(test_db_path)


def test_record_and_retrieve_poll_runs():
    db.record_poll_run("aws", 0, False)
    db.record_poll_run("aws", 2, True)
    polls = db.get_recent_polls()
    assert len(polls) == 2
    assert polls[0]["source"] == "aws"


def test_record_and_retrieve_check_history():
    db.record_check("aws", "Test trigger", {"status": "FAIL"}, "Test summary")
    history = db.get_check_history()
    assert len(history) == 1
    assert history[0]["summary"] == "Test summary"


def test_github_repo_state_baseline_then_change():
    assert db.get_github_repo_state("owner/repo1") is None

    db.set_github_repo_state("owner/repo1", False)
    state = db.get_github_repo_state("owner/repo1")
    assert state["last_branch_protected"] == 0

    db.set_github_repo_state("owner/repo1", True)
    state = db.get_github_repo_state("owner/repo1")
    assert state["last_branch_protected"] == 1


def test_recent_polls_respects_limit():
    for i in range(5):
        db.record_poll_run("aws", i, False)
    polls = db.get_recent_polls(limit=3)
    assert len(polls) == 3
