"""
Tests for the AWS collector's access key rotation check (CC6.2) — the
newly added broader criteria coverage.
"""
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
from collectors.aws_collector import AWSEvidenceCollector


def _make_mock_iam(users_and_keys):
    """
    users_and_keys: list of (username, [(key_id, age_days, days_since_used_or_None)])
    """
    mock_iam = MagicMock()
    mock_iam.list_users.return_value = {"Users": [{"UserName": u} for u, _ in users_and_keys]}

    now = datetime.now(timezone.utc)

    def list_access_keys(UserName):
        for u, keys in users_and_keys:
            if u == UserName:
                return {"AccessKeyMetadata": [
                    {"AccessKeyId": kid, "Status": "Active", "CreateDate": now - timedelta(days=age)}
                    for kid, age, _ in keys
                ]}
        return {"AccessKeyMetadata": []}

    def get_access_key_last_used(AccessKeyId):
        for u, keys in users_and_keys:
            for kid, age, last_used in keys:
                if kid == AccessKeyId:
                    if last_used is None:
                        return {"AccessKeyLastUsed": {}}
                    return {"AccessKeyLastUsed": {"LastUsedDate": now - timedelta(days=last_used)}}
        return {"AccessKeyLastUsed": {}}

    mock_iam.list_access_keys.side_effect = list_access_keys
    mock_iam.get_access_key_last_used.side_effect = get_access_key_last_used
    return mock_iam


def test_fresh_key_passes():
    mock_iam = _make_mock_iam([("alice", [("AKIAFRESH1", 10, 2)])])
    with patch("boto3.client", return_value=mock_iam):
        collector = AWSEvidenceCollector()
        result = collector.check_access_key_rotation(stale_days=90)

    assert result["details"][0]["status"] == "PASS"
    assert "1/1" in result["summary"]


def test_old_key_fails_on_age():
    mock_iam = _make_mock_iam([("bob", [("AKIAOLD1", 120, 5)])])
    with patch("boto3.client", return_value=mock_iam):
        collector = AWSEvidenceCollector()
        result = collector.check_access_key_rotation(stale_days=90)

    assert result["details"][0]["status"] == "FAIL"
    assert result["details"][0]["age_days"] == 120


def test_unused_key_fails_on_inactivity():
    mock_iam = _make_mock_iam([("carol", [("AKIAUNUSED1", 20, 150)])])
    with patch("boto3.client", return_value=mock_iam):
        collector = AWSEvidenceCollector()
        result = collector.check_access_key_rotation(stale_days=90)

    assert result["details"][0]["status"] == "FAIL"
    assert result["details"][0]["days_since_last_used"] == 150


def test_access_key_is_masked_in_output():
    mock_iam = _make_mock_iam([("dave", [("AKIASECRETVALUE1234", 10, 2)])])
    with patch("boto3.client", return_value=mock_iam):
        collector = AWSEvidenceCollector()
        result = collector.check_access_key_rotation()

    key_shown = result["details"][0]["access_key_id"]
    assert key_shown != "AKIASECRETVALUE1234", "full key id should never be shown in output"
    assert key_shown.endswith("1234")
    assert key_shown.startswith("*")
