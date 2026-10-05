"""
Tests for remediation.py — free-tier guidance lookup and the multi-provider
AI tier (Anthropic + OpenAI). AI calls are mocked; no real API key or
network access is needed to run this suite.
"""
from unittest.mock import MagicMock, patch
import remediation


def test_free_guidance_known_categories():
    assert "MFA" in remediation.get_free_guidance("aws", "access_control")
    assert "branch protection" in remediation.get_free_guidance("github", "change_management").lower()


def test_free_guidance_unknown_category_falls_back_gracefully():
    result = remediation.get_free_guidance("aws", "not_a_real_category")
    assert "No specific guidance" in result


def test_anthropic_ai_guidance_success():
    mock_block = MagicMock()
    mock_block.text = "Enable MFA for user april-01 specifically."
    mock_response = MagicMock()
    mock_response.content = [mock_block]
    mock_client = MagicMock()
    mock_client.messages.create.return_value = mock_response

    with patch("anthropic.Anthropic", return_value=mock_client):
        result = remediation.get_ai_guidance(
            "aws", "access_control", {"user": "april-01"}, api_key="fake", provider="anthropic"
        )

    assert "guidance" in result
    assert "april-01" in result["guidance"]
    assert result["provider"] == "anthropic"


def test_openai_ai_guidance_success():
    mock_choice = MagicMock()
    mock_choice.message.content = "For repo SOC2, enable branch protection on main."
    mock_response = MagicMock()
    mock_response.choices = [mock_choice]
    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = mock_response

    with patch("openai.OpenAI", return_value=mock_client):
        result = remediation.get_ai_guidance(
            "github", "change_management", {"repo": "SOC2"}, api_key="fake", provider="openai"
        )

    assert "guidance" in result
    assert "SOC2" in result["guidance"]
    assert result["provider"] == "openai"


def test_ai_guidance_bad_api_key_returns_error_not_crash():
    mock_client = MagicMock()
    mock_client.messages.create.side_effect = Exception("invalid x-api-key")

    with patch("anthropic.Anthropic", return_value=mock_client):
        result = remediation.get_ai_guidance("aws", "access_control", {}, api_key="bad-key")

    assert "error" in result


def test_unknown_provider_is_rejected_not_silently_defaulted():
    result = remediation.get_ai_guidance("aws", "access_control", {}, api_key="x", provider="made-up")
    assert "error" in result
    assert "Unknown provider" in result["error"]


def test_generate_security_report_success():
    mock_block = MagicMock()
    mock_block.text = "Your business has significant security gaps to address."
    mock_response = MagicMock()
    mock_response.content = [mock_block]
    mock_client = MagicMock()
    mock_client.messages.create.return_value = mock_response

    with patch("anthropic.Anthropic", return_value=mock_client):
        result = remediation.generate_security_report(
            {"access_control": {"summary": "0/16 MFA"}}, {}, api_key="fake"
        )

    assert "report" in result
    assert "security gaps" in result["report"]
