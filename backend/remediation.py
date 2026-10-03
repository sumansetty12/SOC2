"""
Remediation guidance for SOC2 findings — two-tier design.

  - Free tier: curated, specific fix-it text per control category. Works
    for every user, no API key, no cost. This is the default and is
    always available.
  - AI tier: optional. If the user supplies their own Anthropic API key,
    calls Claude to generate guidance tailored to the specific finding's
    details (naming the exact user/bucket/repo involved) rather than a
    generic template.

The two-tier split is a deliberate product choice: a user without an API
key still gets real, usable guidance — AI is an enhancement, not a
requirement for the tool to be useful.

API keys are never stored — they're passed per-request and used only for
that one call.
"""

FREE_TIER_GUIDANCE = {
    ("aws", "access_control"): (
        "Enable MFA for this IAM user: AWS Console -> IAM -> Users -> select the user -> "
        "Security credentials tab -> Assign MFA device. Use an authenticator app "
        "(Google Authenticator, Authy, etc.). This is the single highest-impact fix "
        "for CC6.1 (logical access control)."
    ),
    ("aws", "logging_monitoring"): (
        "Enable CloudTrail logging: AWS Console -> CloudTrail -> Trails -> Create trail. "
        "Enable multi-region logging and log file validation. This satisfies CC7.2 "
        "(logging and monitoring) and is required evidence for almost every SOC2 audit."
    ),
    ("aws", "security_config"): (
        "Block public access on this S3 bucket: AWS Console -> S3 -> select the bucket -> "
        "Permissions tab -> Block public access -> Edit -> enable all four blocking options. "
        "Unless this bucket is intentionally meant to host public content (like a static "
        "website), this should always be enabled for CC6.6 (security configuration)."
    ),
    ("github", "access_control"): (
        "Review this repository's collaborator list: GitHub -> repo -> Settings -> "
        "Collaborators and teams. Remove anyone who no longer needs access, and confirm "
        "admin access is limited to people who genuinely need it. This supports CC6.1 "
        "evidence on the GitHub side."
    ),
    ("github", "change_management"): (
        "Add a branch protection rule: GitHub -> repo -> Settings -> Branches -> "
        "Add branch protection rule -> enter your default branch name (e.g. 'main') -> "
        "check 'Require a pull request before merging'. This satisfies CC8.1 "
        "(change management) by ensuring no code reaches production without review."
    ),
}


def get_free_guidance(source: str, category: str) -> str:
    return FREE_TIER_GUIDANCE.get(
        (source, category),
        "No specific guidance available for this finding yet — check the SOC2 Trust "
        "Service Criteria documentation for general best practices.",
    )


def _call_claude(api_key: str, prompt: str, max_tokens: int) -> dict:
    try:
        import anthropic
    except ImportError:
        return {"error": "anthropic package not installed. Run: pip install anthropic"}

    try:
        client = anthropic.Anthropic(api_key=api_key)
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        text = "".join(block.text for block in response.content if hasattr(block, "text"))
        return {"text": text}
    except Exception as e:
        return {"error": str(e)}


def get_ai_guidance(source: str, category: str, finding_detail: dict, api_key: str) -> dict:
    """
    Tailored remediation guidance for one specific finding, using the
    user's own Anthropic API key.
    """
    prompt = (
        "You are a security compliance assistant. A SOC2 evidence-collection tool "
        "found this specific finding:\n\n"
        f"Source: {source}\nCategory: {category}\nDetail: {finding_detail}\n\n"
        "Write a short (3-5 sentence), specific, actionable remediation explanation "
        "for a small engineering team with no dedicated compliance staff. "
        "Name the exact resource from the detail above where possible. "
        "Do not use generic boilerplate — be concrete about this specific finding."
    )
    result = _call_claude(api_key, prompt, max_tokens=400)
    if "error" in result:
        return result
    return {"guidance": result["text"], "source": "ai"}


def generate_security_report(aws_report: dict, github_report: dict, api_key: str) -> dict:
    """
    Executive-readable, plain-English security posture summary for a
    non-technical small-business owner, generated from real findings.
    """
    prompt = (
        "You are writing a security posture summary for a non-technical small-business "
        "owner, based on real SOC2 evidence-collection results below. Write 3-4 short "
        "paragraphs in plain English: (1) overall posture in one sentence, "
        "(2) the most important issues to fix first and why they matter in business terms "
        "(not technical jargon), (3) what's already working well, (4) a short closing "
        "recommendation. Avoid acronyms where possible; explain any you must use.\n\n"
        f"AWS findings:\n{aws_report}\n\nGitHub findings:\n{github_report}"
    )
    result = _call_claude(api_key, prompt, max_tokens=800)
    if "error" in result:
        return result
    return {"report": result["text"]}
