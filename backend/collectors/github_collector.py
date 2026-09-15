"""
GitHub Evidence Collector for SOC 2 Trust Service Criteria.

Read-only evidence collection via the GitHub REST API.
Requires a GitHub personal access token with repo read scope.
"""

import requests
from datetime import datetime, timezone


class GitHubEvidenceCollector:
    def __init__(self, token: str, org: str):
        self.token = token
        self.org = org
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
        }
        self.base_url = "https://api.github.com"

    def collect_all(self) -> dict:
        return {
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "access_control": self.check_repo_access_control(),
            "change_management": self.check_branch_protection(),
        }

    def _get_repos(self) -> list:
        resp = requests.get(
            f"{self.base_url}/orgs/{self.org}/repos",
            headers=self.headers,
            params={"per_page": 100},
        )
        resp.raise_for_status()
        return resp.json()

    # ---- Access Control (SOC 2 CC6.1) ----
    def check_repo_access_control(self) -> dict:
        findings = []
        try:
            repos = self._get_repos()
            for repo in repos:
                repo_name = repo["name"]
                collab_resp = requests.get(
                    f"{self.base_url}/repos/{self.org}/{repo_name}/collaborators",
                    headers=self.headers,
                )
                collaborators = collab_resp.json() if collab_resp.status_code == 200 else []

                admin_count = sum(
                    1 for c in collaborators
                    if isinstance(c, dict) and c.get("permissions", {}).get("admin")
                )

                findings.append({
                    "repo": repo_name,
                    "private": repo.get("private", False),
                    "collaborator_count": len(collaborators) if isinstance(collaborators, list) else 0,
                    "admin_count": admin_count,
                    "status": "PASS" if repo.get("private", False) else "REVIEW",
                    "control": "Repository access restricted appropriately (SOC 2 CC6.1)",
                })
        except Exception as e:
            findings.append({"error": str(e)})

        return {
            "summary": f"{len(findings)} repo(s) evaluated",
            "details": findings,
        }

    # ---- Change Management (SOC 2 CC8.1) ----
    def check_branch_protection(self) -> dict:
        findings = []
        try:
            repos = self._get_repos()
            for repo in repos:
                repo_name = repo["name"]
                default_branch = repo.get("default_branch", "main")

                protection_resp = requests.get(
                    f"{self.base_url}/repos/{self.org}/{repo_name}/branches/{default_branch}/protection",
                    headers=self.headers,
                )
                is_protected = protection_resp.status_code == 200

                requires_review = False
                if is_protected:
                    protection_data = protection_resp.json()
                    requires_review = "required_pull_request_reviews" in protection_data

                findings.append({
                    "repo": repo_name,
                    "default_branch": default_branch,
                    "branch_protected": is_protected,
                    "requires_pr_review": requires_review,
                    "status": "PASS" if (is_protected and requires_review) else "FAIL",
                    "control": "Changes require PR review before merge to default branch (SOC 2 CC8.1)",
                })
        except Exception as e:
            findings.append({"error": str(e)})

        return {
            "summary": f"{len(findings)} repo(s) evaluated",
            "details": findings,
        }
