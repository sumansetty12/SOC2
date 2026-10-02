# SOC 2 Evidence Collector

**Automated audit evidence collection for small teams without dedicated compliance staff.**

## Why this exists

SOC 2 compliance is a near-mandatory requirement for any B2B SaaS company selling to mid-market or enterprise customers — but the evidence-gathering process (screenshotting IAM configs, exporting access logs, documenting change approvals) is manual, repetitive, and often costs small companies thousands of dollars per audit cycle in either engineering hours or outsourced compliance consulting.

This project automates the evidence-collection layer of SOC 2 readiness — pulling access control, logging, and change-management evidence directly from AWS and GitHub, and mapping it to specific SOC 2 Trust Service Criteria — so a small engineering team can generate an audit-ready evidence package in minutes instead of weeks.

## Who this is for

Early-stage startups and small engineering teams (typically 2-50 engineers) pursuing their first SOC 2 audit, who don't yet have budget for a dedicated compliance platform or consultant.

## What it checks today (MVP scope)

| Trust Service Criterion | AWS Evidence | GitHub Evidence |
|---|---|---|
| CC6.1 — Logical access control | IAM users, MFA enforcement, active access keys | Repository access list, admin count |
| CC6.6 — Security configuration | S3 public access block settings | — |
| CC7.2 — Logging & monitoring | CloudTrail logging status, multi-region config | — |
| CC8.1 — Change management | — | Branch protection, required PR reviews |

All checks are **read-only** — this tool never modifies your AWS or GitHub configuration.

## Real-world validation

This tool has been run end-to-end against real (not synthetic) AWS and GitHub accounts to confirm it works correctly, including using its own findings to drive actual remediation:

**Before:**

| Control | Result |
|---|---|
| IAM MFA enforcement (CC6.1) | 0/16 users had MFA enabled |
| CloudTrail logging (CC7.2) | 1 trail evaluated — logging enabled, multi-region, log file validation on — **PASS** |
| S3 public access block (CC6.6) | 0/6 buckets had public access blocked |
| Branch protection (CC8.1) | 0/14 repositories required PR review on their default branch |

**After remediating one finding on each platform (enabling MFA on one IAM user, adding a branch-protection rule to one repository) and re-running the collector:**

| Control | Before | After |
|---|---|---|
| IAM MFA — target user | FAIL | **PASS** |
| Branch protection — target repository | FAIL | **PASS** |

This confirms the tool correctly detects both the initial gap and the fix, rather than just returning a static or hardcoded result.

## Architecture

```
soc2-evidence-collector/
├── backend/
│   ├── main.py                    # FastAPI app, API endpoints
│   ├── collectors/
│   │   ├── aws_collector.py       # AWS evidence collection (boto3)
│   │   └── github_collector.py    # GitHub evidence collection (REST API)
│   └── requirements.txt
└── frontend/
    └── index.html                 # Dashboard (vanilla JS, no build step)
```

## Setup

### Prerequisites
- Python 3.10+
- AWS credentials configured (`aws configure`, or environment variables) with read-only IAM/CloudTrail/S3 permissions
- A GitHub personal access token with `repo` read scope (for private repos) or `public_repo` (for public only)

### Install and run

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

Then open `http://localhost:8000` in your browser.

### Recommended AWS IAM policy (read-only, least-privilege)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:ListUsers",
        "iam:ListMFADevices",
        "iam:ListAccessKeys",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "s3:ListAllMyBuckets",
        "s3:GetPublicAccessBlock"
      ],
      "Resource": "*"
    }
  ]
}
```

## Roadmap

- [ ] PDF export of evidence reports (auditor-ready format)
- [ ] Scheduled/recurring collection (evidence trends over time, not just point-in-time)
- [ ] Additional SOC 2 criteria coverage (Availability, Confidentiality categories)
- [ ] Support for GCP and Azure
- [ ] Slack/email notifications when a control moves from PASS to FAIL

## Contributing

This is an early-stage open-source project. Issues and pull requests are welcome — see the roadmap above for areas that need work.

## License

MIT
