"""
AWS Evidence Collector for SOC 2 Trust Service Criteria.

Read-only evidence collection — this module never modifies AWS resources.
All calls are describe/list/get operations only.
"""

import boto3
from datetime import datetime, timezone
from botocore.exceptions import ClientError


class AWSEvidenceCollector:
    def __init__(self, region_name="us-east-1"):
        self.region_name = region_name
        self.iam = boto3.client("iam", region_name=region_name)
        self.cloudtrail = boto3.client("cloudtrail", region_name=region_name)
        self.s3 = boto3.client("s3", region_name=region_name)
        self.ec2 = boto3.client("ec2", region_name=region_name)

    def collect_all(self) -> dict:
        """Run all AWS evidence collectors and return a structured report."""
        return {
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "access_control": self.check_iam_access_control(),
            "logging_monitoring": self.check_cloudtrail_logging(),
            "security_config": self.check_security_config(),
        }

    # ---- Access Control (SOC 2 CC6.x) ----
    def check_iam_access_control(self) -> dict:
        findings = []
        try:
            users = self.iam.list_users()["Users"]
            for user in users:
                username = user["UserName"]
                mfa_devices = self.iam.list_mfa_devices(UserName=username)["MFADevices"]
                has_mfa = len(mfa_devices) > 0

                access_keys = self.iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
                active_keys = [k for k in access_keys if k["Status"] == "Active"]

                findings.append({
                    "user": username,
                    "mfa_enabled": has_mfa,
                    "active_access_keys": len(active_keys),
                    "status": "PASS" if has_mfa else "FAIL",
                    "control": "MFA required for all IAM users (SOC 2 CC6.1)",
                })
        except ClientError as e:
            findings.append({"error": str(e)})

        total = len([f for f in findings if "status" in f])
        passed = len([f for f in findings if f.get("status") == "PASS"])
        return {
            "summary": f"{passed}/{total} users have MFA enabled",
            "details": findings,
        }

    # ---- Logging & Monitoring (SOC 2 CC7.x) ----
    def check_cloudtrail_logging(self) -> dict:
        findings = []
        try:
            trails = self.cloudtrail.describe_trails()["trailList"]
            for trail in trails:
                trail_name = trail["Name"]
                status = self.cloudtrail.get_trail_status(Name=trail["TrailARN"])
                is_logging = status.get("IsLogging", False)

                findings.append({
                    "trail_name": trail_name,
                    "is_logging": is_logging,
                    "multi_region": trail.get("IsMultiRegionTrail", False),
                    "log_file_validation": trail.get("LogFileValidationEnabled", False),
                    "status": "PASS" if is_logging else "FAIL",
                    "control": "Continuous audit logging enabled (SOC 2 CC7.2)",
                })
        except ClientError as e:
            findings.append({"error": str(e)})

        return {
            "summary": f"{len(findings)} trail(s) evaluated",
            "details": findings,
        }

    # ---- Security Configuration (SOC 2 CC6.6 / CC6.7) ----
    def check_security_config(self) -> dict:
        findings = []
        try:
            buckets = self.s3.list_buckets()["Buckets"]
            for bucket in buckets:
                bucket_name = bucket["Name"]
                try:
                    public_access = self.s3.get_public_access_block(Bucket=bucket_name)
                    config = public_access["PublicAccessBlockConfiguration"]
                    is_blocked = all([
                        config.get("BlockPublicAcls", False),
                        config.get("BlockPublicPolicy", False),
                        config.get("IgnorePublicAcls", False),
                        config.get("RestrictPublicBuckets", False),
                    ])
                except ClientError:
                    is_blocked = False  # No public access block configured

                findings.append({
                    "bucket": bucket_name,
                    "public_access_blocked": is_blocked,
                    "status": "PASS" if is_blocked else "FAIL",
                    "control": "S3 buckets must block public access by default (SOC 2 CC6.6)",
                })
        except ClientError as e:
            findings.append({"error": str(e)})

        return {
            "summary": f"{len(findings)} bucket(s) evaluated",
            "details": findings,
        }
