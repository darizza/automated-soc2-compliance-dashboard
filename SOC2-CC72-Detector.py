# detector.py
"""
SOC2 CC7.2 Detector Lambda
Handler: detector.lambda_handler

Environment variables:
- BUCKET (required): S3 bucket name where findings will be written
- FINDINGS_PREFIX (optional): e.g., "audit_reports/findings"
- SNS_TOPIC_ARN (optional): ARN of SNS topic to publish a short summary
- DETECT_PORTS (optional): "ALL" or comma-separated ports (e.g., "22,3389,3306"). Default ALL.
"""

import os
import json
import uuid
import boto3
import datetime
import logging
from typing import Optional, Set

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2 = boto3.client("ec2")
s3 = boto3.client("s3")
sns = boto3.client("sns")

BUCKET = os.environ["BUCKET"]
FINDINGS_PREFIX = os.environ.get("FINDINGS_PREFIX", "audit_reports/findings")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")
DETECT_PORTS = os.environ.get("DETECT_PORTS", "ALL")  # "ALL" or csv of ints

def _parse_ports(raw: str) -> Optional[Set[int]]:
    raw = (raw or "").strip().upper()
    if raw in ("", "ALL"):
        return None
    out = set()
    for p in raw.split(","):
        p = p.strip()
        if not p:
            continue
        try:
            out.add(int(p))
        except ValueError:
            logger.warning("Ignoring invalid port in DETECT_PORTS: %r", p)
    return out

DETECT_PORT_SET = _parse_ports(DETECT_PORTS)

def _is_world_cidr(cidr: Optional[str]) -> bool:
    return cidr in ("0.0.0.0/0", "::/0")

def _perm_matches_ports(perm: dict) -> bool:
    """Return True if this permission matches DETECT_PORT_SET filter.
    If DETECT_PORT_SET is None, match everything."""
    if DETECT_PORT_SET is None:
        return True
    ip_proto = perm.get("IpProtocol")
    from_port = perm.get("FromPort")
    to_port = perm.get("ToPort")
    if ip_proto in ("tcp", "udp") and from_port is not None and to_port is not None:
        for p in DETECT_PORT_SET:
            if from_port <= p <= to_port:
                return True
    return False

def _now_iso() -> str:
    return datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()

def lambda_handler(event, context):
    account_id = None
    try:
        account_id = context.invoked_function_arn.split(":")[4] if context and getattr(context, "invoked_function_arn", None) else None
    except Exception:
        account_id = None
    region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")

    logger.info("Starting CC7.2 detector | account=%s region=%s", account_id, region)
    findings = []

    paginator = ec2.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        for sg in page.get("SecurityGroups", []):
            group_id = sg.get("GroupId")
            group_name = sg.get("GroupName")
            vpc_id = sg.get("VpcId")
            for perm in sg.get("IpPermissions", []):
                if not _perm_matches_ports(perm):
                    continue
                ip_proto = perm.get("IpProtocol")
                from_port = perm.get("FromPort")
                to_port = perm.get("ToPort")

                # IPv4 ranges
                for r in perm.get("IpRanges", []):
                    cidr = r.get("CidrIp")
                    if _is_world_cidr(cidr):
                        findings.append({
                            "findingId": str(uuid.uuid4()),
                            "control": "SOC2-CC7.2",
                            "detectedAt": _now_iso(),
                            "accountId": account_id,
                            "region": region,
                            "groupId": group_id,
                            "groupName": group_name,
                            "vpcId": vpc_id,
                            "direction": "ingress",
                            "ipProtocol": ip_proto,
                            "fromPort": from_port,
                            "toPort": to_port,
                            "cidr": cidr,
                            "ipv6Cidr": None,
                            "risk": "Security group ingress open to world",
                            "remediationEligible": True,
                            "metadata": {"description": r.get("Description")}
                        })

                # IPv6 ranges
                for r in perm.get("Ipv6Ranges", []):
                    cidr6 = r.get("CidrIpv6")
                    if _is_world_cidr(cidr6):
                        findings.append({
                            "findingId": str(uuid.uuid4()),
                            "control": "SOC2-CC7.2",
                            "detectedAt": _now_iso(),
                            "accountId": account_id,
                            "region": region,
                            "groupId": group_id,
                            "groupName": group_name,
                            "vpcId": vpc_id,
                            "direction": "ingress",
                            "ipProtocol": ip_proto,
                            "fromPort": from_port,
                            "toPort": to_port,
                            "cidr": None,
                            "ipv6Cidr": cidr6,
                            "risk": "Security group ingress open to world (IPv6)",
                            "remediationEligible": True,
                            "metadata": {"description": r.get("Description")}
                        })

    ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    key = f"{FINDINGS_PREFIX}/cc72-findings-{ts}-{uuid.uuid4().hex[:8]}.json"

    doc = {
        "schemaVersion": "2025-09-10",
        "control": "SOC2-CC7.2",
        "generator": "cc72-detector-lambda",
        "accountId": account_id,
        "region": region,
        "detectedAt": _now_iso(),
        "filters": {"ports": "ALL" if DETECT_PORT_SET is None else sorted(list(DETECT_PORT_SET))},
        "findingsCount": len(findings),
        "findings": findings
    }

    s3.put_object(
        Bucket=BUCKET,
        Key=key,
        Body=json.dumps(doc, indent=2).encode("utf-8"),
        ContentType="application/json"
    )
    logger.info("Wrote findings to s3://%s/%s (count=%d)", BUCKET, key, len(findings))

    if SNS_TOPIC_ARN:
        msg = {
            "summary": f"CC7.2 Detector found {len(findings)} open-to-world SG rule(s)",
            "bucket": BUCKET,
            "key": key,
            "region": region,
            "accountId": account_id,
        }
        try:
            sns.publish(
                TopicArn=SNS_TOPIC_ARN,
                Message=json.dumps(msg),
                Subject=f"[SOC2 CC7.2] Detector findings: {len(findings)} rule(s)"
            )
        except Exception as e:
            logger.exception("Failed to publish SNS: %s", e)

    return {"status": "OK", "s3Key": key, "count": len(findings)}
