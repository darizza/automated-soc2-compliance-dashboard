# remediator.py
"""
SOC2 CC7.2 Remediator Lambda
Handler: remediator.lambda_handler

Environment variables:
- BUCKET (required): S3 bucket name used by detector & remediator
- FINDINGS_PREFIX (optional): prefix detector writes findings to (default "audit_reports/findings")
- REMEDIATIONS_PREFIX (optional): prefix to write remediation reports (default "audit_reports/remediations")
- SNS_TOPIC_ARN (optional): ARN of SNS topic to notify
- REMEDIATE_PORTS (optional): "ALL" or comma-separated ports to auto-remediate (default "22,3389")
- DRY_RUN (optional): "true" or "false" - if true, performs no mutations (default "false")
"""

import os
import json
import uuid
import boto3
import datetime
import logging
from typing import Optional, Set
from urllib.parse import unquote_plus

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2 = boto3.client("ec2")
s3 = boto3.client("s3")
sns = boto3.client("sns")

BUCKET = os.environ["BUCKET"]
FINDINGS_PREFIX = os.environ.get("FINDINGS_PREFIX", "audit_reports/findings")
REMEDIATIONS_PREFIX = os.environ.get("REMEDIATIONS_PREFIX", "audit_reports/remediations")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")
REMEDIATE_PORTS = os.environ.get("REMEDIATE_PORTS", "22,3389")  # "ALL" or csv
DRY_RUN = os.environ.get("DRY_RUN", "false").lower() == "true"

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
            logger.warning("Ignoring invalid REMEDIATE_PORTS entry: %r", p)
    return out

REMEDIATE_PORT_SET = _parse_ports(REMEDIATE_PORTS)

def _now_iso() -> str:
    return datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()

def _world(f):
    return f.get("cidr") == "0.0.0.0/0" or f.get("ipv6Cidr") == "::/0"

def _ports_match(f) -> bool:
    """Return True if this finding should be auto-remediated according to REMEDIATE_PORTS."""
    if REMEDIATE_PORT_SET is None:
        return True
    fp = f.get("fromPort")
    tp = f.get("toPort")
    proto = (f.get("ipProtocol") or "").lower()
    if proto in ("tcp", "udp") and isinstance(fp, int) and isinstance(tp, int):
        for p in REMEDIATE_PORT_SET:
            if fp <= p <= tp:
                return True
    return False

def _build_ip_permissions(f):
    ip_permissions = {
        "IpProtocol": f.get("ipProtocol") if f.get("ipProtocol") is not None else "-1"
    }
    if f.get("fromPort") is not None:
        ip_permissions["FromPort"] = int(f["fromPort"])
    if f.get("toPort") is not None:
        ip_permissions["ToPort"] = int(f["toPort"])

    ipv4 = []
    ipv6 = []
    if f.get("cidr"):
        ipv4.append({"CidrIp": f["cidr"]})
    if f.get("ipv6Cidr"):
        ipv6.append({"CidrIpv6": f["ipv6Cidr"]})
    if ipv4:
        ip_permissions["IpRanges"] = ipv4
    if ipv6:
        ip_permissions["Ipv6Ranges"] = ipv6
    return [ip_permissions]

def lambda_handler(event, context):
    # EventBridge "Object Created" -> event['detail']['bucket']['name'] and event['detail']['object']['key']
    try:
        detail = event.get("detail") or {}
        bucket = (detail.get("bucket") or {}).get("name")
        key = (detail.get("object") or {}).get("key")
        if key:
            key = unquote_plus(key)
    except Exception:
        logger.exception("Unexpected event format")
        return {"status": "ERROR", "message": "Bad event format"}

    if not bucket or not key:
        logger.error("Missing bucket/key in event: %s", json.dumps(event))
        return {"status": "ERROR", "message": "Missing bucket/key"}

    if not key.startswith(FINDINGS_PREFIX + "/"):
        logger.info("Ignoring object outside findings prefix: s3://%s/%s", bucket, key)
        return {"status": "IGNORED"}

    logger.info("Processing findings: s3://%s/%s", bucket, key)
    obj = s3.get_object(Bucket=bucket, Key=key)
    payload = json.loads(obj["Body"].read())

    results = []
    attempted = 0
    revoked = 0
    skipped = 0
    failed = 0

    for f in payload.get("findings", []):
        if not f.get("remediationEligible", True):
            skipped += 1
            results.append({"findingId": f.get("findingId"), "groupId": f.get("groupId"), "action": "SKIPPED", "reason": "remediationEligible=false"})
            continue
        if f.get("direction") != "ingress" or not _world(f):
            skipped += 1
            results.append({"findingId": f.get("findingId"), "groupId": f.get("groupId"), "action": "SKIPPED", "reason": "not ingress or not world-open"})
            continue
        if not _ports_match(f):
            skipped += 1
            results.append({"findingId": f.get("findingId"), "groupId": f.get("groupId"), "action": "SKIPPED", "reason": "port not in REMEDIATE_PORTS"})
            continue

        attempted += 1
        if DRY_RUN:
            results.append({"findingId": f.get("findingId"), "groupId": f.get("groupId"), "action": "DRY_RUN"})
            continue

        try:
            ip_permissions = _build_ip_permissions(f)
            ec2.revoke_security_group_ingress(
                GroupId=f["groupId"],
                IpPermissions=ip_permissions
            )
            revoked += 1
            results.append({"findingId": f.get("findingId"), "groupId": f.get("groupId"), "action": "REVOKED"})
        except Exception as e:
            failed += 1
            logger.exception("Failed to revoke SG rule for %s", f.get("groupId"))
            results.append({"findingId": f.get("findingId"), "groupId": f.get("groupId"), "action": "FAILED", "error": str(e)})

    summary = {
        "totalFindingsInFile": len(payload.get("findings", [])),
        "attempted": attempted,
        "revoked": revoked,
        "failed": failed,
        "skipped": skipped,
        "dryRun": DRY_RUN,
    }

    ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    rem_key = f"{REMEDIATIONS_PREFIX}/cc72-remediation-{ts}-{uuid.uuid4().hex[:8]}.json"
    report = {
        "schemaVersion": "2025-09-10",
        "control": "SOC2-CC7.2",
        "processor": "cc72-remediator-lambda",
        "sourceFindingsKey": key,
        "remediatedAt": _now_iso(),
        "summary": summary,
        "results": results,
    }

    s3.put_object(
        Bucket=BUCKET,
        Key=rem_key,
        Body=json.dumps(report, indent=2).encode("utf-8"),
        ContentType="application/json"
    )
    logger.info("Wrote remediation report to s3://%s/%s", BUCKET, rem_key)

    if SNS_TOPIC_ARN:
        msg = {
            "summary": summary,
            "bucket": BUCKET,
            "remediationKey": rem_key,
            "sourceFindingsKey": key,
        }
        try:
            sns.publish(
                TopicArn=SNS_TOPIC_ARN,
                Message=json.dumps(msg),
                Subject=f"[SOC2 CC7.2] Remediation: revoked={revoked}, failed={failed}, skipped={skipped}, dryRun={DRY_RUN}"
            )
        except Exception as e:
            logger.exception("Failed to publish SNS: %s", e)

    return {"status": "OK", "remediationReportKey": rem_key, "summary": summary}
