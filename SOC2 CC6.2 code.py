import boto3
import os
import json
import datetime
import logging
import uuid

logger = logging.getLogger()
logger.setLevel(logging.INFO)

iam = boto3.client('iam')
s3 = boto3.client('s3')
sns = boto3.client('sns')

# === Environment Variables ===
S3_BUCKET = os.environ['S3_BUCKET']  # central bucket e.g. soc2-central-logs
S3_PREFIX = os.environ.get('S3_PREFIX', 'audit_reports/cc6-2')
SNS_TOPIC_ARN = os.environ['SNS_TOPIC_ARN']

# DRY_RUN = true means only detect, don’t disable keys
DRY_RUN = os.environ.get('DRY_RUN', 'false').lower() in ('1', 'true', 'yes')

# Users to skip (service accounts etc.)
SKIP_USERS = set(u.strip() for u in os.environ.get('SKIP_USERS', '').split(',') if u.strip())


def now_iso():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def write_s3_report(body_dict, key_suffix):
    """Write pretty-printed JSON report to S3 under audit-reports path."""
    now = datetime.datetime.utcnow()
    key = (
        f"{S3_PREFIX}/"
        f"year={now.year}/month={now.month:02d}/day={now.day:02d}/"
        f"{key_suffix}"
    )
    try:
        s3.put_object(
            Bucket=S3_BUCKET,
            Key=key,
            Body=json.dumps(body_dict, indent=4).encode('utf-8')  # ✅ pretty JSON (multi-line)
        )
        logger.info("✅ Wrote report to s3://%s/%s", S3_BUCKET, key)
        return f"s3://{S3_BUCKET}/{key}"
    except Exception as e:
        logger.exception("❌ Failed to write report to S3: %s", e)
        raise


def lambda_handler(event, context):
    run_id = str(uuid.uuid4())
    ts = now_iso()
    findings = []
    disabled = []
    errors = []

    logger.info("CC6.2 run_id=%s DRY_RUN=%s skip_users=%s", run_id, DRY_RUN, ",".join(SKIP_USERS))

    paginator = iam.get_paginator('list_users')
    for page in paginator.paginate():
        for user in page.get('Users', []):
            user_name = user.get('UserName')
            if user_name in SKIP_USERS:
                logger.info("Skipping user (skip list): %s", user_name)
                continue

            try:
                mfa_resp = iam.list_mfa_devices(UserName=user_name)
                if mfa_resp.get('MFADevices'):
                    # Has MFA -> skip
                    continue
            except Exception as e:
                logger.exception("Error listing MFA devices for %s: %s", user_name, e)
                errors.append({"user": user_name, "error": str(e)})
                continue

            # No MFA -> check access keys
            try:
                keys = iam.list_access_keys(UserName=user_name).get('AccessKeyMetadata', [])
            except Exception as e:
                logger.exception("Error listing access keys for %s: %s", user_name, e)
                errors.append({"user": user_name, "error": str(e)})
                continue

            for k in keys:
                if k.get('Status') != 'Active':
                    continue

                akid = k.get('AccessKeyId')
                create_date = k.get('CreateDate').isoformat() if k.get('CreateDate') else None

                # get last used
                try:
                    last_used = iam.get_access_key_last_used(AccessKeyId=akid).get('AccessKeyLastUsed', {})
                    last_used_date = last_used.get('LastUsedDate')
                    if isinstance(last_used_date, datetime.datetime):
                        last_used_date = last_used_date.isoformat()
                except Exception:
                    last_used_date = None

                finding = {
                    "user": user_name,
                    "access_key_id": akid,
                    "access_key_create_date": create_date,
                    "access_key_last_used": last_used_date,
                    "action": "detected"
                }

                if not DRY_RUN:
                    try:
                        iam.update_access_key(UserName=user_name, AccessKeyId=akid, Status='Inactive')
                        finding["action"] = "disabled"
                        finding["disabled_at"] = ts
                        disabled.append(finding)
                        logger.info("✅ Disabled access key %s for user %s", akid, user_name)
                    except Exception as e:
                        logger.exception("❌ Failed to disable %s for %s: %s", akid, user_name, e)
                        errors.append({"user": user_name, "access_key": akid, "error": str(e)})

                findings.append(finding)

    report = {
        "job_id": run_id,
        "timestamp": ts,
        "dry_run": DRY_RUN,
        "skipped_users": list(SKIP_USERS),
        "findings_count": len(findings),
        "findings": findings,
        "disabled_count": len(disabled),
        "disabled": disabled,
        "errors": errors
    }

    key_suffix = f"{ts.replace(':','-')}_{run_id}.json"
    s3_path = write_s3_report(report, key_suffix)

    # SNS summary
    subject = "SOC2 CC6.2 — Access Key Disable Report"
    message = (
        f"job_id: {run_id}\n"
        f"timestamp: {ts}\n"
        f"dry_run: {DRY_RUN}\n"
        f"findings: {len(findings)}\n"
        f"disabled: {len(disabled)}\n"
        f"report: {s3_path}"
    )
    try:
        sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject, Message=message)
        logger.info("✅ Published SNS summary to %s", SNS_TOPIC_ARN)
    except Exception as e:
        logger.exception("❌ Failed to publish SNS: %s", e)

    return {
        "status": "ok",
        "job_id": run_id,
        "findings": len(findings),
        "disabled": len(disabled),
        "report": s3_path
    }
