import boto3 
import json
from datetime import datetime, timezone

s3 = boto3.client("s3")
sns = boto3.client("sns")
iam = boto3.client("iam")

# Replace with your central logging bucket + SNS topic ARN
CENTRAL_BUCKET = "soc2-audit-logs-central-206299126127"
SNS_TOPIC_ARN = "arn:aws:sns:us-east-1:206299126127:SOC2Automation"

def lambda_handler(event, context):
    now = datetime.now(timezone.utc)

    # Get current password policy
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
    except iam.exceptions.NoSuchEntityException:
        policy = {}

    findings = []

    # Define required SOC 2 settings
    required_policy = {
        "MinimumPasswordLength": 14,
        "RequireSymbols": True,
        "RequireNumbers": True,
        "RequireUppercaseCharacters": True,
        "RequireLowercaseCharacters": True,
        "MaxPasswordAge": 90,
        "PasswordReusePrevention": 24,
        "HardExpiry": False,
    }

    # Compare actual vs required
    for key, required_value in required_policy.items():
        actual_value = policy.get(key)
        if actual_value != required_value:
            findings.append(f"{key} is {actual_value}, should be {required_value}")

    compliance_status = "COMPLIANT"
    finding_text = "Password policy is compliant with SOC 2 CC6.1."

    # If findings exist, remediate
    if findings:
        compliance_status = "NON_COMPLIANT_REMEDIATED"
        finding_text = "; ".join(findings)

        # Update password policy to required SOC 2 settings
        iam.update_account_password_policy(
            MinimumPasswordLength=required_policy["MinimumPasswordLength"],
            RequireSymbols=required_policy["RequireSymbols"],
            RequireNumbers=required_policy["RequireNumbers"],
            RequireUppercaseCharacters=required_policy["RequireUppercaseCharacters"],
            RequireLowercaseCharacters=required_policy["RequireLowercaseCharacters"],
            MaxPasswordAge=required_policy["MaxPasswordAge"],
            PasswordReusePrevention=required_policy["PasswordReusePrevention"],
            HardExpiry=required_policy["HardExpiry"],
            AllowUsersToChangePassword=True
        )

        finding_text += " | Password policy updated to comply with SOC 2 CC6.1."

    # Build audit log entry
    log_entry = {
        "timestamp": now.isoformat(),
        "control_id": "CC6.1",
        "resource_type": "IAM_Password_Policy",
        "resource_id": "AWS_Account",
        "compliance_status": compliance_status,
        "finding": finding_text,
        "account_id": context.invoked_function_arn.split(":")[4],
        "region": context.invoked_function_arn.split(":")[3],
    }

    # Save JSON to partitioned path in S3
    s3_key = (
        f"audit_reports/cc6-1/"
        f"year={now.year}/month={now.month:02d}/day={now.day:02d}/"
        f"report-{now.strftime('%Y%m%dT%H%M%S')}.json"
    )

    # Store pretty JSON
    s3.put_object(
        Bucket=CENTRAL_BUCKET,
        Key=s3_key,
        Body=json.dumps(log_entry, indent=2) + "\n"
    )

    # Send SNS alert with pretty JSON
    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"SOC2 CC6.1 Result - {compliance_status}",
        Message=json.dumps(log_entry, indent=2)
    )

    return {"status": "ok", "log_entry": log_entry}
