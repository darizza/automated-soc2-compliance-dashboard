import json
import boto3
import os
from datetime import datetime

sns = boto3.client('sns')
s3 = boto3.client('s3')

# Fixed bucket for SOC 2 audit logs
AUDIT_BUCKET = "soc2-audit-logs-central-206299126127"
# SNS topic from environment variable
SNS_TOPIC = os.environ['SNS_TOPIC']

def lambda_handler(event, context):
    detail = event.get("detail", {})

    if detail.get("eventName") == "RevokeSecurityGroupEgress":
        # Build alert message
        alert_msg = f"""
🚨 SOC 2 CC6.6 ALERT: RevokeSecurityGroupEgress detected

Time: {detail.get('eventTime')}
User: {detail.get('userIdentity', {}).get('arn')}
IP: {detail.get('sourceIPAddress')}
Group ID: {detail.get('requestParameters', {}).get('groupId')}
"""

        # Send SNS alert
        sns.publish(
            TopicArn=SNS_TOPIC,
            Subject="CC6.6 - SG Egress Revoked",
            Message=alert_msg.strip()
        )

        # ✅ Force logs to go into audit_reports/cc6-6/
        filename = (
            f"audit_reports/cc6-6/"
            f"revoke-egress-{datetime.utcnow().strftime('%Y-%m-%dT%H-%M-%SZ')}.json"
        )

        # Save pretty-printed JSON audit report
        s3.put_object(
            Bucket=AUDIT_BUCKET,
            Key=filename,
            Body=json.dumps(event, indent=4),  # pretty JSON
            ContentType='application/json'
        )

        return {
            "status": "OK",
            "message": f"Audit log saved to s3://{AUDIT_BUCKET}/{filename}"
        }

    return {"status": "IGNORED", "reason": "Not a RevokeSecurityGroupEgress event"}
