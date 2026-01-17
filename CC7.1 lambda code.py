import json
import boto3
import os
from datetime import datetime

sns_client = boto3.client('sns')
s3_client = boto3.client('s3')

# Use environment variables (best practice)
SNS_TOPIC_ARN = os.environ['SNS_TOPIC_ARN']
# Hardcode central bucket name since you want a single central repo
CENTRAL_BUCKET = "soc2-audit-logs-central-206299126127"

def lambda_handler(event, context):
    # Log raw event for debugging
    print("Event:", json.dumps(event))

    detail = event['detail']

    # Extract main details
    finding_id = detail.get('id')
    title = detail.get('title', 'No title')
    severity = detail.get('severity', 'Unknown')
    finding_type = detail.get('type', 'Unknown')
    description = detail.get('description', 'No description')
    account_id = detail.get('accountId', 'Unknown')
    region = detail.get('region', 'Unknown')

    # Prepare SNS message
    sns_message = (
        f"🚨 GuardDuty Finding 🚨\n"
        f"Title: {title}\n"
        f"Severity: {severity}\n"
        f"Type: {finding_type}\n"
        f"Account: {account_id}\n"
        f"Region: {region}\n"
        f"Description: {description}\n"
        f"Finding ID: {finding_id}"
    )

    # Publish to SNS
    sns_client.publish(
        TopicArn=SNS_TOPIC_ARN,
        Message=sns_message,
        Subject=f"GuardDuty Alert - Severity {severity}"
    )

    # Save full finding to S3 (central audit bucket → audit_reports folder)
    timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H-%M-%SZ')
    s3_key = f"audit_reports/cc7.1-guardduty-findings/{timestamp}_{finding_id}.json"

    s3_client.put_object(
        Bucket=CENTRAL_BUCKET,
        Key=s3_key,
        Body=json.dumps(detail, indent=2),
        ContentType='application/json'
    )

    return {"statusCode": 200, "body": "Processed successfully"}