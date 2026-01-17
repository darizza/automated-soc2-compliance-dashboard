import boto3
import json
import gzip
import os
from datetime import datetime
from urllib.parse import unquote_plus

# Initialize AWS clients
s3 = boto3.client('s3')
sns = boto3.client('sns')

# Get environment variables
SNS_TOPIC = os.environ['SNS_TOPIC']
AUDIT_BUCKET = os.environ['AUDIT_BUCKET']

def lambda_handler(event, context):
    for record in event['Records']:
        bucket = record['s3']['bucket']['name']
        key = unquote_plus(record['s3']['object']['key'])

        # Process only CloudTrail .json.gz files
        if not key.endswith(".json.gz"):
            continue

        # Download and decompress CloudTrail file
        response = s3.get_object(Bucket=bucket, Key=key)
        gzipped = gzip.decompress(response['Body'].read())
        data = json.loads(gzipped)

        matched_events = []
        for event_record in data.get('Records', []):
            if event_record['eventName'] in [
                "AuthorizeSecurityGroupIngress",
                "RevokeSecurityGroupIngress",
                "AuthorizeSecurityGroupEgress",
                "RevokeSecurityGroupEgress",
            ]:
                matched_events.append(event_record)

        if matched_events:
            # Prepare SNS message
            message = (
                f"⚠️ Security Group Change(s) Detected:\n" +
                "\n".join(
                    f"{e['eventName']} by {e['userIdentity'].get('arn', 'Unknown User')}"
                    for e in matched_events
                )
            )

            # Send alert to SNS topic
            sns.publish(
                TopicArn=SNS_TOPIC,
                Subject="SOC2 CC6.6 - Security Group Change",
                Message=message
            )

            # Prepare audit file path inside audit_reports folder
            audit_file = (
                f"audit_reports/cc6.6-sg-changes/"
                f"sg-change-{datetime.utcnow().strftime('%Y-%m-%dT%H-%M-%SZ')}.json"
            )

            # Save matched events to the audit S3 bucket
            s3.put_object(
                Bucket=AUDIT_BUCKET,
                Key=audit_file,
                Body=json.dumps(matched_events, indent=2),
                ContentType='application/json'
            )

    return {"status": "processed"}
