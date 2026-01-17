import boto3, json, datetime, os

s3 = boto3.client('s3')
sns = boto3.client('sns')

BUCKET = "soc2-audit-logs-central-206299126127"
SNS_TOPIC = "arn:aws:sns:us-east-1:206299126127:SOC2Automation"

def lambda_handler(event, context):
    findings = []
    findings.append({
        "control": "CC9.2",
        "type": "encryption-at-rest",
        "resource": "s3://example-unencrypted-bucket",
        "status": "NON_COMPLIANT",
        "timestamp": datetime.datetime.utcnow().isoformat()
    })

    # Save to S3
    key = f"audit_reports/cc9.2_at_rest/finding-{datetime.datetime.utcnow().isoformat()}.json"
    s3.put_object(
        Bucket=BUCKET,
        Key=key,
        Body=json.dumps(findings, indent=2).encode("utf-8")
    )

    # Send SNS
    sns.publish(
        TopicArn=SNS_TOPIC,
        Subject="CC9.2 At Rest Finding",
        Message=json.dumps(findings, indent=2)
    )

    return {"status": "done", "findings": findings}
