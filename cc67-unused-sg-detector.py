import boto3
import os
import json
from datetime import datetime

# Initialize AWS clients
ec2 = boto3.client('ec2')
sns = boto3.client('sns')
s3 = boto3.client('s3')

# Environment variables
SNS_TOPIC = os.environ['SNS_TOPIC']
AUDIT_BUCKET = "soc2-audit-logs-central-206299126127"

def lambda_handler(event, context):
    # Get all security groups and ENIs
    all_sgs = ec2.describe_security_groups()['SecurityGroups']
    all_eni = ec2.describe_network_interfaces()['NetworkInterfaces']

    # Build set of all attached SGs
    attached_sgs = set()
    for eni in all_eni:
        for sg in eni['Groups']:
            attached_sgs.add(sg['GroupId'])

    # Find unused security groups (excluding 'default' and SOC2Protected)
    unused_sgs = []
    for sg in all_sgs:
        if (
            sg['GroupId'] not in attached_sgs and
            sg['GroupName'] != 'default' and
            not any(tag.get('Key') == 'SOC2Protected' and tag.get('Value') == 'true' for tag in sg.get('Tags', []))
        ):
            unused_sgs.append({
                "GroupId": sg['GroupId'],
                "GroupName": sg['GroupName'],
                "Description": sg['Description'],
                "VpcId": sg.get('VpcId'),
                "Tags": sg.get('Tags', [])
            })

    # If any unused SGs detected, send notification and log to S3
    if unused_sgs:
        message = (
            f"🧹 SOC 2 CC6.7: Detected {len(unused_sgs)} unused Security Groups:\n\n"
            + json.dumps(unused_sgs, indent=2)
        )

        # Publish to SNS
        sns.publish(
            TopicArn=SNS_TOPIC,
            Subject="SOC2 CC6.7 - Unused Security Groups",
            Message=message
        )

        # Write report to S3 inside audit_reports/cc6.7-sgs/ folder
        filename = f"audit_reports/cc6.7-sgs/report-{datetime.utcnow().strftime('%Y-%m-%dT%H-%M-%SZ')}.json"
        s3.put_object(
            Bucket=AUDIT_BUCKET,
            Key=filename,
            Body=json.dumps(unused_sgs, indent=2),
            ContentType='application/json'
        )

    return {"unused_count": len(unused_sgs)}
