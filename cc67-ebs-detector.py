import boto3, os, json
from datetime import datetime, timezone, timedelta

# AWS Clients
ec2 = boto3.client('ec2')
sns = boto3.client('sns')
s3 = boto3.client('s3')

# Environment variables
SNS_TOPIC = os.environ['SNS_TOPIC']   # should be set in Lambda configuration
AUDIT_BUCKET = "soc2-audit-logs-central-206299126127"

# Settings
THRESHOLD_DAYS = 0
DELETE_ENABLED = True  # change to False to disable deletion but keep logging

def lambda_handler(event, context):
    threshold_date = datetime.now(timezone.utc) - timedelta(days=THRESHOLD_DAYS)
    deleted_volumes = []

    # Get all unattached (available) volumes
    response = ec2.describe_volumes(Filters=[{"Name": "status", "Values": ["available"]}])

    for vol in response['Volumes']:
        vol_id = vol["VolumeId"]
        create_time = vol["CreateTime"]
        eligible = create_time < threshold_date  # check age

        # Prepare log entry
        entry = {
            "VolumeId": vol_id,
            "Size": vol["Size"],
            "AZ": vol["AvailabilityZone"],
            "CreateTime": create_time.isoformat(),
            "Tags": vol.get("Tags", []),
            "EligibleForDeletion": eligible
        }

        if eligible:
            try:
                if DELETE_ENABLED:
                    ec2.delete_volume(VolumeId=vol_id)
                    entry["Action"] = "Deleted"
                else:
                    entry["Action"] = "WouldDelete"
            except Exception as e:
                entry["Action"] = "Error"
                entry["Error"] = str(e)

        else:
            entry["Action"] = "Skipped"

        deleted_volumes.append(entry)

    # If we did something, send notification and save logs
    if deleted_volumes:
        message = (
            f"🧹 SOC 2 CC6.7: Processed {len(deleted_volumes)} unattached EBS volumes "
            f"(older than {THRESHOLD_DAYS} days are deleted):\n\n"
            + json.dumps(deleted_volumes, indent=2)
        )

        # SNS notification
        sns.publish(
            TopicArn=SNS_TOPIC,
            Subject=f"SOC2 CC6.7: {len(deleted_volumes)} EBS Volumes Processed",
            Message=message
        )

        # Save logs in S3
        filename = f"audit_reports/cc6.7-ebs-deleted/deleted-{datetime.utcnow().strftime('%Y-%m-%dT%H-%M-%SZ')}.json"
        s3.put_object(
            Bucket=AUDIT_BUCKET,
            Key=filename,
            Body=json.dumps(deleted_volumes, indent=2),
            ContentType='application/json'
        )

    return {"processed_count": len(deleted_volumes)}
