import boto3, json, os
from datetime import datetime

iam = boto3.client('iam')
sns = boto3.client('sns')
s3 = boto3.client('s3')

SNS_TOPIC_ARN = os.environ['SNS_TOPIC_ARN']
GROUP_NAME = os.environ['GROUP_NAME']

S3_BUCKET = "soc2-audit-logs-central-206299126127"
S3_PREFIX = "audit_reports/cc6-3/"

def lambda_handler(event, context):
    response = iam.get_group(GroupName=GROUP_NAME)
    users = response['Users']
    violations = []

    for user in users:
        user_name = user['UserName']

        # ----- Check attached managed policies -----
        attached_policies = iam.list_attached_user_policies(UserName=user_name)['AttachedPolicies']
        for policy in attached_policies:
            policy_details = iam.get_policy(PolicyArn=policy['PolicyArn'])
            version = iam.get_policy_version(
                PolicyArn=policy['PolicyArn'],
                VersionId=policy_details['Policy']['DefaultVersionId']
            )
            doc = version['PolicyVersion']['Document']
            statements = doc['Statement'] if isinstance(doc['Statement'], list) else [doc['Statement']]

            for stmt in statements:
                actions = stmt.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                for act in actions:
                    if act in ["iam:*", "ec2:*", "s3:*", "*"] or "PowerUserAccess" in policy['PolicyName']:
                        violations.append({
                            'User': user_name,
                            'Policy': policy['PolicyName'],
                            'Action': act,
                            'DetectedAt': datetime.utcnow().isoformat()
                        })

        # ----- Check inline policies -----
        inline_policy_names = iam.list_user_policies(UserName=user_name)['PolicyNames']
        for policy_name in inline_policy_names:
            inline_policy = iam.get_user_policy(UserName=user_name, PolicyName=policy_name)
            statements = inline_policy['PolicyDocument']['Statement']
            if not isinstance(statements, list):
                statements = [statements]

            for stmt in statements:
                actions = stmt.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                for act in actions:
                    if act in ["iam:*", "ec2:*", "s3:*", "*"]:
                        violations.append({
                            'User': user_name,
                            'Policy': f"{policy_name} (inline)",
                            'Action': act,
                            'DetectedAt': datetime.utcnow().isoformat()
                        })

    # ----- Alert and log violations -----
    if violations:
        message = f"Least Privilege Violations Detected:\n" + json.dumps(violations, indent=2)
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject="SOC2 CC6.3 Violation Detected",
            Message=message
        )

        timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H-%M-%SZ')
        
        # Save pretty-printed JSON array instead of NDJSON
        report_key = f"{S3_PREFIX}report-{timestamp}.json"
        s3.put_object(
            Bucket=S3_BUCKET,
            Key=report_key,
            Body=json.dumps(violations, indent=4),  # <-- pretty print
            ContentType='application/json'
        )

    return {
        'statusCode': 200,
        'body': json.dumps({'violations_found': len(violations)})
    }
