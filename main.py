import boto3
import json
import time
from botocore.exceptions import ClientError

def get_user_input():
    """Collect user input for CloudTrail setup"""
    print("AWS CloudTrail Centralized Logging Setup\n")
    
    inputs = {
        'management_account_id': input("Enter the management account ID: ").strip(),
        'region': input("Enter the AWS region to use (e.g., us-east-1): ").strip(),
        'member_accounts': input("Enter member account IDs (comma separated): ").replace(" ", "").split(','),
        'trail_name': input("Enter the CloudTrail name (e.g., CentralizedLogging): ").strip(),
        'bucket_name': input("Enter the S3 bucket name for logs (must be globally unique): ").strip(),
        'enable_log_validation': input("Enable log file validation? (yes/no): ").strip().lower() == 'yes',
        'enable_sns_notification': input("Enable SNS notifications? (yes/no): ").strip().lower() == 'yes',
        'enable_kms_encryption': input("Enable KMS encryption? (yes/no): ").strip().lower() == 'yes',
        'enable_data_events': input("Enable data events logging? (yes/no): ").strip().lower() == 'yes',
        'enable_insights_events': input("Enable insights events? (yes/no): ").strip().lower() == 'yes',
    }
    
    if inputs['enable_kms_encryption']:
        inputs['kms_key_alias'] = input("Enter KMS key alias (e.g., cloudtrail-key): ").strip()
    
    if inputs['enable_sns_notification']:
        inputs['sns_topic_name'] = input("Enter SNS topic name for notifications: ").strip()
    
    return inputs

def create_cloudtrail_bucket(boto3_session, bucket_name, region):
    """Create the S3 bucket for CloudTrail logs"""
    s3 = boto3_session.client('s3')
    
    try:
        if region == 'us-east-1':
            s3.create_bucket(Bucket=bucket_name)
        else:
            s3.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={'LocationConstraint': region}
            )
        
        # Wait for bucket to be created
        waiter = s3.get_waiter('bucket_exists')
        waiter.wait(Bucket=bucket_name)
        print(f"Created S3 bucket: {bucket_name}")
        
        # Enable bucket versioning
        s3.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={'Status': 'Enabled'}
        )
        
        # Apply default encryption (SSE-S3)
        s3.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                'Rules': [
                    {
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'AES256'
                        }
                    }
                ]
            }
        )
        
        return True
    except ClientError as e:
        if e.response['Error']['Code'] == 'BucketAlreadyExists':
            print(f"Bucket {bucket_name} already exists. Using existing bucket.")
            return True
        else:
            print(f"Error creating bucket: {e}")
            return False

def update_bucket_policy(boto3_session, bucket_name, management_account_id, member_accounts):
    """Update the bucket policy to allow CloudTrail from all accounts"""
    s3 = boto3_session.client('s3')
    
    # Build the resource ARNs for all accounts
    resource_arns = [f"arn:aws:s3:::{bucket_name}/AWSLogs/{management_account_id}/*"]
    resource_arns.extend([f"arn:aws:s3:::{bucket_name}/AWSLogs/{account_id}/*" for account_id in member_accounts])
    
    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck20131101",
                "Effect": "Allow",
                "Principal": {
                    "Service": "cloudtrail.amazonaws.com"
                },
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket_name}"
            },
            {
                "Sid": "AWSCloudTrailWrite20131101",
                "Effect": "Allow",
                "Principal": {
                    "Service": "cloudtrail.amazonaws.com"
                },
                "Action": "s3:PutObject",
                "Resource": resource_arns,
                "Condition": {
                    "StringEquals": {
                        "s3:x-amz-acl": "bucket-owner-full-control"
                    }
                }
            }
        ]
    }
    
    try:
        s3.put_bucket_policy(
            Bucket=bucket_name,
            Policy=json.dumps(bucket_policy)
        )
        print("Updated bucket policy to allow CloudTrail from all accounts")
        return True
    except ClientError as e:
        print(f"Error updating bucket policy: {e}")
        return False

def create_kms_key(boto3_session, key_alias, account_id, region):
    """Create KMS key for CloudTrail encryption"""
    kms = boto3_session.client('kms', region_name=region)
    
    try:
        # Create the key
        response = kms.create_key(
            Description='Key for CloudTrail log encryption',
            KeyUsage='ENCRYPT_DECRYPT',
            Origin='AWS_KMS',
            BypassPolicyLockoutSafetyCheck=False
        )
        key_id = response['KeyMetadata']['KeyId']
        
        # Create alias
        kms.create_alias(
            AliasName=f'alias/{key_alias}',
            TargetKeyId=key_id
        )
        
        # Update key policy
        key_policy = {
            "Version": "2012-10-17",
            "Id": "KeyPolicyCreatedForCloudTrail",
            "Statement": [
                {
                    "Sid": "Enable IAM User Permissions",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": f"arn:aws:iam::{account_id}:root"
                    },
                    "Action": "kms:*",
                    "Resource": "*"
                },
                {
                    "Sid": "Allow CloudTrail to encrypt logs",
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "cloudtrail.amazonaws.com"
                    },
                    "Action": "kms:GenerateDataKey*",
                    "Resource": "*",
                    "Condition": {
                        "StringLike": {
                            "kms:EncryptionContext:aws:cloudtrail:arn": f"arn:aws:cloudtrail:*:{account_id}:trail/*"
                        }
                    }
                },
                {
                    "Sid": "Allow CloudTrail to describe key",
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "cloudtrail.amazonaws.com"
                    },
                    "Action": "kms:DescribeKey",
                    "Resource": "*"
                },
                {
                    "Sid": "Allow S3 to use the key",
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "s3.amazonaws.com"
                    },
                    "Action": [
                        "kms:GenerateDataKey",
                        "kms:Decrypt"
                    ],
                    "Resource": "*"
                }
            ]
        }
        
        kms.put_key_policy(
            KeyId=key_id,
            PolicyName='default',
            Policy=json.dumps(key_policy)
        )
        
        print(f"Created KMS key with alias: {key_alias} in region {region}")
        return key_id
    except ClientError as e:
        print(f"Error creating KMS key: {e}")
        return None

def create_sns_topic(boto3_session, topic_name, region):
    """Create SNS topic for CloudTrail notifications"""
    sns = boto3_session.client('sns', region_name=region)
    
    try:
        response = sns.create_topic(Name=topic_name)
        topic_arn = response['TopicArn']
        print(f"Created SNS topic: {topic_name}")
        return topic_arn
    except ClientError as e:
        print(f"Error creating SNS topic: {e}")
        return None

def create_cloudtrail(boto3_session, trail_name, bucket_name, region, is_organization_trail=False, 
                      kms_key_id=None, sns_topic_arn=None, enable_log_validation=False, 
                      enable_data_events=False, enable_insights_events=False):
    """Create or update a CloudTrail"""
    cloudtrail = boto3_session.client('cloudtrail', region_name=region)
    
    trail_params = {
        'Name': trail_name,
        'S3BucketName': bucket_name,
        'IncludeGlobalServiceEvents': True,
        'IsMultiRegionTrail': True,
        'EnableLogFileValidation': enable_log_validation,
        'IsOrganizationTrail': is_organization_trail
    }
    
    if kms_key_id:
        if not kms_key_id.startswith('arn:aws:kms:'):
            account_id = boto3_session.client('sts').get_caller_identity()['Account']
            kms_key_id = f"arn:aws:kms:{region}:{account_id}:key/{kms_key_id}"
        trail_params['KmsKeyId'] = kms_key_id
    
    if sns_topic_arn:
        trail_params['SnsTopicName'] = sns_topic_arn
    
    try:
        # Check if trail exists
        trails = cloudtrail.describe_trails()['trailList']
        existing_trail = next((t for t in trails if t['Name'] == trail_name), None)
        
        if existing_trail:
            print(f"Updating existing CloudTrail: {trail_name}")
            response = cloudtrail.update_trail(**trail_params)
        else:
            print(f"Creating new CloudTrail: {trail_name}")
            response = cloudtrail.create_trail(**trail_params)
        
        # Start logging
        cloudtrail.start_logging(Name=trail_name)
        print(f"Started logging for CloudTrail: {trail_name}")
        
        # Configure event selectors
        event_selectors = []
        
        # Management events selector
        management_selector = {
            'ReadWriteType': 'All',
            'IncludeManagementEvents': True,
            'ExcludeManagementEventSources': []
        }
        
        # Data events selector (if enabled)
        if enable_data_events:
            data_selector = {
                'ReadWriteType': 'All',
                'DataResources': [{
                    'Type': 'AWS::S3::Object',
                    'Values': ['arn:aws:s3:::']  # Correct format for all S3 buckets
                }]
            }
            event_selectors.append(data_selector)
        
        # Always include management events
        event_selectors.append(management_selector)
        
        # Put event selectors
        cloudtrail.put_event_selectors(
            TrailName=trail_name,
            EventSelectors=event_selectors
        )
        
        # Configure insights events if enabled
        if enable_insights_events:
            cloudtrail.put_insight_selectors(
                TrailName=trail_name,
                InsightSelectors=[{'InsightType': 'ApiCallRateInsight'}]
            )
        
        return True
    except ClientError as e:
        print(f"Error creating/updating CloudTrail: {e}")
        return False

def assume_role(account_id, role_name, region):
    """Assume role in target account"""
    sts_client = boto3.client('sts')
    
    try:
        response = sts_client.assume_role(
            RoleArn=f"arn:aws:iam::{account_id}:role/{role_name}",
            RoleSessionName="CloudTrailSetupSession"
        )
        
        return boto3.Session(
            aws_access_key_id=response['Credentials']['AccessKeyId'],
            aws_secret_access_key=response['Credentials']['SecretAccessKey'],
            aws_session_token=response['Credentials']['SessionToken'],
            region_name=region
        )
    except ClientError as e:
        print(f"Error assuming role in account {account_id}: {e}")
        return None

def setup_member_account(account_id, inputs, management_session):
    """Configure a member account for centralized logging"""
    print(f"\nSetting up member account: {account_id}")
    
    # Assume role in member account
    member_session = assume_role(account_id, 'OrganizationAccountAccessRole', inputs['region'])
    if not member_session:
        print(f"Failed to assume role in account {account_id}")
        return False
    
    # Create KMS key in member account if encryption is enabled
    kms_key_id = None
    if inputs['enable_kms_encryption']:
        kms_key_id = create_kms_key(
            member_session,
            inputs['kms_key_alias'],
            account_id,
            inputs['region']
        )
        if not kms_key_id:
            print("Failed to create KMS key in member account")
            return False
    
    # Create CloudTrail in member account
    success = create_cloudtrail(
        member_session,
        inputs['trail_name'],
        inputs['bucket_name'],
        inputs['region'],
        is_organization_trail=False,
        kms_key_id=kms_key_id,
        sns_topic_arn=None,
        enable_log_validation=inputs['enable_log_validation'],
        enable_data_events=inputs['enable_data_events'],
        enable_insights_events=inputs['enable_insights_events']
    )
    
    if success:
        print(f"Successfully configured CloudTrail in account {account_id}")
    else:
        print(f"Failed to configure CloudTrail in account {account_id}")
    
    return success

def main():
    # Initialize boto3 session
    session = boto3.Session()
    
    # Get user input
    inputs = get_user_input()
    
    # Step 1: Create S3 bucket in management account
    if not create_cloudtrail_bucket(session, inputs['bucket_name'], inputs['region']):
        print("Failed to create S3 bucket. Exiting.")
        return
    
    # Step 2: Update bucket policy
    if not update_bucket_policy(session, inputs['bucket_name'], inputs['management_account_id'], inputs['member_accounts']):
        print("Failed to update bucket policy. Exiting.")
        return
    
    # Step 3: Create KMS key in management account if encryption is enabled
    kms_key_id = None
    if inputs['enable_kms_encryption']:
        kms_key_id = create_kms_key(
            session,
            inputs['kms_key_alias'],
            inputs['management_account_id'],
            inputs['region']
        )
        if not kms_key_id:
            print("Failed to create KMS key. Continuing without encryption.")
            inputs['enable_kms_encryption'] = False
    
    # Step 4: Create SNS topic if notifications are enabled
    sns_topic_arn = None
    if inputs['enable_sns_notification']:
        sns_topic_arn = create_sns_topic(session, inputs['sns_topic_name'], inputs['region'])
        if not sns_topic_arn:
            print("Failed to create SNS topic. Continuing without notifications.")
            inputs['enable_sns_notification'] = False
    
    # Step 5: Create CloudTrail in management account
    if not create_cloudtrail(
        session,
        inputs['trail_name'],
        inputs['bucket_name'],
        inputs['region'],
        is_organization_trail=False,
        kms_key_id=kms_key_id,
        sns_topic_arn=sns_topic_arn,
        enable_log_validation=inputs['enable_log_validation'],
        enable_data_events=inputs['enable_data_events'],
        enable_insights_events=inputs['enable_insights_events']
    ):
        print("Failed to create CloudTrail in management account. Exiting.")
        return
    
    # Step 6: Configure member accounts
    for account_id in inputs['member_accounts']:
        setup_member_account(account_id, inputs, session)
    
    print("\nCloudTrail centralized logging setup complete!")

if __name__ == "__main__":
    main()