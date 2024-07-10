import boto3
from datetime import datetime, timezone

# Initialize the IAM and CloudTrail clients
iam_client = boto3.client('iam')
cloudtrail_client = boto3.client('cloudtrail')

# Define the IAM username
username = 'your-iam-username'

# List all access keys for the IAM user
access_keys = iam_client.list_access_keys(UserName=username)['AccessKeyMetadata']

# Print the creation date, last used date, and services accessed by each access key
for access_key in access_keys:
    access_key_id = access_key['AccessKeyId']
    create_date = access_key['CreateDate']
    age_in_days = (datetime.now(timezone.utc) - create_date).days

    # Get the last used date
    last_used_info = iam_client.get_access_key_last_used(AccessKeyId=access_key_id)
    last_used_date = last_used_info['AccessKeyLastUsed'].get('LastUsedDate', 'Never')

    print(f"Access Key ID: {access_key_id}")
    print(f"  Created: {create_date} ({age_in_days} days old)")
    print(f"  Last Used: {last_used_date}")

    # Get the CloudTrail events for the access key
    events = cloudtrail_client.lookup_events(
        LookupAttributes=[
            {
                'AttributeKey': 'AccessKeyId',
                'AttributeValue': access_key_id
            },
        ],
        StartTime=create_date,
        EndTime=datetime.now(timezone.utc)
    )['Events']

    # Extract the services accessed from the events
    services_accessed = set()
    for event in events:
        event_name = event['EventName']
        event_source = event['EventSource']
        service_name = event_source.split('.')[0]
        services_accessed.add(service_name)

    print(f"  Services Accessed: {', '.join(services_accessed) if services_accessed else 'None'}")
