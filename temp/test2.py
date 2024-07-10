import boto3
from datetime import datetime, timezone
import csv

# Initialize the IAM and CloudTrail clients
iam_client = boto3.client('iam')
cloudtrail_client = boto3.client('cloudtrail')

# List all IAM users
users = iam_client.list_users()['Users']

# Create a list to store the results
results = []

# Process each IAM user
for user in users:
    username = user['UserName']
    user_arn = user['Arn']

    # List all access keys for the IAM user
    access_keys = iam_client.list_access_keys(UserName=username)['AccessKeyMetadata']

    # Process each access key
    for access_key in access_keys:
        access_key_id = access_key['AccessKeyId']
        create_date = access_key['CreateDate']
        age_in_days = (datetime.now(timezone.utc) - create_date).days

        # Get the last used date
        last_used_info = iam_client.get_access_key_last_used(AccessKeyId=access_key_id)
        last_used_date = last_used_info['AccessKeyLastUsed'].get('LastUsedDate', 'Never')

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
            event_source = event['EventSource']
            service_name = event_source.split('.')[0]
            services_accessed.add(service_name)

        # Add the details to the results list
        results.append({
            'Username': username,
            'Access Key ID': access_key_id,
            'Created': create_date,
            'Age (days)': age_in_days,
            'Last Used': last_used_date,
            'Services Accessed': ', '.join(services_accessed) if services_accessed else 'None'
        })

# Define the CSV file name
csv_file_name = 'iam_user_access_key_details.csv'

# Write the results to a CSV file
with open(csv_file_name, mode='w', newline='') as csv_file:
    fieldnames = ['Username', 'Access Key ID', 'Created', 'Age (days)', 'Last Used', 'Services Accessed']
    writer = csv.DictWriter(csv_file, fieldnames=fieldnames)

    writer.writeheader()
    for result in results:
        writer.writerow(result)

print(f"Access key details written to {csv_file_name}")
