import boto3
from datetime import datetime, timezone

# Initialize a session using Boto3
iam = boto3.client('iam')
cloudtrail = boto3.client('cloudtrail')

# Define the age threshold in days
threshold_days = 90

# Get the list of all IAM users
users = iam.list_users()

# Iterate over each user
for user in users['Users']:
    username = user['UserName']
    print(f"Access keys for user: {username}")

    # Get the access keys for the user
    keys = iam.list_access_keys(UserName=username)

    # Iterate over each key and calculate its age
    for key in keys['AccessKeyMetadata']:
        key_id = key['AccessKeyId']
        create_date = key['CreateDate']
        
        # Calculate the age of the key in days
        key_age_days = (datetime.now(timezone.utc) - create_date).days

        # Check if the key is older than the threshold
        if key_age_days > threshold_days:
            print(f"  AccessKeyId: {key_id}, Created: {create_date}, Age (days): {key_age_days}")

            # Query CloudTrail to see what services the access key has used
            lookup_attrs = [{'AttributeKey': 'AccessKeyId', 'AttributeValue': key_id}]
            events = cloudtrail.lookup_events(LookupAttributes=lookup_attrs)

            # Create a set to hold unique services
            services_used = set()
            
            # Iterate over CloudTrail events to find services used
            for event in events['Events']:
                event_name = event['EventName']
                event_source = event['EventSource']
                services_used.add(event_source.split('.')[0])

            if services_used:
                print(f"    Services used by this access key: {', '.join(services_used)}")
            else:
                print("    No services used by this access key found in CloudTrail")

    print("")
