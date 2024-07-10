import boto3
import csv
import time

# Initialize a boto3 client for Support
client = boto3.client('support')

# Get all Trusted Advisor checks
checks = client.describe_trusted_advisor_checks(language='en')
check_ids = [check['id'] for check in checks['checks']]

# Perform a Trusted Advisor check refresh
for check_id in check_ids:
    response = client.refresh_trusted_advisor_check(checkId=check_id)
    print(f"Refresh status for check {check_id}: {response['status']}")

# Wait for checks to complete
time.sleep(30)

# Retrieve check results
results = []
for check_id in check_ids:
    response = client.describe_trusted_advisor_check_result(checkId=check_id)
    result = response['result']
    for resource in result['flaggedResources']:
        results.append({
            'CheckId': check_id,
            'CheckName': checks['checks'][check_ids.index(check_id)]['name'],
            'ResourceId': resource['resourceId'],
            'Status': resource['status'],
            'Region': resource['metadata'][0] if resource['metadata'] else 'N/A',
            'Details': resource['metadata']
        })

# Define the CSV file name
csv_file_name = 'trusted_advisor_checks.csv'

# Write results to CSV
with open(csv_file_name, 'w', newline='') as csvfile:
    fieldnames = ['CheckId', 'CheckName', 'ResourceId', 'Status', 'Region', 'Details']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

    writer.writeheader()
    for result in results:
        writer.writerow(result)

print(f"Results written to {csv_file_name}")
