#--------------------------------------------------------------------------------------------------
# Function: GLOBAL-update-s3-bucket-policy-ssl
# Purpose:  Updates S3 bucket policies to enforce TLS encryption
# Inputs:   
#
#    {
#      "view_only": "true|false",
#      "regions": ["us-east-1", ...]
#    }
#
#    Leave the regions sections blank to apply to all regions
#
#--------------------------------------------------------------------------------------------------

import json
import boto3
from botocore.exceptions import ClientError
from botocore.exceptions import EndpointConnectionError

sts_client = boto3.client('sts')
organizations_client = boto3.client('organizations')

#--------------------------------------------------------------------------------------------------
# Function handler
#--------------------------------------------------------------------------------------------------
def lambda_handler(event, context):

  # Determine whether the user just wants to view the orphaned logs.
  view_only = ('view_only' in event and event['view_only'].lower() == 'true')

  regions = []

  #--------------------------------------------------
  # Determine which regions to include. Apply to all regions by default.
  #--------------------------------------------------
  if 'regions' in event and type(event['regions']) == list:
      regions = event['regions']

  # Get all regions if not otherwise specified.
  if not regions:
      region_response = boto3.client('ec2').describe_regions()
      regions = [region['RegionName'] for region in region_response['Regions']]


  # Loop through the accounts in the organization.
  response = organizations_client.list_accounts()

  for account in response['Accounts']:

      if account['Status'] == 'ACTIVE':

          print('** In account: {}'.format(account['Id']))

          member_account = sts_client.assume_role(
              RoleArn='arn:aws:iam::{}:role/AWSControlTowerExecution'.format(account['Id']),
              RoleSessionName='delete_logs'
          )

          update_policy(member_account, account['Id'], regions, view_only)

  return


#--------------------------------------------------------------------------------------------------
# Function handler
#--------------------------------------------------------------------------------------------------
def update_policy(member_account, account_id, regions, view_only):

  ACCESS_KEY = member_account['Credentials']['AccessKeyId']
  SECRET_KEY = member_account['Credentials']['SecretAccessKey']
  SESSION_TOKEN = member_account['Credentials']['SessionToken']

  policy = {}
  policy['Id'] = 'CreatedFromGlobalScript'
  policy['Version'] = "2012-10-17"
  policy['Statement'] = []


  #--------------------------------------------------
  # Iterate through the specified regions.
  #--------------------------------------------------
  for region in regions:

      print('REGION: {}'.format(region))

      #--------------------------------------------------
      # Iterate through the buckets and determine whether
      # each has a policy.
      #--------------------------------------------------
      # create service client using the assumed role credentials, e.g. S3
      s3_client = boto3.client(
          's3',
          aws_access_key_id=ACCESS_KEY,
          aws_secret_access_key=SECRET_KEY,
          aws_session_token=SESSION_TOKEN,
          region_name=region
      )

      for bucket in s3_client.list_buckets()['Buckets']:

          policy_statement = {
                "Sid": "AllowSSLRequestsOnly",
                "Action": "s3:*",
                "Effect": "Deny",
                "Resource": [
                  "arn:aws:s3:::" + bucket['Name'],
                  "arn:aws:s3:::" + bucket['Name'] + "/*"
                ],
                "Condition": {
                  "Bool": {
                    "aws:SecureTransport": "false"
                  }
                },
                "Principal": "*"
              }

          bucket_data = {}
          bucket_data['account_id'] = account_id
          bucket_data['bucket_name'] = bucket['Name']

          try:
              response = s3_client.get_bucket_policy(Bucket=bucket['Name'])
              bucket_data['bucket_policy_exists'] = 'Yes'

              existing_policy = json.loads(response['Policy'])

              already_includes_statement = False  
              for statement in existing_policy['Statement']:
                  if statement['Sid'] == 'AllowSSLRequestsOnly':
                      already_includes_statement = True
                      break

              # Add the policy.
              if not already_includes_statement:
                  existing_policy['Statement'].append(policy_statement)

                  response = s3_client.put_bucket_policy(
                      Bucket=bucket['Name'],
                      Policy=json.dumps(existing_policy)
                  )

          except:

              policy['Statement'] = []
              policy['Statement'].append(policy_statement)

              bucket_data['bucket_policy_exists'] = 'No, creating'

              print(json.dumps(policy))

              response = s3_client.put_bucket_policy(
                  Bucket=bucket['Name'],
                  Policy=json.dumps(policy)
              )

          print(json.dumps(bucket_data))

