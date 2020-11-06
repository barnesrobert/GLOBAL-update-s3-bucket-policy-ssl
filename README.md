# GLOBAL-update-s3-bucket-policy-ssl

This script is intended to be created as a Lamdbda function executed from an AWS Organization root account. It requires the following permissions:

sts:AssumeRole
organizations:ListAccounts
s3:ListBuckets
s3:GetBucketPolicy
s3:PutBucketPolicy
