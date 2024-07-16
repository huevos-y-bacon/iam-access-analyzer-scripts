#!/usr/bin/env python3

import json
import boto3
import botocore
import argparse
from datetime import datetime
import os
import time

NOW = datetime.now().strftime("%Y%m%d-%H%M")
DEBUG = False

accessanalyzer = boto3.client('accessanalyzer')


def main(arn,limit):
    if not arn.startswith("arn:aws:access-analyzer:"):
        print("No valid ARN provided")
        usage()
        exit(1)

    account_id = arn.split(":")[4]
    analyzer = arn.split("/")[1]

    d_print(f"Account ID: {account_id}")
    d_print(f"Analyzer:   {analyzer}")

    suffix = ""
    results_file_path = f"{NOW}-{account_id}-{analyzer}{suffix}.details.json"

    d_print(f"results_file_path: {results_file_path}")

    print (f"Getting all findings for {analyzer} (account {account_id})\n")
    # print("-"*80)

    data = list_all_findings(arn)

    total_findings = len(data['findings'])
    print(f"Total findings:    {total_findings}")

    # Iterate over the full findings, storing the results in the list
    full_findings_list = []    
    for finding in data['findings']:
        full_findings_list.append(finding['id'])

    full_findings_details = []
    full_findings_list_len = len(full_findings_list)
    limit = full_findings_list_len if limit == "None" else int(limit)

    position = 0
    for finding_id in full_findings_list:
        position += 1

        # Print progress over the same line
        print(f"Getting finding {position} of {full_findings_list_len}\r", end="") # \r is carriage return, end="" to avoid newline

        try:
            result = accessanalyzer.get_finding_v2(id=finding_id, analyzerArn=arn)
        except botocore.exceptions.ClientError as e:
            print(f"Error at position {position}: {e}")
            # print(f"Too many requests at position {position}")
            print("Waiting 10 seconds and trying again")
            time.sleep(10)
            try:
                result = accessanalyzer.get_finding_v2(id=finding_id, analyzerArn=arn)
            except botocore.exceptions.ClientError as e:
                print(f"Error at position {position}: {e}")
                # print(f"Too many requests at position {position}, breaking")
                break
        full_findings_details.append(result)

        # if counter at position limit, exit
        if position == limit and limit != full_findings_list_len:
            print(f"\nBreaking at {limit}\n")        
            break

    write_results(full_findings_details, results_file_path)

def list_all_findings(arn):
    # List all findings, with pagination
    findings = accessanalyzer.list_findings(analyzerArn=arn)
    next_token = findings.get("nextToken")
    while next_token:
        next_page = accessanalyzer.list_findings(analyzerArn=arn, nextToken=next_token)
        findings["findings"] += next_page["findings"]
        next_token = next_page.get("nextToken")
    return findings

def write_results(findings_details, results_file_path):
    trimmed = True # set to False to include ResponseMetadata
    findings_details = trim_response_metadata(findings_details) if trimmed else findings_details

    findings_details_json = json.dumps(findings_details, indent=4, default=str)
    output_file = open(results_file_path, "w")
    output_file.write(findings_details_json)
    output_file.close()
    print(f"Results written to {results_file_path}")

def usage():
    print()
    print("Usage: python get_findings_details.py --arn <arn> --resource_type <resource_type> --status <status> --limit <limit>")
    print()
    print("    --arn:  ** REQUIRED ** The ARN of the analyzer to use")
    print("    --resource_type: The resource type to filter by (e.g. 'AWS::S3::Bucket')")
    print("    --status: The status to filter by (e.g. 'ACTIVE')")
    print("    --limit: The limit to use (e.g. 20, default=no limit)")
    print()
    print("Possible values for resource_type:")
    print("    AWS::S3::Bucket, AWS::IAM::Role, AWS::SQS::Queue, AWS::Lambda::Function, AWS::Lambda::LayerVersion, ")
    print("    AWS::KMS::Key, AWS::SecretsManager::Secret, AWS::EFS::FileSystem, AWS::EC2::Snapshot, AWS::ECR::Repository, ")
    print("    AWS::RDS::DBSnapshot, AWS::RDS::DBClusterSnapshot, AWS::SNS::Topic, AWS::S3Express::DirectoryBucket, ")
    print("    AWS::DynamoDB::Table, AWS::DynamoDB::Stream")
    print()
    print("Possible values for status:\n    ACTIVE, ARCHIVED, RESOLVED")
    # print("Possible source:\n POLICY, BUCKET_ACL, S3_ACCESS_POINT, S3_ACCESS_POINT_ACCOUNT")
    print()

def trim_response_metadata(findings_details):
    for key in findings_details:
        if "ResponseMetadata" in key:
            del key["ResponseMetadata"]
    
    return findings_details

def d_print(message):
    if DEBUG:
        print(f"DEBUG: {message}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Process some variables.')
    parser.add_argument(
        '--arn',
            dest='arn',
            default='None',
            help='The ARN to use (default: None)'
        )
    parser.add_argument(
        '--limit',
            dest='limit',
            default='None',
            help='The limit to use for testing (e.g. 20) (default: "None")'
        )

    args = parser.parse_args()

    # Unset env vars - read only from .env file
    os.environ.pop('DEBUG', None)
    os.environ.pop('ANALYZER_ARN', None)

    # Load dotenv
    from dotenv import load_dotenv
    load_dotenv()

    # if DEBUG not set in env, use the default value
    DEBUG = bool(os.getenv("DEBUG")) if os.getenv("DEBUG") != None else DEBUG
    d_print(f"DEBUG {DEBUG}, {type(DEBUG)}")

    # if no ANALYZER_ARN provided, read ANALYZER_ARN from env
    arn = args.arn if args.arn != "None" else os.getenv("ANALYZER_ARN")
    d_print(f"arn: {arn}")

    main(arn=arn, limit=args.limit)
    