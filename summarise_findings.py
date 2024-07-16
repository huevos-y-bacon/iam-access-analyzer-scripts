#!/usr/bin/env python3

import json
import argparse
from datetime import datetime
import os

NOW = datetime.now().strftime("%Y%m%d-%H%M")
TRIMMED = True # Set to True to exclude metadata (get_all_findings.py)
MAX_LEN = 20 # Max title length
DEBUG = False


def main(filename):
    fn = "Filename"
    print(f"{fn.ljust(MAX_LEN)}   : {filename}")

    # Open json file for reading
    with open(filename, 'r') as file:
        data = json.load(file)

    findings_qty = len(data)
    tf = "Total findings"
    print(f"{tf.ljust(MAX_LEN)}   : {findings_qty}")

    # External
    by_external(data)

    # Public
    by_public(data)

    # By owner
    by_owner(data)

    # By principal
    by_principal(data)

    # Per status
    statuses = ['ACTIVE', 'ARCHIVED', 'RESOLVED']
    sstatus_title = "\nStatus"
    print(f"{sstatus_title}:")
    status_types = []
    for status in statuses:
        r = by_status(data, status) # if status != None else None
        # print(r)
        status_types.append({"status": r[0], "len_status": r[1]})
    # Sort status_types by len_status
    status_types = sorted(status_types, key=lambda x: x['len_status'], reverse=True)

    for status_type in status_types:
        status = status_type['status']
        len_status = status_type['len_status']
        print(f"  {status.ljust(MAX_LEN)} : {len_status}")

    # By resource type
    resource_types = ["AWS::S3::Bucket", "AWS::IAM::Role", "AWS::SQS::Queue", "AWS::Lambda::Function", "AWS::Lambda::LayerVersion", "AWS::KMS::Key", "AWS::SecretsManager::Secret", "AWS::EFS::FileSystem", "AWS::EC2::Snapshot", "AWS::ECR::Repository", "AWS::RDS::DBSnapshot", "AWS::RDS::DBClusterSnapshot", "AWS::SNS::Topic", "AWS::S3Express::DirectoryBucket", "AWS::DynamoDB::Table", "AWS::DynamoDB::Stream"]

    r_types = []
    for r_type in resource_types:
        response = by_resource_type(data, r_type) #if resource_type else None
        len_resource_type_list = response[0]
        resource_type = response[1]
        len_resource_type = response[2]
        r_types.append({"resource_type": resource_type, "len_resource_type" : len_resource_type})

    urt = "\nResource Types"
    print(f"{urt.ljust(MAX_LEN)}    : {len_resource_type_list}")

    # Sort r_types by len_resource_type
    r_types = sorted(r_types, key=lambda x: x['len_resource_type'], reverse=True)
    # Remove empty resource types
    r_types = [r_type for r_type in r_types if r_type['len_resource_type'] > 0]
    for r_type in r_types:
        print(f"  {r_type['resource_type'].ljust(MAX_LEN)} : {r_type['len_resource_type']}")


def d_print(message):
    print(f"DEBUG: {message}") if DEBUG else None


def by_public(data):
    findings_details = []
    for finding in data:
        finding = finding['finding'] if not TRIMMED else finding
        try:
            if finding['findingDetails'][0]['externalAccessDetails']['isPublic']:
                findings_details.append(finding)
        except:
            pass
    len_public = len(findings_details)
    pf = "Public findings"
    print(f"{pf.ljust(MAX_LEN)}   : {len_public}")


def by_external(data):
    findings_details = []
    for finding in data:
        finding = finding['finding'] if not TRIMMED else finding
        try:
            if finding['findingType'] == 'ExternalAccess':
                findings_details.append(finding)
        except:
            pass
    len_external = len(findings_details)
    pf = "External Access"
    print(f"{pf.ljust(MAX_LEN)}   : {len_external}")


def by_status(data, status):
    findings_details = []
    for finding in data:
        finding = finding['finding'] if not TRIMMED else finding
        if finding['status'] == status:
            findings_details.append(finding)
    len_status = len(findings_details)
    return status, len_status


def by_owner(data):
    findings_details = []
    owner_list = []
    for finding in data:
        finding = finding['finding'] if not TRIMMED else finding
        owner_value = finding['resourceOwnerAccount']
        owner_list.append(owner_value)
        findings_details.append(finding)
    owner_list = list(set(owner_list))
    len_owner_list = len(owner_list)

    uo = "Unique owners"
    print(f"{uo.ljust(MAX_LEN)}   : {len_owner_list}")


def by_principal(data):
    findings_details = []
    principal_list = []
    for finding in data:
        finding = finding['finding'] if not TRIMMED else finding
        p = None
        p_value = None
        try:
            p = finding['principal']
        except:
            pass
        try:
            p_value = p['AWS']
            key = "aws"
        except:
            pass
        try:
            p_value = p['Federated']
            key = "federated"
        except:
            pass
        principal_list.append(p_value)
        findings_details.append(finding)
    principal_list = list(set(principal_list))
    len_principal_list = len(principal_list)
    up = "Unique principals"
    print(f"{up.ljust(MAX_LEN)}   : {len_principal_list}")
    len_principal = len(findings_details)


def by_resource_type(data, resource_type):
    findings_details = []
    resource_type_list = []
    for finding in data:
        finding = finding['finding'] if not TRIMMED else finding
        resource_type_value = finding['resourceType']
        resource_type_list.append(resource_type_value)
        # print(resource_type_value)
        if resource_type_value == resource_type:
            findings_details.append(finding)
    resource_type_list = list(set(resource_type_list))
    len_resource_type_list = len(resource_type_list)
    len_resource_type = len(findings_details)
    
    return len_resource_type_list, resource_type, len_resource_type


def usage(message):
    print(message)
    print("Usage: python analyse_access.py -f <filename>; or set the FINDINGS_FILE env var")
    exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Process some variables.')
    parser.add_argument( '-f', dest='filename', help='The filename to use') 
    args = parser.parse_args()

    # Unset env vars - read from .env file
    os.environ.pop('DEBUG', None)
    os.environ.pop('FINDINGS_FILE', None)

    # Load dotenv
    from dotenv import load_dotenv
    load_dotenv()

    # If DEBUG not set in env, use the default value
    DEBUG = bool(os.getenv("DEBUG")) if os.getenv("DEBUG") != None else DEBUG
    d_print(f"DEBUG {DEBUG}, {type(DEBUG)}")

    if args.filename != None:
        filename = args.filename
    elif bool(os.getenv("FINDINGS_FILE")) != None:
        filename = os.getenv("FINDINGS_FILE")
    else:
        usage("No filename provided")

    main(filename)
