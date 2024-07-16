#!/usr/bin/env python3

import json
import argparse
from datetime import datetime
import os

NOW = datetime.now().strftime("%Y%m%d-%H%M")

TRIMMED = True # Set to True to exclude metadata (get_all_findings.py)
MAX_LEN = 20 # Max title length

INCL_RESOLVED = os.getenv("INCL_RESOLVED", False)
INCL_ARCHIVED = os.getenv("INCL_ARCHIVED", False)


def main(filename):
    incl_resolved = INCL_RESOLVED
    incl_archived = INCL_ARCHIVED

    # Strip extension from filename
    filename_pre = filename.split(".")[0]

    res = "Include resolved"
    print(f"{res.ljust(MAX_LEN)} : {incl_resolved}")

    arc = "Include archived"
    print(f"{arc.ljust(MAX_LEN)} : {incl_archived}")

    fn = "Filename"
    print(f"{fn.ljust(MAX_LEN)} : {filename}")

    # Open json file for reading
    with open(filename, 'r') as file:
        data = json.load(file)

    findings_qty = len(data)
    tf = "\nTotal findings"
    print(f"{tf.ljust(MAX_LEN)}  : {findings_qty}")

    # Public
    response_public = by_public(data,incl_resolved,incl_archived)
    res_suffix = "-incl_resolved" if incl_resolved else ""
    arc_suffix = "-incl_archived" if incl_archived else ""
    file_pre = f"{filename_pre}-PUBLIC"
    results_file_path_prefix = f"{file_pre}{res_suffix}{arc_suffix}"
    process_response(response_public,results_file_path_prefix)

    # External
    response_external = by_external(data,incl_resolved,incl_archived)
    res_suffix = "-incl_resolved" if incl_resolved else ""
    arc_suffix = "-incl_archived" if incl_archived else ""
    file_pre = f"{filename_pre}-EXTERNAL"
    results_file_path_prefix = f"{file_pre}{res_suffix}{arc_suffix}"
    process_response(response_external,results_file_path_prefix)

    # Per status
    statuses = ['ACTIVE', 'ARCHIVED', 'RESOLVED']
    for status in statuses:
        response_by_status = by_status(data, status)
        results_file_path_prefix = f"{filename_pre}-{status.upper()}"
        process_response(response_by_status,results_file_path_prefix)


def by_public(data, incl_resolved, incl_archived):
    findings_details = []
    for finding in data:
        finding = finding['finding'] if not TRIMMED else finding
        try:
            if finding['findingDetails'][0]['externalAccessDetails']['isPublic']:
                if incl_resolved:
                    if incl_archived:
                        findings_details.append(finding)
                    else:
                        if finding['status'] != "ARCHIVED":
                            findings_details.append(finding)
                else:
                    if finding['status'] != "RESOLVED":
                        if incl_archived:
                            findings_details.append(finding)
                        else:
                            if finding['status'] != "ARCHIVED":
                                findings_details.append(finding)
        except:
            pass
    len_public = len(findings_details)
    pf = "\nPublic findings"
    print(f"{pf.ljust(MAX_LEN)}  : {len_public}")
    return findings_details


def by_external(data, incl_resolved, incl_archived):
    findings_details = []
    for finding in data:
        finding = finding['finding'] if not TRIMMED else finding
        try:
            if finding['findingType'] == "ExternalAccess":
                if incl_resolved:
                    if incl_archived:
                        findings_details.append(finding)
                    else:
                        if finding['status'] != "ARCHIVED":
                            findings_details.append(finding)
                else:
                    if finding['status'] != "RESOLVED":
                        if incl_archived:
                            findings_details.append(finding)
                        else:
                            if finding['status'] != "ARCHIVED":
                                findings_details.append(finding)
        except:
            pass
    len_external = len(findings_details)
    pf = "\nExternal findings"
    print(f"{pf.ljust(MAX_LEN)}  : {len_external}")
    return findings_details


def by_status(data, status):
    findings_details = []
    for finding in data:
        finding = finding['finding'] if not TRIMMED else finding
        if finding['status'] == status:
            findings_details.append(finding)
    len_status = len(findings_details)
    sf = f"\n{status} findings"
    print(f"{sf.ljust(MAX_LEN)}  : {len_status}")
    return findings_details


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
    print(f"{uo.ljust(MAX_LEN)} : {len_owner_list}")


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
    print(f"{up.ljust(MAX_LEN)} : {len_principal_list}")
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


def write_results_json(findings_details, results_file_path_prefix):
    '''Output to JSON'''
    results_file = f"{results_file_path_prefix}.json"
    findings_details_json = json.dumps(findings_details, indent=4, default=str)
    output_file = open(results_file, "w")
    output_file.write(findings_details_json)
    output_file.close()
    ext = "  json"
    print(f"{ext.ljust(MAX_LEN)} : {results_file}")


def write_results_csv(findings_details, results_file_path_prefix):
    '''Output to CSV'''
    results_file = f"{results_file_path_prefix}.csv"
    # Define header
    # header = "analyzedAt,createdAt,id,resource,resourceType,resourceOwnerAccount,status,updatedAt,findingDetails,findingType,x_actions,x_principal,x_condition,x_isPublic"
    header = "analyzedAt,createdAt,id,resource,resourceType,resourceOwnerAccount,status,updatedAt,findingDetails,findingType,actions,principal,condition,isPublic"

    # Write data
    with open(results_file, "w") as file:
        file.write(header + "\n")
        for finding in findings_details:
            line = ""
            for key in header.split(","):
                try:
                    # replace commas in values with semicolons
                    line += f"{finding[key].replace(',', ';')},"
                except:
                    line += ","
            
            file.write(line[:-1] + "\n")
    file.close()
    ext = "  csv"
    print(f"{ext.ljust(MAX_LEN)} : {results_file}")


def process_response(response,results_file_path_prefix):
    # Flatten the response somewhat
    for finding in response:
        try:
            finding['findingDetails'] = finding['findingDetails'][0]
        except:
            pass

        # Make actions list a string
        try:
            # finding['x_actions'] = ", ".join(finding['findingDetails']['externalAccessDetails']['action'])
            finding['actions'] = ", ".join(finding['findingDetails']['externalAccessDetails']['action'])
        except:
            # finding['x_actions'] = ""
            finding['actions'] = ""

        # Make principal object key and value a string
        try:
            # finding['x_principal'] = f"{list(finding['findingDetails']['externalAccessDetails']['principal'].keys())[0]}: {list(finding['findingDetails']['externalAccessDetails']['principal'].values())[0]}"
            finding['principal'] = f"{list(finding['findingDetails']['externalAccessDetails']['principal'].keys())[0]}: {list(finding['findingDetails']['externalAccessDetails']['principal'].values())[0]}"
        except:
            # finding['x_principal'] = ""
            finding['principal'] = ""

        # Make condition object key and value a string
        try:
            # finding['x_condition'] = f"{list(finding['findingDetails']['externalAccessDetails']['condition'].keys())[0]}: {list(finding['findingDetails']['externalAccessDetails']['condition'].values())[0]}"
            finding['condition'] = f"{list(finding['findingDetails']['externalAccessDetails']['condition'].keys())[0]}: {list(finding['findingDetails']['externalAccessDetails']['condition'].values())[0]}"
        except:
            # finding['x_condition'] = ""
            finding['condition'] = ""

        # Make isPublic object key and value a string
        try:
            # finding['x_isPublic'] = str(finding['findingDetails']['externalAccessDetails']['isPublic'])
            finding['isPublic'] = str(finding['findingDetails']['externalAccessDetails']['isPublic'])
        except:
            # finding['x_isPublic'] = ""
            finding['isPublic'] = ""

        # Make findingDetails object key and value a string
        try:
            finding['findingDetails'] = f"{list(finding['findingDetails'].keys())[0]}: {list(finding['findingDetails'].values())[0]}"
        except:
            finding['findingDetails'] = ""

    write_results_json(response, results_file_path_prefix)
    write_results_csv(response, results_file_path_prefix)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Process some variables.')
    parser.add_argument( '-f', dest='filename', help='The filename to use') 

    parser.add_argument( '--include-resolved', dest='incl_resolved', help='Included resolved findings', action='store_true') 
    parser.add_argument( '--include-archived', dest='incl_archived', help='Included archived findings', action='store_true') 

    args = parser.parse_args()
    
    # Unset env vars - read from .env file
    os.environ.pop('DEBUG', None)
    os.environ.pop('FINDINGS_FILE', None)

    # Load dotenv
    from dotenv import load_dotenv
    load_dotenv()

    if args.filename != None:
        filename = args.filename
    elif bool(os.getenv("FINDINGS_FILE")) != None:
        filename = os.getenv("FINDINGS_FILE")
    else:
        usage("No filename provided")

    if args.incl_resolved or os.getenv("INCL_RESOLVED") == "True":
        INCL_RESOLVED = True
    if args.incl_archived or os.getenv("INCL_ARCHIVED") == "True":
        INCL_ARCHIVED = True

    main(filename)
