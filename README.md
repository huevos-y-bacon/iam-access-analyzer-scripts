# IAM Access Analyzer Scripts

Extract IAM Access Analyzer findings, flatten and create CSV and JSON files.

## Prereqs

- Create `.env` file (see `example.env`)
  - Should at a minimum contain the ARN of the configured Access Analyzer, e.g.:
      - `ANALYZER_ARN=arn:aws:access-analyzer:eu-west-1:112233445566:analyzer/My-Analyzer`

## Script 1 - `get_all_findings.py` 

- Get a list of, then details of all findings in IAA
- **Note**: This takes 10-12 minutes on a m1 Macbook Pro 13" (2020)
- Output to json for reuse by sebsequent scripts
  - *add `FINDINGS_FILE=<output file name>` to `.env`*

- example:
  ```bash
  ❯ ./get_all_findings.py
  Getting all findings for My-Analyzer (account 112233445566)

  Total findings:    3014
  Getting finding 3014 of 3014

  Results written to 20240715-1030-112233445566-My-Analyzer.details.json
  ```

## Script 2 - `summarise_findings.py`

- Displays a summary of findings, e.g.:
    ```bash
    ❯ ./summarise_findings.py 
    Filename               : 20240715-1030-112233445566-My-Analyzer.details.json
    Total findings         : 3014
    External Access        : 3014
    Public findings        : 495
    Unique owners          : 56
    Unique principals      : 1

    Status:
      ACTIVE               : 2467
      RESOLVED             : 546
      ARCHIVED             : 1

    Resource Types         : 8
      AWS::IAM::Role       : 1925
      AWS::SQS::Queue      : 494
      AWS::S3::Bucket      : 428
      AWS::EC2::Snapshot   : 103
      AWS::SNS::Topic      : 54
      AWS::KMS::Key        : 6
      AWS::RDS::DBSnapshot : 3
      AWS::ECR::Repository : 1
    ```

## Script 3 - `extract_findings.py`

- Extracts findings, grouped by the following:
  - Public
  - External (same a all)
  - Active
  - Archived
  - Resolved
- Writes output to json and csv, using the same file name prefix
- Example:
  ```bash
  ❯ ./extract_findings.py   
  Include resolved     : False
  Include archived     : False
  Filename             : 20240715-1030-112233445566-My-Analyzer.details.json

  Total findings       : 3014

  Public findings      : 8
    json               : 20240715-1030-112233445566-My-Analyzer-PUBLIC.json
    csv                : 20240715-1030-112233445566-My-Analyzer-PUBLIC.csv

  External findings    : 2467
    json               : 20240715-1030-112233445566-My-Analyzer-EXTERNAL.json
    csv                : 20240715-1030-112233445566-My-Analyzer-EXTERNAL.csv

  ACTIVE findings      : 2467
    json               : 20240715-1030-112233445566-My-Analyzer-ACTIVE.json
    csv                : 20240715-1030-112233445566-My-Analyzer-ACTIVE.csv

  ARCHIVED findings    : 1
    json               : 20240715-1030-112233445566-My-Analyzer-ARCHIVED.json
    csv                : 20240715-1030-112233445566-My-Analyzer-ARCHIVED.csv

  RESOLVED findings    : 546
    json               : 20240715-1030-112233445566-My-Analyzer-RESOLVED.json
    csv                : 20240715-1030-112233445566-My-Analyzer-RESOLVED.csv\
  ```

Optional:
- *To include archived or resolved findings to the output:*
  - Add to `.env`:
    ```bash
    INCL_RESOLVED=True
    INCL_ARCHIVED=True
    ```
  - or provide `--include-resolved` or `--include-archived` arguments
  - example:
    ```bash
    ...

    Public findings      : 495
    json               : 20240715-1030-112233445566-My-Analyzer-PUBLIC-incl_resolved-incl_archived.json
    csv                : 20240715-1030-112233445566-My-Analyzer-PUBLIC-incl_resolved-incl_archived.csv

    External findings    : 3014
    json               : 20240715-1030-112233445566-My-Analyzer-EXTERNAL-incl_resolved-incl_archived.json
    csv                : 20240715-1030-112233445566-My-Analyzer-EXTERNAL-incl_resolved-incl_archived.csv

    ...
    ```

## To do / considerations

- Turn into Lambda functions, schedule to run regularly and output to S3 bucket
- Think about how to track findings. e.g. DDB table?
