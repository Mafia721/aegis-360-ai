# AWS Cloud Configuration Review — Quick Start

All tools are installed system-wide and registered as MCP tools in Aegis-360 AI.

## Credential Setup (required before any scan)

```bash
# Option A: named profile in ~/.aws/credentials
aws configure --profile <client-name>

# Option B: environment variables
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...   # if using temporary credentials / STS

# Verify access
aws sts get-caller-identity --profile <client-name>
```

## Individual Tool Commands

### Prowler v5 — security checks
```bash
# Full account scan (all services), JSON output
prowler aws --profile <client> --region us-east-1 --output-formats json --no-banner

# Scoped scan (IAM + S3 + CloudTrail)
prowler aws --profile <client> --region us-east-1 \
  --services iam s3 cloudtrail kms ec2 rds \
  --output-formats json csv html --no-banner
```

### ScoutSuite — multi-cloud config audit
```bash
scout aws --profile <client> --region us-east-1 \
  --no-browser --report-dir /tmp/scoutsuite-report
```

### Steampipe — SQL queries against live AWS
```bash
steampipe query "select name, versioning_enabled from aws_s3_bucket where versioning_enabled = false"
steampipe query "select arn from aws_iam_user where mfa_enabled = false"
steampipe query "select trail_arn, is_logging from aws_cloudtrail_trail"
```

### Powerpipe + Compliance Mod — benchmark runs
```bash
cd /home/kali/aegis-360-ai-master/tools/steampipe-aws-compliance

# CIS AWS Foundations Benchmark v3.0.0
powerpipe benchmark run aws_compliance.benchmark.cis_v300 --output json

# NIST 800-53 Rev 5
powerpipe benchmark run aws_compliance.benchmark.nist_800_53_rev_5 --output json

# PCI DSS v3.2.1
powerpipe benchmark run aws_compliance.benchmark.pci_dss_v321 --output json
```

### Cloudsplaining — IAM policy risk analysis
```bash
# Step 1: download IAM state
cloudsplaining download --profile <client> --output-file /tmp/iam-auth.json

# Step 2: analyze
cloudsplaining analyze --input-file /tmp/iam-auth.json --output-dir /tmp/cloudsplaining-out
```

### Pacu — IAM / service enumeration
```bash
# Launch interactive session
pacu
# At prompt: enter session name, then:
# Pacu> run iam__enum_users_roles_policies_groups
# Pacu> run s3__enum
# Pacu> run ec2__enum
# Pacu> exit
```

### AWS CLI v2
```bash
aws sts get-caller-identity
aws iam list-users
aws s3 ls
aws cloudtrail describe-trails
aws ec2 describe-security-groups
aws config describe-configuration-recorders
```

## Orchestrated Review via MCP (Claude Code)

```
aws_tools_status()
aws_cli_run("sts get-caller-identity", profile="<client>")
aws_config_review(profile="<client>", region="us-east-1",
                  services=["iam","s3","ec2","rds","cloudtrail","kms"],
                  download_iam=True)
aws_steampipe_compliance(benchmark="cis_v300", profile="<client>")
```
