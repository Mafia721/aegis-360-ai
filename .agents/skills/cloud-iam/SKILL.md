---
name: Cloud IAM & Storage Exploitation (AWS/GCP/Azure)
description: Find and prove cloud misconfigurations — public object storage, unauthenticated serverless functions, leaked/over-privileged service-account keys, and IAM privilege paths across AWS, GCP, and Azure.
tags: [cloud, iam, aws, gcp, azure, misconfig, storage]
recommended_tools: [curl, jq, python3, httpx_probe, nuclei_scan, ffuf_scan]
vuln_classes: [misconfig]
domain: cloud
phase: exploitation
provenance: {source: uphiago/recon-skills, paths: [redteam/cloud-iam-deep/SKILL.md, redteam/hunt-cloud-misconfig/SKILL.md]}
---
# Cloud IAM & Storage Exploitation (AWS/GCP/Azure)

Most cloud findings are **misconfiguration**, not zero-days: world-readable buckets, unauthenticated
functions, and keys/tokens that grant far more than intended. Goal: enumerate the cloud surface, find the
weak IAM/storage boundary, and prove impact with a read (or authorized write) — without touching data you
aren't authorized to.

## When to use
Target resolves to cloud infra (`*.amazonaws.com`, `*.cloudfunctions.net`, `*.run.app`, `*.azurewebsites.net`,
`*.blob.core.windows.net`, `storage.googleapis.com`), you have a leaked key/token, or an SSRF foothold can
reach a metadata endpoint.

## Object storage (read gate first)
```
# AWS S3
curl -s https://BUCKET.s3.amazonaws.com/?list-type=2 | head        # public listing?
# GCP GCS
curl -s https://storage.googleapis.com/storage/v1/b/BUCKET/o        # object list if public
# Azure Blob
curl -s "https://ACCOUNT.blob.core.windows.net/CONTAINER?restype=container&comp=list"
```
If listable/readable: prove with ONE non-sensitive object (e.g. an index/manifest). Look for `gcf-sources-*`
(GCP function source), `*-backups`, `*-terraform-state` (state files leak provider creds). Also test **write**
only if authorized (upload a benign marker, then delete).

## Serverless / metadata
- **GCP Cloud Functions/Run:** discover PROJECT_ID (source-map hosts, `x-goog-*` headers, bucket names), then
  test the function URL with different HTTP methods for missing auth.
- **Metadata pivot (from SSRF foothold):** AWS `http://169.254.169.254/latest/meta-data/iam/security-credentials/`,
  GCP `http://metadata.google.internal/computeMetadata/v1/` (`Metadata-Flavor: Google`), Azure IMDS
  `http://169.254.169.254/metadata/identity/oauth2/token` (`Metadata: true`). A returned token = temporary creds.

## Service-account keys & tokens → what can they do
The only honest privilege check is asking the provider what the identity is allowed to do:
```
# AWS
aws sts get-caller-identity
aws iam list-attached-user-policies / aws iam simulate-principal-policy
# GCP (SA key json → token)
gcloud auth activate-service-account --key-file=key.json
gcloud projects get-iam-policy PROJECT_ID
# Azure
az account get-access-token ; az role assignment list --assignee <id>
```
Map for privilege-escalation edges: `iam:PassRole`+`lambda`/`ec2`, `setIamPolicy`, wildcard `*` actions,
default/over-broad SA on a compute resource, ability to create keys for a higher-priv SA.

## IAM privilege paths (prove, don't assume)
Identify one concrete escalation edge and demonstrate it minimally (e.g. attach a policy to yourself in a
sandbox resource, or generate a token for a higher-priv SA) — capture the API call + response as proof.
Do not pivot into production data or persist access.

## Validation gate
- Storage: a real read of an object you were able to list (or an authorized benign write), not just a 200 on
  the bucket root.
- Creds/token: the `get-caller-identity`/token response proving the identity + at least one allowed sensitive
  action from a policy simulation.
- IAM path: the specific edge named (principal → permission → target) with the API proof.

## Remediation (attach to findings)
Make buckets private + enable public-access-block; require auth on functions; scope SA/role permissions to
least privilege; rotate exposed keys and prefer short-lived workload identity; enable IMDSv2 / restrict
metadata access; alert on `iam:*`/`setIamPolicy` usage.
