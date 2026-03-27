# Security Implementation Guide

## Overview

This document provides actionable security implementation guidance for deploying and operating the AWS Observability Assessment Tool, including security control definitions, implementation steps, measurable metrics, and prioritization.

## Security Controls

### 1. IAM Least-Privilege Access (Priority: HIGH)

**Control**: The assessment uses a dedicated read-only IAM role (`ObservabilityAssessmentRole`) scoped to 58 specific API actions required for discovery checks. No write permissions are granted except `ssm:SendCommand` (used to check CloudWatch Agent status on EC2 instances).

**Implementation Steps**:
1. Deploy `1-observability-assessment-role.yaml` in each target account
2. Set `AssessmentAccountID` to restrict the trust policy to only the account running CodeBuild
3. Verify the role has no write permissions beyond `ssm:SendCommand` and `ssm:GetCommandInvocation`
4. Review `observability-assessment-role.json` for the complete list of permitted actions

**Measurable Metrics**:
- Number of IAM actions granted: 58 (all read-only except SSM command execution)
- Trust policy scope: single account (not wildcard)
- Resource scope: verify no overly broad resource ARNs beyond `*` (required for read-only describe/list calls)

### 2. Cross-Account Trust Policy (Priority: HIGH)

**Control**: The `ObservabilityAssessmentRole` trust policy restricts `sts:AssumeRole` to a specific IAM role (`ObservabilityAssessmentCodeBuildRole`) in a specific account.

**Implementation Steps**:
1. In `1-observability-assessment-role.yaml`, set `AssessmentAccountID` to the 12-digit account ID where CodeBuild runs
2. The trust policy uses `aws:PrincipalArn` condition to restrict assumption to only the CodeBuild execution role
3. Do not use wildcard (`*`) for the principal — always specify the exact account

**Measurable Metrics**:
- Trust policy principal count: exactly 1 role per deployment
- Condition keys present: `aws:PrincipalArn` must be set

### 3. S3 Report Bucket Security (Priority: HIGH)

**Control**: The S3 bucket storing assessment reports enforces encryption, blocks public access, and requires SSL.

**Implementation Steps**:
1. Deploy `2-observability-assessment-codebuild.yaml` which creates the bucket with security controls
2. Verify `PublicAccessBlockConfiguration` has all four settings set to `true`
3. Verify the bucket policy includes `aws:SecureTransport` condition denying non-SSL requests
4. Verify `BucketEncryption` uses `AES256` (SSE-S3) at minimum

**Measurable Metrics**:
- Public access blocked: 4/4 settings enabled
- SSL-only policy: present
- Encryption: enabled (SSE-S3)
- Versioning: enabled

### 4. CodeBuild Execution Security (Priority: MEDIUM)

**Control**: The CodeBuild project runs in a managed environment with scoped IAM permissions and no persistent credentials.

**Implementation Steps**:
1. The CodeBuild role only has permissions for: CloudWatch Logs (build logs), S3 PutObject (report upload), and `sts:AssumeRole` on the assessment role
2. Build timeout is set to 60 minutes to prevent runaway executions
3. The build environment uses a managed Amazon Linux 2 image (`aws/codebuild/amazonlinux2-x86_64-standard:5.0`)

**Measurable Metrics**:
- Build timeout: 60 minutes maximum
- IAM policy statement count: 3 (logs, S3, STS)
- Privileged mode: disabled

### 5. Command Execution Security (Priority: MEDIUM)

**Control**: The assessment script executes AWS CLI commands via `subprocess`. Commands are constructed internally (not from user input). Shell mode is avoided except for commands requiring shell metacharacters (pipes, redirects in SSM remote commands).

**Implementation Steps**:
1. All AWS CLI commands are hardcoded strings — no user-supplied input is interpolated into commands
2. Commands without shell metacharacters use `shlex.split()` with `shell=False`
3. Commands requiring shell features (3 out of ~70) use `shell=True` with `nosec`/`nosemgrep` suppression and documented justification
4. SSM command polling uses a retry loop instead of arbitrary `time.sleep()`

**Measurable Metrics**:
- Commands using `shell=False`: ~67/70 (96%)
- Commands using `shell=True`: 3/70 (4%), all with documented justification
- User-supplied input in commands: none

### 6. Data Handling (Priority: MEDIUM)

**Control**: Assessment output contains AWS resource metadata (ARNs, resource counts, configuration status) but no secrets, credentials, or customer data.

**Implementation Steps**:
1. The assessment only calls read-only/describe/list APIs — no data plane access
2. HTML reports contain resource counts and configuration evidence, not raw data
3. CSV discovery check output contains command results, not sensitive payloads
4. Reports are saved locally to `assessment-result/` or uploaded to the private S3 bucket

**Measurable Metrics**:
- Secrets in output: 0
- Data plane API calls: 0
- Report storage: local filesystem or private S3 bucket only

## Implementation Prioritization

| Priority | Control | Effort | Impact |
|----------|---------|--------|--------|
| 1 (HIGH) | IAM least-privilege role | Low — deploy CFN template | Prevents unauthorized access |
| 2 (HIGH) | Cross-account trust policy | Low — set account ID parameter | Prevents cross-account abuse |
| 3 (HIGH) | S3 bucket security | Low — included in CFN template | Protects assessment reports |
| 4 (MEDIUM) | CodeBuild execution security | Low — included in CFN template | Limits blast radius |
| 5 (MEDIUM) | Command execution security | Done — implemented in code | Prevents command injection |
| 6 (MEDIUM) | Data handling | Low — inherent in design | Prevents data leakage |

## Security Review Checklist

Before deploying to a new account:

- [ ] `AssessmentAccountID` parameter is set to the correct 12-digit account ID
- [ ] S3 bucket public access block is enabled (all 4 settings)
- [ ] S3 bucket policy requires SSL
- [ ] CodeBuild role does not have `AdministratorAccess` or broad `*` action permissions
- [ ] Assessment role trust policy does not use wildcard principals
- [ ] Assessment role permissions match `observability-assessment-role.json` exactly
- [ ] Build timeout is set to 60 minutes or less

## Data Classification

| Data Type | Classification | Encryption at Rest | Encryption in Transit |
|-----------|---------------|-------------------|----------------------|
| Assessment HTML reports | Internal — contains resource ARNs and counts | SSE-S3 (AES-256) on S3 bucket | HTTPS enforced via bucket policy |
| Discovery CSV files | Internal — contains AWS CLI command outputs | SSE-S3 (AES-256) on S3 bucket | HTTPS enforced via bucket policy |
| Temporary STS credentials | Confidential — short-lived access tokens | In-memory only, not persisted | AWS SDK uses HTTPS |
| CloudWatch Logs (build logs) | Internal — contains build output | CloudWatch Logs default encryption | HTTPS via AWS API |

## Key Management Strategy

- **S3 report bucket**: Uses SSE-S3 (AES-256) server-side encryption by default. For environments requiring customer-managed keys, replace `SSEAlgorithm: AES256` with `aws:kms` and specify a KMS key ARN in the CloudFormation template.
- **CloudWatch Logs**: Uses default service encryption. For customer-managed keys, add a `KmsKeyId` to the log group resource.
- **No local key storage**: The tool does not generate, store, or manage encryption keys directly.

## Access Logging

- **S3 bucket access**: Enable S3 server access logging by adding a `LoggingConfiguration` to the `ReportBucket` resource pointing to a dedicated logging bucket.
- **API activity**: AWS CloudTrail captures all API calls made by the assessment role for audit purposes.
- **Build execution**: AWS CodeBuild logs all build activity to Amazon CloudWatch Logs with 7-day retention.
