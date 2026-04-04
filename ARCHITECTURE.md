# Architecture and Design Document

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     Assessment Account                          │
│                                                                 │
│  ┌──────────────┐    ┌──────────────────┐    ┌──────────────┐  │
│  │ CloudFormation│───>│   CodeBuild      │───>│  S3 Bucket   │  │
│  │ (Deployment)  │    │ (Execution Env)  │    │ (Reports)    │  │
│  └──────────────┘    └───────┬──────────┘    └──────────────┘  │
│                              │ sts:AssumeRole                   │
│                              ▼                                  │
│                     ┌──────────────────┐                        │
│                     │ Assessment Role  │                        │
│                     │ (Read-Only)      │                        │
│                     └───────┬──────────┘                        │
│                             │                                   │
│              ┌──────────────┼──────────────┐                    │
│              ▼              ▼              ▼                     │
│     ┌──────────────┐ ┌───────────┐ ┌────────────┐              │
│     │ CloudWatch   │ │  X-Ray    │ │ Compute    │              │
│     │ Logs/Metrics │ │  Traces   │ │ EC2/ECS/   │              │
│     │ Alarms/Dash  │ │  Groups   │ │ EKS/Lambda │              │
│     └──────────────┘ └───────────┘ └────────────┘              │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    Assessment Script Flow                        │
│                                                                 │
│  main() ──> setup_discovery_checks() ──> execute_checks()       │
│                                              │                  │
│              50 AWS CLI read-only calls ◄─────                  │
│                       │                                         │
│                       ▼                                         │
│              score_maturity_levels() ──> generate_html_report()  │
│                                              │                  │
│              HTML + CSV output ◄──────────────                  │
└─────────────────────────────────────────────────────────────────┘
```

## Design Decisions with Security Considerations

### 1. Read-Only Assessment Model
The tool only reads AWS resource metadata via describe/list API calls. No resources are created, modified, or deleted (except SSM SendCommand for agent detection). This minimizes blast radius.

### 2. Subprocess for AWS CLI
AWS CLI is invoked via `subprocess` rather than boto3 for most checks because:
- CLI output parsing is simpler for complex nested queries
- CLI handles pagination and retries automatically
- Security mitigation: all commands are hardcoded strings, `shlex.split()` used with `shell=False` by default

### 3. Local Report Generation
Reports are generated locally as static HTML files with no external dependencies (no CDN, no JavaScript frameworks). This prevents supply chain attacks and enables air-gapped environments to view reports.

### 4. IAM Role Separation
Two separate IAM roles are used:
- **CodeBuild execution role**: Can write to S3 (reports) and CloudWatch Logs (build logs), and assume the assessment role
- **Assessment role**: Read-only access to observability services only

## Threat Model

### Assets
| Asset | Sensitivity | Location |
|-------|------------|----------|
| Assessment reports (HTML/CSV) | Medium — contains resource metadata, ARNs, counts | Local filesystem or S3 bucket |
| IAM role credentials | High — temporary STS credentials | In-memory during execution |
| AWS resource metadata | Low — read-only configuration data | Transient during API calls |

### Threat Actors
| Actor | Motivation | Capability |
|-------|-----------|------------|
| Malicious insider | Escalate read-only access | Modify assessment script or role |
| External attacker | Access AWS account metadata | Compromise CodeBuild or S3 bucket |

### Threats and Mitigations
| # | Threat | Impact | Mitigation |
|---|--------|--------|------------|
| T1 | Command injection via subprocess | High — arbitrary command execution | All commands are hardcoded; `shlex.split()` with `shell=False`; no user input in commands |
| T2 | IAM role privilege escalation | High — write access to resources | Role limited to 58 read-only actions; trust policy scoped to single account/role |
| T3 | Report data exfiltration | Medium — resource metadata exposure | S3 bucket blocks public access, requires SSL, enables versioning |
| T4 | Supply chain attack on dependencies | Medium — malicious code execution | Only stdlib + boto3 dependencies; no external packages in HTML output |
| T5 | Cross-account unauthorized access | High — access to other accounts | Trust policy uses `aws:PrincipalArn` condition; no wildcard principals |
| T6 | SSM command abuse | Medium — remote code execution on EC2 | SSM commands are read-only checks (pgrep, systemctl status); limited to 5 instances |

## AWS Service Security Guidelines

### Amazon CloudWatch
- Log groups: Use retention policies to limit data exposure window
- Dashboards: No sensitive data in dashboard names or widget titles
- Alarms: SNS topics should use encryption for alarm notifications
- Metrics: Custom metric names should not contain PII

### AWS X-Ray
- Trace data may contain request/response metadata — consider configuring sampling rules to limit sensitive data capture
- X-Ray groups and insights do not store raw request payloads

### Amazon EC2
- Assessment reads instance metadata only (describe-instances)
- SSM SendCommand is used to check CloudWatch Agent status — commands are read-only shell checks

### Amazon ECS / Amazon EKS
- Assessment reads cluster configuration and task definitions only
- Container Insights and add-on status checks are metadata-only

### AWS Lambda
- Assessment reads function configuration (structured logging, tracing config, layers)
- No function invocations are performed

### Amazon S3 (Report Storage)
- Bucket must have public access blocked (all 4 settings)
- Bucket policy must require `aws:SecureTransport`
- Server-side encryption must be enabled
- Versioning should be enabled for audit trail

### AWS Systems Manager
- SSM SendCommand is the only write-equivalent action in the assessment
- Commands are limited to process status checks (`pgrep`, `systemctl`, `find`)
- Execution is limited to first 5 SSM-managed instances for performance

### AWS Organizations
- Assessment reads organization structure for context only
- No modifications to organization policies or accounts

### Amazon SNS
- Assessment reads topic and subscription metadata only
- No messages are published

### AWS Identity and Access Management
- Assessment role uses `Resource: "*"` because describe/list actions do not support resource-level permissions
- Trust policy is scoped to a single principal ARN
