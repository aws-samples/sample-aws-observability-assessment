# Scrubbing Guide — Sanitizing Assessment Output for Public Release

This document defines the rules and process for sanitizing the Observability Assessment
HTML report before committing it to the public repository as a sample.

## Why Scrub?

The assessment discovers real AWS resource names, account IDs, ARNs, and infrastructure
details. While AWS account IDs are not considered secrets, resource names can reveal
internal project codenames, org structure, and deployment patterns. We scrub to:

1. Prevent leaking internal project/resource names that identify the customer or org.
2. Follow AWS documentation conventions so the sample looks professional and familiar.
3. Ensure the sample is reusable as a teaching artifact without distracting details.

## Placeholder Conventions

These follow the [AWS CLI Reference Guide example standards](https://docs.aws.amazon.com/cli/latest/userguide/welcome-examples.html)
and internal AWS documentation team conventions.

### Account & Identity

| Data Type | Placeholder Pattern | Notes |
|---|---|---|
| AWS Account ID (12-digit) | `111122223333` | For multiple accounts: `111122223333`, `444455556666`, `777788889999` |
| IAM Role ARN | `arn:aws:iam::111122223333:role/ExampleRole` | Keep the service prefix, replace the name |
| IAM User | `arn:aws:iam::111122223333:user/ExampleUser` | |
| Email addresses | Remove or replace with `user@example.com` | |

### Resource Identifiers

| Data Type | Placeholder Pattern | Notes |
|---|---|---|
| EC2 Instance ID | `i-1234567890abcdef0` | Keep `i-` prefix |
| VPC ID | `vpc-1a2b3c4d5e6f7g8h9` | Keep `vpc-` prefix |
| Subnet ID | `subnet-1a2b3c4d5e6f7g8h` | Keep `subnet-` prefix |
| Security Group ID | `sg-1a2b3c4d5e6f7g8h9` | Keep `sg-` prefix |
| EKS/ECS Cluster | `ExampleAppEKS-cluster`, `ExampleECS-cluster` | Use `Example` prefix |
| S3 Bucket | `amzn-s3-demo-bucket` or `example-bucket-name` | AWS standard demo bucket name |
| CloudFormation Stack ID | `a1b2c3d4-0001-0001-0001-abcdef012345` | Increment middle sections for multiple |
| Lambda Function | `ExampleStack-FunctionName` | Keep structural suffixes |
| Log Group | `/aws/lambda/ExampleStack-Function` | Keep AWS service prefix path |
| SNS Topic | `Default_CloudWatch_Alarms_Topic` or `ExampleTopic` | |
| CloudWatch Alarm | `ExampleApp-alarm-name` | Replace customer-specific prefixes |
| Workspace ID (AMP) | `ws-a1b2c3d4-0005-0005-0005-abcdef012345` | Keep `ws-` prefix |
| Canary ID | `cwsyn-exampleapp-canary-a1b2c3d4-...` | Keep `cwsyn-` prefix |

### UUIDs and GUIDs

| Position | Pattern |
|---|---|
| First | `a1b2c3d4-5678-90ab-cdef-EXAMPLE11111` |
| Second | `a1b2c3d4-5678-90ab-cdef-EXAMPLE22222` |
| Third | `a1b2c3d4-5678-90ab-cdef-EXAMPLE33333` |
| Short form (stack IDs) | `a1b2c3d4-0001-0001-0001-abcdef012345` (increment `0001`) |

### ARNs

Replace each component independently:
```
arn:aws:<service>:<region>:<account>:<resource-type>/<resource-name>
         ↓          ↓        ↓                         ↓
      keep      us-west-2  111122223333          ExampleResource
```

Keep the service name, resource type, and structural separators (`:`, `/`).
Only replace the account ID and resource name portions.

### Regions

Use `us-west-2` unless the resource is region-locked or multi-region context matters.

### Resource Names — The `Example*` Convention

Replace real resource names with `Example`-prefixed equivalents that preserve the
structural meaning:

| Real Pattern | Scrubbed Equivalent |
|---|---|
| `mycompany-prod-eks-cluster` | `ExampleAppEKS-cluster` |
| `petstore-microservice` | `ExampleStack-Microservices` |
| `internal-cicd-pipeline` | `ExampleStack-Pipeline` |
| `my-observability-workshop` | `ExampleWorkshop` |

Keep suffixes that convey architectural meaning (e.g., `-cluster`, `-LogGroup`,
`-pipeline`, `-Assessment`).

### Tags

CloudFormation-generated tags are generally safe to keep (they reference stack names
that are already scrubbed). Remove or replace:
- Tags containing team names, cost centers, or org-specific values
- Tags with `owner`, `contact`, or email-related keys
- Tags revealing internal project codenames

Keep:
- `environment=non-prod` / `environment=prod`
- `application=<scrubbed-name>`
- `aws:cloudformation:*` tags (after scrubbing the stack-id value)

## Process

### Manual Scrubbing Checklist

1. **Account ID**: Find/replace the 12-digit account ID → `111122223333`
2. **Resource names**: Replace project/team-specific names with `Example*` equivalents
3. **Stack IDs (UUIDs in ARNs)**: Replace with incrementing `a1b2c3d4-NNNN-...` pattern
4. **VPC/Subnet/SG IDs**: Replace with placeholder IDs keeping the prefix
5. **Instance IDs**: Replace with `i-1234567890abcdef0` pattern
6. **Dates**: Assessment generation date can stay (it's not sensitive)
7. **Metrics/counts**: Keep real numbers — they demonstrate the tool's value
8. **Log group names**: Replace custom names; keep `/aws/` service paths with scrubbed suffixes

### Automated Scrubbing

Use the provided `scripts/scrub-sample-report.py` script:

```bash
python3 scripts/scrub-sample-report.py \
    --input assessment-result/observability_assessment.html \
    --output sample-result/observability_assessment_sample.html \
    --account-id 209466560996
```

The script performs regex-based replacements in this order:
1. Account ID → `111122223333`
2. Known resource ID patterns (instance, VPC, subnet, SG, ENI)
3. ARN resource-name portions
4. UUID/GUID patterns in stack-ids and resource identifiers
5. Custom resource names (provided via `--names-file` or auto-detected)

**Always review the output manually** — regex can miss context-dependent names
(e.g., a log group named after an internal project that doesn't match a pattern).

### Verification

After scrubbing, verify no sensitive data remains:

```bash
# Check for the real account ID
grep -c "209466560996" sample-result/observability_assessment_sample.html
# Should return 0

# Check for common resource ID patterns that weren't caught
grep -oP '\b\d{12}\b' sample-result/observability_assessment_sample.html | sort -u
# Should only show 111122223333 (or other placeholder accounts)

# Check for internal hostnames or endpoints
grep -iP '(\.corp\.|\.internal\.|amazon\.com|@)' sample-result/observability_assessment_sample.html
# Should return nothing
```

## What NOT to Scrub

- **Service names**: `Amazon CloudWatch`, `AWS X-Ray`, etc. are public.
- **Region names**: `us-west-2` is fine and expected.
- **API actions**: `logs:DescribeLogGroups`, etc. are public.
- **Metric/count values**: Total log groups, alarm counts, resource counts — keep these.
- **Assessment scores and maturity levels**: These demonstrate the tool's output.
- **AWS service log group prefixes**: `/aws/lambda/`, `/aws/eks/`, etc. are public patterns.
- **Generic resource type suffixes**: `-LogGroup`, `-cluster`, `-pipeline` are fine.

## References

- [AWS CLI Example Standards](https://docs.aws.amazon.com/cli/latest/userguide/welcome-examples.html) — `111122223333` convention
- [AWS Documentation Conventions](https://docs.aws.amazon.com/general/latest/gr/docconventions.html) — placeholder formatting
- [aws-samples contribution guide](https://github.com/aws-samples/.github/blob/main/CONTRIBUTING.md) — public repo standards
- Commit `3d21ebb` in this repo — the original scrub that established the patterns used here
