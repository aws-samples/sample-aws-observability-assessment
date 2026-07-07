# AWS Observability Assessment Tool

Automated evaluation of observability maturity across AWS environments. Runs 50 discovery checks across 5 categories (Logs, Metrics, Traces, Dashboards & Alerting, Organization) and generates an HTML report with maturity scoring, evidence, and actionable recommendations.

## Table of Contents

- [Quick Start](#quick-start)
  - [Option 1: Run Locally](#option-1-run-locally)
  - [Option 2: Deploy via CodeBuild (Recommended)](#option-2-deploy-via-codebuild-recommended)
    - [Single-account mode (most common)](#single-account-mode-most-common)
    - [Multi / cross-account mode](#multi--cross-account-mode)
    - [Run the Assessment](#run-the-assessment)
- [CLI Options](#cli-options)
- [Assessment Coverage](#assessment-coverage)
- [Output](#output)
- [IAM Permissions](#iam-permissions)

## Quick Start

### Option 1: Run Locally

**Prerequisites:** Python 3.12+, [AWS CLI v2](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) **version 2.34.21 or later** installed and on your `PATH` (the tool shells out to `aws`, and the AWS DevOps Agent check requires the `devops-agent` commands that ship natively starting in 2.34.21), and configured AWS credentials.

```bash
# Confirm your AWS CLI is v2.34.21 or later (required for the AWS DevOps Agent check)
aws --version

# Install Python dependencies
pip install -r requirements.txt

# Run assessment
python3 observability_assessment_comprehensive.py --profile YOUR_PROFILE --region us-west-2
```

### Option 2: Deploy via CodeBuild (Recommended)

CloudFormation deployment that runs the assessment automatically in AWS CodeBuild. There are two templates:

- `1-observability-assessment-role.yaml` — creates the read-only `ObservabilityAssessmentRole` that CodeBuild assumes to scan an account.
- `2-observability-assessment-codebuild.yaml` — creates the S3 report bucket, the CodeBuild project, and the CodeBuild role. It **also contains the assessment role inline**, gated by the `CreateAssessmentRole` parameter.

**Which templates you need depends on your mode:**

| Mode | What it does | Templates to deploy |
|------|--------------|---------------------|
| **Single account** | CodeBuild scans the same account it runs in | **Only template 2**, with `CreateAssessmentRole=yes` (the default). It creates the role inline — you do **not** need template 1. |
| **Multi / cross account** | CodeBuild runs in one central account and scans other target accounts | Template 2 in the central account with `CreateAssessmentRole=no`, **plus** template 1 in **each target account** (so the role exists there for CodeBuild to assume). |

Pick one of the two paths below.

---

#### Single-account mode (most common)

Deploy only template 2. The read-only assessment role is created inline.

```bash
aws cloudformation create-stack \
  --stack-name ObservabilityAssessmentCodeBuild \
  --template-body file://2-observability-assessment-codebuild.yaml \
  --parameters ParameterKey=AssessmentRegion,ParameterValue=us-west-2 \
               ParameterKey=CreateAssessmentRole,ParameterValue=yes \
  --capabilities CAPABILITY_NAMED_IAM \
  --region us-west-2
```

Then skip to [Run the Assessment](#run-the-assessment).

---

#### Multi / cross-account mode

**Step 1 — Deploy the read-only role in each target account.**

Template 1 must exist in every account you want to assess. In all of them, set `AssessmentAccountID` to the central account where CodeBuild runs — this is the only account allowed to assume the role. Choose one of the two options below depending on how many accounts you have.

<details>
<summary><b>Option A — Per-account stack (a few accounts)</b></summary>

Run this in each target account (using that account's credentials). Simple, no prerequisites — but it doesn't scale and won't cover accounts added later.

```bash
aws cloudformation create-stack \
  --stack-name ObservabilityAssessmentRole \
  --template-body file://1-observability-assessment-role.yaml \
  --parameters ParameterKey=AssessmentAccountID,ParameterValue=CENTRAL_CODEBUILD_ACCOUNT_ID \
  --capabilities CAPABILITY_NAMED_IAM \
  --region us-west-2
```

</details>

<details>
<summary><b>Option B — StackSet across an OU (many accounts / org-scale)</b></summary>

For org-scale rollout, deploy template 1 as a **service-managed StackSet** targeting an Organizational Unit. One operation deploys the role to every account in the OU, and **auto-deployment** adds it to any account later moved into the OU — so new accounts become assessable with no manual step. Policy updates (e.g. a new `Describe*` action) roll out with a single `update-stack-set`.

Prerequisites: run from the Organizations **management account** or a **delegated StackSets administrator**, with [trusted access for StackSets](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-orgs-enable-trusted-access.html) enabled.

```bash
# Create the StackSet (service-managed permissions, auto-deploy to new accounts in the OU)
aws cloudformation create-stack-set \
  --stack-set-name ObservabilityAssessmentRole \
  --template-body file://1-observability-assessment-role.yaml \
  --parameters ParameterKey=AssessmentAccountID,ParameterValue=CENTRAL_CODEBUILD_ACCOUNT_ID \
  --capabilities CAPABILITY_NAMED_IAM \
  --permission-model SERVICE_MANAGED \
  --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
  --region us-west-2

# Deploy it to all accounts in one or more OUs
aws cloudformation create-stack-instances \
  --stack-set-name ObservabilityAssessmentRole \
  --deployment-targets OrganizationalUnitIds=ou-xxxx-xxxxxxxx \
  --regions us-west-2 \
  --operation-preferences FailureToleranceCount=5,MaxConcurrentCount=10
```

> IAM roles are global, so deploy the StackSet in a **single region** only — deploying to multiple regions would collide on the role name `ObservabilityAssessmentRole`.

</details>

**Step 2 — Deploy the CodeBuild pipeline in the central account.**

Template 2 is a singleton — deploy it **only** in the central account (not as a StackSet).

Set `CreateAssessmentRole=no` so template 2 does not try to recreate the role (it already exists from Step 1).

```bash
aws cloudformation create-stack \
  --stack-name ObservabilityAssessmentCodeBuild \
  --template-body file://2-observability-assessment-codebuild.yaml \
  --parameters ParameterKey=AssessmentRegion,ParameterValue=us-west-2 \
               ParameterKey=CreateAssessmentRole,ParameterValue=no \
  --capabilities CAPABILITY_NAMED_IAM \
  --region us-west-2
```

---

#### Run the Assessment

A build is triggered automatically on stack creation. To re-run:

```bash
aws codebuild start-build --project-name ObservabilityAssessmentCodeBuild --region us-west-2
```

The CodeBuild project downloads the assessment script from the public GitHub repo ([aws-samples/sample-aws-observability-assessment](https://github.com/aws-samples/sample-aws-observability-assessment)) automatically. Reports (HTML + CSV) are uploaded to the S3 bucket automatically.

> **Optional fallback:** If CodeBuild can't reach GitHub (e.g. a private VPC without egress), upload the script to the S3 bucket created by template 2 — the buildspec uses it as a fallback source:
>
> ```bash
> BUCKET=$(aws cloudformation describe-stacks \
>   --stack-name ObservabilityAssessmentCodeBuild \
>   --query 'Stacks[0].Outputs[?OutputKey==`ReportBucketName`].OutputValue' \
>   --output text --region us-west-2)
>
> aws s3 cp observability_assessment_comprehensive.py s3://$BUCKET/
> ```

## CLI Options

| Option | Description |
|--------|-------------|
| `--profile` | AWS profile to use for authentication |
| `--region` | AWS region to assess (default: `us-west-2`) |
| `--role-arn` | IAM role ARN to assume before running checks (used by CodeBuild) |
| `--single-check N` | Run only a specific discovery check by ID |
| `--single-question N` | Run discovery checks for a specific question (1-17) and score it |
| `--debug` | Enable verbose debug logging (per-instance diagnostics, failed-command details) |

## Assessment Coverage

50 discovery checks across 17 questions in 5 categories:

| Category | Questions | What's Assessed |
|----------|-----------|-----------------|
| Logs | Q1-Q4 | Collection, usage, access, retention |
| Metrics | Q5-Q7 | Collection types, usage patterns, centralized access |
| Traces | Q8-Q9 | Collection instrumentation, usage and correlation |
| Dashboards & Alerting | Q10-Q12 | Alarm strategies, dashboard maturity, adaptive thresholds |
| Organization | Q13-Q17 | Strategy, SLOs, ROI, AI/ML, real user monitoring |

## Output

- **HTML Report** with radar chart visualization, maturity scoring (1.0-4.0), evidence-based results, and recommendations
- **CSV** with discovery check details
- Reports saved to `assessment-result/` locally or uploaded to S3 via CodeBuild

## IAM Permissions

The assessment requires access to Amazon CloudWatch, AWS X-Ray, AWS Lambda, Amazon ECS, Amazon EKS, Amazon SNS, AWS Systems Manager, Amazon CloudWatch Application Signals, AWS Organizations, and related services. Almost all actions are read-only (`Describe*`, `List*`, `Get*`) and make no changes to your resources. See `1-observability-assessment-role.yaml` for the complete list of IAM actions.

**One exception to read-only:** the EC2 CloudWatch agent check uses `ssm:SendCommand` to run a read-only diagnostic command (via the managed `AWS-RunShellScript` document) on instances that are managed by AWS Systems Manager. It checks whether the CloudWatch agent process is running and whether log collection is configured; it does not modify the instances. This check is skipped for instances not managed by SSM.
