# AWS Comprehensive Observability Assessment Tool

Automated evaluation of observability maturity across AWS environments. Runs 50 discovery checks across 5 categories (Logs, Metrics, Traces, Dashboards & Alerting, Organization) and generates an HTML report with maturity scoring, evidence, and actionable recommendations.

## Quick Start

### Option 1: Run Locally

**Prerequisites:** Python 3.9+, the [AWS CLI v2](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) installed and on your `PATH` (the tool shells out to `aws`), and configured AWS credentials.

```bash
# Install Python dependencies
pip install -r requirements.txt

# Install AWS DevOps Agent CLI model (needed for the AWS DevOps Agent check to detect agent spaces)
curl -o devopsagent.json https://d1co8nkiwcta1g.cloudfront.net/devopsagent.json
aws configure add-model --service-model "file://${PWD}/devopsagent.json" --service-name devopsagent

# Run assessment
python3 observability_assessment_comprehensive.py --profile YOUR_PROFILE --region us-west-2
```

### Option 2: Deploy via CodeBuild (Recommended)

Two-step CloudFormation deployment that runs the assessment automatically in your account.

#### Step 1: Deploy the Read-Only Assessment Role

```bash
aws cloudformation create-stack \
  --stack-name ObservabilityAssessmentRole \
  --template-body file://1-observability-assessment-role.yaml \
  --parameters ParameterKey=AssessmentAccountID,ParameterValue=YOUR_ACCOUNT_ID \
  --capabilities CAPABILITY_NAMED_IAM \
  --region us-west-2
```

Set `AssessmentAccountID` to the account where AWS CodeBuild runs (your own account for single-account mode).

#### Step 2: Deploy the CodeBuild Pipeline

```bash
aws cloudformation create-stack \
  --stack-name ObservabilityAssessmentCodeBuild \
  --template-body file://2-observability-assessment-codebuild.yaml \
  --parameters ParameterKey=AssessmentRegion,ParameterValue=us-west-2 \
               ParameterKey=CreateAssessmentRole,ParameterValue=no \
  --capabilities CAPABILITY_NAMED_IAM \
  --region us-west-2
```

Set `CreateAssessmentRole` to `yes` if you skipped Step 1 (single-account mode creates the role inline).

#### Step 3: Run the Assessment

A build is triggered automatically on stack creation. To re-run:

```bash
aws codebuild start-build --project-name ObservabilityAssessmentCodeBuild --region us-west-2
```

The CodeBuild project downloads the assessment script from the public GitHub repo ([aws-samples/sample-aws-observability-assessment](https://github.com/aws-samples/sample-aws-observability-assessment)) automatically. Reports (HTML + CSV) are uploaded to the S3 bucket automatically.

> **Optional fallback:** If CodeBuild can't reach GitHub (e.g. a private VPC without egress), upload the script to the S3 bucket created by Step 2 — the buildspec uses it as a fallback source:
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
