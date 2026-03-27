# AI/ML Security and Compliance

## Overview

This tool references and recommends the following AWS AI/ML services as part of observability maturity assessment:

1. **Amazon CloudWatch anomaly detection** — ML-based metric anomaly detection
2. **Amazon CloudWatch Investigations** — AI-assisted incident investigation
3. **AWS DevOps Agent** — AI-assisted troubleshooting via natural language

The tool does not train, fine-tune, or deploy any AI/ML models. It only checks whether these AWS-managed services are configured in the assessed account.

## AI/ML Service Security Controls

### Amazon CloudWatch Anomaly Detection
- **Data scope**: Operates on CloudWatch metric data already in the customer's account
- **Model ownership**: Models are fully managed by AWS; customers do not access model internals
- **Data residency**: Metric data stays within the AWS Region where it is collected
- **Access control**: Governed by IAM policies (`cloudwatch:DescribeAnomalyDetectors`)

### Amazon CloudWatch Investigations
- **Data scope**: Analyzes CloudWatch metrics, logs, and traces within the customer's account
- **Data sharing**: No customer data is shared across accounts or used for model training
- **Access control**: Governed by IAM policies and CloudWatch Investigations configuration
- **Opt-in**: Must be explicitly enabled by the customer

### AWS DevOps Agent
- **Data scope**: Processes operational data (metrics, logs, traces) within the customer's account
- **Data sharing**: Interactions are not used to train or improve underlying models
- **Access control**: Governed by IAM policies and explicit agent configuration
- **Opt-in**: Must be explicitly configured by the customer

## Assessment Tool AI/ML Usage

The assessment tool itself does **not** use AI/ML. It performs deterministic checks:
- Calls `cloudwatch:DescribeAnomalyDetectors` to check if anomaly detection is configured
- Calls the DevOps Agent API to check if agent spaces exist
- Checks CloudWatch Investigations alarm actions for configuration presence

No inference, prediction, or generative AI is performed by the assessment tool.

## Bias and Fairness Considerations

- The maturity scoring algorithm is deterministic and rule-based (not ML-driven)
- Scoring criteria are documented in `assessment_mapping.md` and applied uniformly
- No demographic or personal data is collected or used in scoring

## Compliance Notes

- All referenced AI/ML services are AWS-managed and covered under the [AWS Shared Responsibility Model](https://aws.amazon.com/compliance/shared-responsibility-model/)
- Customers should review the [AWS AI Service Cards](https://aws.amazon.com/machine-learning/responsible-machine-learning/) for detailed information on each service
- No third-party AI/ML services or models are used
