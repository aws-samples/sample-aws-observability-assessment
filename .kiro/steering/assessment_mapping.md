# Assessment Questions to Implementation Mapping

## Overview
This document maps each of the 17 assessment questions from the CSV to specific AWS service checks and implementation requirements.

## Log Centralization Patterns

### Native Logs Centralization
**CloudWatch Logs cross-account/cross-Region centralization**: Organization-aware feature that copies log events from member accounts/Regions into log groups in a designated central account using "centralization rules." Supports selecting all or filtered log groups, merging same-named log groups, optional backup Region, and handling of KMS-encrypted log groups, with @aws.account and @aws.region added for source context.

### Subscription-based Aggregation
1. **Logs subscription filter → Kinesis Data Stream/Kinesis Data Firehose**: Each source log group has a subscription filter that forwards logs to a cross-account destination (Kinesis or Firehose) in the logging account. Central account then stores to CloudWatch Logs, S3, or third-party tools for analysis.

2. **Logs subscription filter → Lambda**: Subscription sends logs to a Lambda function in a logging account that can normalize, enrich, and then write them to centralized CloudWatch Logs or other stores.

### Cross-account Viewing vs Data Movement
**CloudWatch Observability Access Manager**: Gives a central monitoring account visibility into log groups across accounts without copying data, using shared accounts/links instead of physical aggregation. Useful when you want centralized operators but are okay leaving logs in their source accounts for compliance or cost reasons.

### Export and Archive-driven Approaches
**Export/subscription to S3 as a log lake**: CloudWatch Logs can be streamed (via Firehose or custom Lambda) into S3 buckets in a central account to serve as a multi-account archive and analytics lake (Athena/Lake Formation/etc.). Often combined with partitioned S3 layouts and Glue catalogs for cross-account analytics at lower cost.

### When to Choose Which Pattern
- **Use Logs Centralization rules**: When you want a managed, CloudWatch-native single view of Logs across Org accounts/Regions with minimal plumbing and you still plan to query with Logs Insights or create metrics/alarms on the centralized groups.
- **Use subscription → Kinesis/Firehose/S3**: When you need long-term, cheap storage or external analytics (e.g., SIEM, data lake) and fine-grained control over transformations.
- **Use Observability Access Manager**: When your priority is central access rather than copying data, especially in regulated environments.

## Logs Category

### Question 1: How do you collect logs?
**Implementation Method**: `assess_log_collection()`

**AWS Services to Check**:
- CloudWatch Logs groups and streams
- CloudWatch Agent configuration
- VPC Flow Logs
- AWS Config logging
- CloudTrail logging

**Maturity Level Checks**:
- **Level 1**: Basic log groups exist, some services logging
- **Level 2**: Centralized collection with analytics (Logs Insights queries)
- **Level 3**: Correlation patterns, anomaly detection models
- **Level 4**: Automated insights, ML-based analysis

### Question 2: How do you use logs?
**Implementation Method**: `assess_log_usage()`

**AWS Services to Check**:
- CloudWatch Logs Insights query history
- Metric filters and alarms
- Subscription filters for real-time processing
- Lambda functions triggered by log events

**Maturity Level Checks**:
- **Level 1**: Manual log searches and basic queries
- **Level 2**: Structured queries with faster analysis
- **Level 3**: Automated correlation and anomaly detection
- **Level 4**: Automated resolution and MTTR reduction

### Question 3: How do you access logs?
**Implementation Method**: `assess_log_access()`

**AWS Services to Check**:
- Cross-account log access (resource policies)
- IAM roles and policies for log access
- CloudWatch dashboards with log widgets
- Centralized logging account setup

**Maturity Level Checks**:
- **Level 1**: Basic centralized collection
- **Level 2**: Enterprise-wide visibility with prioritization
- **Level 3**: Single pane correlation and anomaly detection
- **Level 4**: Automated insights with proactive root cause

### Question 4: What is your log retention policy?
**Implementation Method**: `assess_log_retention()`

**AWS Services to Check**:
- CloudWatch Logs retention settings
- S3 lifecycle policies for archived logs
- Compliance tagging and governance
- Cost optimization through tiered storage

**Maturity Level Checks**:
- **Level 1**: Disparate retention policies
- **Level 2**: Enterprise-wide compliance-based policies
- **Level 3**: Automated archival with cost optimization
- **Level 4**: Easy retrieval with metadata-based search

## Metrics Category

### Question 5: What type of metrics do you collect?
**Implementation Method**: `assess_metrics_collection()`

**AWS Services to Check**:
1. Check default metrics for EC2 (AWS/EC2 namespace)
2. Check CloudWatch agent metrics namespace for custom metrics
3. Check if detailed monitoring enabled for EC2
4. Check default metrics for ECS (AWS/ECS namespace)
5. Check if container insights is enabled for ECS
6. Check default metrics for Lambda (AWS/Lambda)
7. Check if Lambda Insights is enabled
8. Check if container insights is enabled for EKS
9. Check if dimensions have been created on custom metrics (not default AWS service metrics)
10. Check number of dimensions is manageable (less than 10)
11. Check use of Application Signals


**Maturity Level Checks**:
- **Level 1**: Infrastructure metrics only (e.g cpu, memory, disk utilization)
- **Level 2**: Infrastructure metrics and application metrics (e.g latency, errors, volume)
- **Level 3**: Infrastructure metrics, application metrics, and custom metrics
- **Level 4**: In addition to infrastructure, application, and custom metrics, we include dimensions on all metrics to provide operators with critical metadata for diagnosing issues

### Question 6: How do you use metrics?
**Implementation Method**: `assess_metrics_usage()`

**AWS Services to Check**:
1. Check if dashboards have been created
2. Check if alarms have been created
3. Check if alarms have been created based on anomaly detection
4. Check metrics based autoscaling policies (if using EC2 Autoscaling)

**Maturity Level Checks**:
- **Level 1**: Manually explore metrics when diagnosing issues
- **Level 2**: Create dashboards that provide operational visibility, and alerting for operators to react manually to issues
- **Level 3**: Drive infrastructure automation to take corrective action. Conduct regular operational reviews to ensure high quality metrics and low signal to noise
- **Level 4**: Leverage AI/ML capabilities to proactively identify potential issues and anomalies

### Question 7: How do you access metrics?
**Implementation Method**: `assess_metrics_access()`

**AWS Services to Check**:
1. Check metrics-streams
2. Check cross-account dashboards
3. Check metrics-filters

**Maturity Level Checks**:
- **Level 1**: We have a centralized metric collection mechanism
- **Level 2**: Our centralized metric management provides enterprise-wide visibility into various data sources. Relevant teams are able to analyze and troubleshoot based on captured information and historical knowledge
- **Level 3**: Our centralized metric management uses correlation and anomaly detection to generate alerts. We are able to immediately determine the root cause of the issue through this correlation
- **Level 4**: With centralized metrics management, we are able to obtain insights into issues automatically with proactive root cause identification and also lay out resolution options to resolve issues

## Traces Category

### Question 8: How do you collect traces?
**Implementation Method**: `assess_traces_collection()`

**AWS Services to Check**:
1. Check Lambda TracingConfig
2. Check EC2 Xray daemon or Cloudwatch Agent configuration or ADOT or OpenTelemetry (Recommend moving to OpenTelemetry)
3. Check ECS Xray daemon or cloudwatch agent sidecar or ADOT or OpenTelemetry
4. Check EKS Xray daemon or cloudwatch agent or ADOT or OpenTelemetry
5. Check transaction search enabled (cloudwatch logs groups, indexing rules)
6. Check if custom annotations are being used
7. Check if sampling rules are configured

**Maturity Level Checks**:
- **Level 1**: Auto-instrumented SDKs for monitoring
- **Level 2**: Auto + manual instrumentation
- **Level 3**: End-to-end visibility with correlation
- **Level 4**: Automatic injection with proactive alerts

### Question 9: How do you use traces?
**Implementation Method**: `assess_traces_usage()`

**AWS Services to Check**:
1. Check if alarms are configured to detect trace latency spikes, error rates, volume, topology changes
2. Check if Cloudwatch RUM has Xray enabled
3. Check if Cloudwatch synthetics have Xray enabled
4. Check if sending to Application Signals
5. Check if X-Ray insights notifications have been configured
6. Check if Application Signals SLOs are configured
7. Check if Alarms are created based on SLOs
8. Check for combined metric and trace widgets on the same dashboard
9. Check for Dashboard variables that filter both metrics and traces simultaneously
10. Check for Alarms configured on X-Ray-derived metrics (e.g., ApproximateTraceCount, ErrorRate)
11. Check for Composite alarms combining X-Ray error rates with CloudWatch metrics
12. Check for SNS topics that receive both CloudWatch metric alarms and X-Ray anomaly notifications
13. Check for EventBridge rules that trigger on X-Ray insights events

**Maturity Level Checks**:
- **Level 1**: We have a centralized trace collection mechanism
- **Level 2**: We use traces to analyze and troubleshoot issues based on captured information and historical knowledge
- **Level 3**: We use traces, log events, and metrics from the infrastructure and applications to obtain a 360 view for correlation and anomaly detection
- **Level 4**: With centralized trace management, we are able to obtain insights into issues that cross application boundaries with proactive root cause identification

## Dashboards & Alerting Category

### Question 10: How do you use alarms?
**Implementation Method**: `assess_alarms_usage()`

**AWS Services to Check**:
1. Most dashboard and Alarms checks are covered in "how do you use" sections above
2. Check EC2 recommended alarms exist
3. Check ECS recommended alarms exist
4. Check EKS recommended alarms exist
5. Check RDS recommended alarms exist
6. Check for priority indicators in alarm names and descriptions (e.g. P1 P2 or Critical, High, Low)
7. Check for impact/customer context in alarm descriptions (customer, business, revenue)
8. Check for different notification channels by severity
9. Check for severity-based SNS topics (critical, high, low, sev)
10. Check for alarms created based on math expressions
11. Check basic threshold based alarms exist
12. Check alarms trigger SNS Topics
13. Check if composite alarms are used
14. Check if alarms trigger Systems Manager Incident Manager
15. Check if alarms trigger Systems Manager Ops Center
16. Check if alarms trigger Cloudwatch Investigations

**Maturity Level Checks**:
- **Level 1**: We use alarms with the notifications service to notify when metrics meet alarm specified triggers
- **Level 2**: By setting clear priority for alerts and notifications, we are able to understand the urgency of the issues and the impact of what it means for our customer
- **Level 3**: We've actionable alarms based on anomaly detection, which analyzes past metric data and creates a model of expected values. The expected values take into account hourly, daily, and weekly patterns in the metric
- **Level 4**: We combine several alarms into one composite alarm to create a summarized, aggregated health indicator over a whole application or group of resources. We reduce alarm noise by taking actions only at an aggregated level

### Question 11: How do you use dashboards?
**Implementation Method**: `assess_dashboards_usage()`

**AWS Services to Check**:
1. Check for parameterized/templated dashboards (input fields)
2. Check for correlation widgets (logs + metrics together)

**Maturity Level Checks**:
- **Level 1**: Basic resource monitoring
- **Level 2**: We have a single pane of glass dashboard giving visibility into various data sources with the ability to visualize issues based on well-defined criteria. This enables team members for faster communication flow during operational events
- **Level 3**: We can create flexible dashboards that can quickly display different content in multiple widgets, depending on the value of an input field within the dashboard enabling us for easier correlation and anomaly detection
- **Level 4**: In addition to standard dashboards, our solution automatically creates dynamic visualizations and these dashboards contain only the information that is relevant to the issue on hand. This enables us to save time and cost in querying and visualizing data that don't really matter

### Question 12: How adaptive are your alarm thresholds?
**Implementation Method**: `assess_adaptive_thresholds()`

**AWS Services to Check**:
1. Check for immediate triggering based on threshold (1 evaluation period, 1 datapoint)
2. Check for timebased triggering (> 1 evaluation or > 1 data points to alarm)
3. Check anomaly based alarms

**Maturity Level Checks**:
- **Level 1**: Alarms are triggered immediately when a metric exceeds a static threshold
- **Level 2**: Alarms are triggered when a metric exceeds a static threshold for a period of time
- **Level 3**: Alarms are triggered when a metric exhibits anomalous behavior
- **Level 4**: Our tool continuously analyzes metrics, determine normal baselines, and surface anomalies with minimal user intervention. Our tool is able to account for the seasonality and trend changes of metrics

## Organization Category

### Question 13: Do you have an enterprise observability strategy?
**Implementation Method**: `assess_enterprise_strategy()`

**AWS Services to Check**:
- Consistent tagging strategy
- Standardized naming conventions
- Governance policies
- Training and documentation

**Maturity Level Checks**:
- **Level 1**: Data collection strategy only
- **Level 2**: Unified tools and technologies
- **Level 3**: Best practices and training
- **Level 4**: Culture of continuous improvement

### Question 14: How do you use SLOs?
**Implementation Method**: `assess_slos_usage()`

**AWS Services to Check**:
- Service level objectives definition
- Error budget tracking
- SLI metric collection
- Business alignment documentation

**Maturity Level Checks**:
- **Level 1**: Team experimentation without adoption
- **Level 2**: Enterprise adoption for reliability
- **Level 3**: Prioritization for users and business
- **Level 4**: Integrated platforms with error budgets

### Question 15: Are you getting ROI from your observability tools?
**Implementation Method**: `assess_roi_optimization()`

**AWS Services to Check**:
- Cost optimization strategies
- Tool consolidation evidence
- Value measurement metrics
- Business impact documentation

**Maturity Level Checks**:
- **Level 1**: Want optimization without knowledge
- **Level 2**: Vendor consolidation attempts
- **Level 3**: Established validation policies
- **Level 4**: Business value and cost optimization

### Question 16: Do you use any AI/ML capability today?
**Implementation Method**: `assess_aiml_capabilities()`

**AWS Services to Check**:
1. Check DevOps Agent configured
2. Check CloudWatch Investigations configured
3. Check anomaly detection configured

**Maturity Level Checks**:
- **Level 1**: No AI/ML features
- **Level 2**: Natural language query capability
- **Level 3**: Automatic correlation and patterns
- **Level 4**: Comprehensive AI/ML with real-time

### Question 17: Do you have real end-user monitoring?
**Implementation Method**: `assess_real_user_monitoring()`

**AWS Services to Check**:
- CloudWatch Synthetics
- Real User Monitoring setup
- Client-side data collection
- Performance monitoring

**Maturity Level Checks**:
- **Level 1**: Test users for validation
- **Level 2**: Synthetic scripts on schedule
- **Level 3**: Scripted interaction tests with correlation
- **Level 4**: Real user monitoring with proactive anomalies

## Implementation Requirements

### Multi-Account Data Structure Updates
```python
@dataclass
class MultiAccountConfig:
    organization_id: str
    management_account: str
    target_accounts: List[str] = field(default_factory=list)
    target_ous: List[str] = field(default_factory=list)
    cross_account_role: str = "OrganizationAccountAccessRole"

@dataclass
class ObservabilityCheck:
    question_id: int
    category: str
    question: str
    current_level: int = 1
    target_level: int = 4
    evidence: List[str] = field(default_factory=list)
    remediation: str = ""
    maturity_descriptions: Dict[int, str] = field(default_factory=dict)
    account_id: str = ""  # Added for multi-account tracking

@dataclass
class OrganizationAssessmentResults:
    organization_id: str
    management_account: str
    account_results: Dict[str, AssessmentResults] = field(default_factory=dict)
    ou_scores: Dict[str, float] = field(default_factory=dict)
    organization_score: float = 0.0
```

### Scoring Algorithm
- Each question scored 1-4 based on maturity level achieved
- Category scores: average of questions in category
- Overall score: weighted average of all categories
- Maturity mapping: 1.0-1.9 (Initial), 2.0-2.9 (Developing), 3.0-3.9 (Defined), 4.0 (Optimized)

### Report Generation
- HTML report with maturity level visualization
- Category-specific recommendations
- Roadmap for advancing to next maturity level
- Evidence-based scoring with AWS resource validation
