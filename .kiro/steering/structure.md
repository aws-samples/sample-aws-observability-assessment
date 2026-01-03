# Project Structure

## Repository Layout
```
resco-observability/
├── observability_assessment_comprehensive.py  # Main assessment tool
├── assessment_questions_and_answers.csv      # Assessment criteria reference
├── README.md                                 # Project documentation
└── .kiro/steering/                          # Project guidance
    ├── product.md                           # Product vision
    ├── tech.md                              # Technical architecture
    ├── structure.md                         # This file
    └── assessment_mapping.md                # Question-to-implementation mapping
```

## Code Organization

### Multi-Account Execution Flow
1. **Discovery Phase**: List organization accounts and OUs
2. **Role Validation**: Verify cross-account access permissions
3. **Parallel Assessment**: Execute checks across multiple accounts
4. **Aggregation**: Combine results by OU and organization level
5. **Reporting**: Multi-level reporting (account/OU/organization)

### Main Module (`observability_assessment_comprehensive.py`)
- **Entry Point**: `main()` function with CLI argument parsing
- **Core Class**: `ComprehensiveObservabilityAssessment`
- **Data Models**: `ObservabilityCheck` and `AssessmentResults` dataclasses
- **Assessment Methods**: 17 individual assessment functions
- **Reporting**: HTML generation with maturity-level visualization

### Assessment Question Mapping

#### Logs Category (Questions 1-4)
1. **Log Collection Assessment** (`assess_log_collection`)
   - Level 1: Basic CloudWatch Logs collection
   - Level 2: Centralized collection with analytics
   - Level 3: Correlation and anomaly detection
   - Level 4: Automated insights and resolution

2. **Log Usage Assessment** (`assess_log_usage`)
   - Level 1: Manual diagnostics and troubleshooting
   - Level 2: Faster analysis with structured access
   - Level 3: Correlation for faster anomaly detection
   - Level 4: Automated insights and MTTR reduction

3. **Log Access Assessment** (`assess_log_access`)
   - Level 1: Centralized collection mechanism
   - Level 2: Enterprise-wide visibility with prioritization
   - Level 3: Single pane correlation and anomaly detection
   - Level 4: Automated insights with proactive root cause

4. **Log Retention Assessment** (`assess_log_retention`)
   - Level 1: Disparate systems with department policies
   - Level 2: Enterprise-wide compliance-based policies
   - Level 3: Automated archival with cost optimization
   - Level 4: Easy retrieval with metadata-based search

#### Metrics Category (Questions 5-7)
5. **Metrics Collection Assessment** (`assess_metrics_collection`)
   - Level 1: Infrastructure metrics only (e.g cpu, memory, disk utilization)
   - Level 2: Infrastructure metrics and application metrics (e.g latency, errors, volume)
   - Level 3: Infrastructure metrics, application metrics, and custom metrics
   - Level 4: In addition to infrastructure, application, and custom metrics, we include dimensions on all metrics to provide operators with critical metadata for diagnosing issues

   **Specific AWS Checks**:
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


6. **Metrics Usage Assessment** (`assess_metrics_usage`)
   - Level 1: Manually explore metrics when diagnosing issues
   - Level 2: Create dashboards that provide operational visibility, and alerting for operators to react manually to issues
   - Level 3: Drive infrastructure automation to take corrective action. Conduct regular operational reviews to ensure high quality metrics and low signal to noise
   - Level 4: Leverage AI/ML capabilities to proactively identify potential issues and anomalies

   **Specific AWS Checks**:
   1. Check if dashboards have been created
   2. Check if alarms have been created
   3. Check if alarms have been created based on anomaly detection
   4. Check metrics based autoscaling policies (if using EC2 Autoscaling)

7. **Metrics Access Assessment** (`assess_metrics_access`)
   - Level 1: We have a centralized metric collection mechanism
   - Level 2: Our centralized metric management provides enterprise-wide visibility into various data sources. Relevant teams are able to analyze and troubleshoot based on captured information and historical knowledge
   - Level 3: Our centralized metric management uses correlation and anomaly detection to generate alerts. We are able to immediately determine the root cause of the issue through this correlation
   - Level 4: With centralized metrics management, we are able to obtain insights into issues automatically with proactive root cause identification and also lay out resolution options to resolve issues

   **Specific AWS Checks**:
   1. Check metrics-streams
   2. Check cross-account dashboards
   3. Check metrics-filters

#### Traces Category (Questions 8-9)
8. **Traces Collection Assessment** (`assess_traces_collection`)
   - Level 1: Auto-instrumented SDKs for monitoring
   - Level 2: Auto + manual instrumentation
   - Level 3: End-to-end visibility with correlation
   - Level 4: Automatic injection with proactive alerts

   **Specific AWS Checks**:
   1. Check Lambda TracingConfig
   2. Check EC2 Xray daemon or Cloudwatch Agent configuration or ADOT or OpenTelemetry (Recommend moving to OpenTelemetry)
   3. Check ECS Xray daemon or cloudwatch agent sidecar or ADOT or OpenTelemetry
   4. Check EKS Xray daemon or cloudwatch agent or ADOT or OpenTelemetry
   5. Check transaction search enabled (cloudwatch logs groups, indexing rules)
   6. Check if custom annotations are being used
   7. Check if sampling rules are configured

9. **Traces Usage Assessment** (`assess_traces_usage`)
   - Level 1: We have a centralized trace collection mechanism
   - Level 2: We use traces to analyze and troubleshoot issues based on captured information and historical knowledge
   - Level 3: We use traces, log events, and metrics from the infrastructure and applications to obtain a 360 view for correlation and anomaly detection
   - Level 4: With centralized trace management, we are able to obtain insights into issues that cross application boundaries with proactive root cause identification

   **Specific AWS Checks**:
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

#### Dashboards & Alerting Category (Questions 10-12)
10. **Alarms Assessment** (`assess_alarms_usage`)
    - Level 1: We use alarms with the notifications service to notify when metrics meet alarm specified triggers
    - Level 2: By setting clear priority for alerts and notifications, we are able to understand the urgency of the issues and the impact of what it means for our customer
    - Level 3: We've actionable alarms based on anomaly detection, which analyzes past metric data and creates a model of expected values. The expected values take into account hourly, daily, and weekly patterns in the metric
    - Level 4: We combine several alarms into one composite alarm to create a summarized, aggregated health indicator over a whole application or group of resources. We reduce alarm noise by taking actions only at an aggregated level

    **Specific AWS Checks**:
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

11. **Dashboards Assessment** (`assess_dashboards_usage`)
    - Level 1: Basic resource monitoring
    - Level 2: We have a single pane of glass dashboard giving visibility into various data sources with the ability to visualize issues based on well-defined criteria. This enables team members for faster communication flow during operational events
    - Level 3: We can create flexible dashboards that can quickly display different content in multiple widgets, depending on the value of an input field within the dashboard enabling us for easier correlation and anomaly detection
    - Level 4: In addition to standard dashboards, our solution automatically creates dynamic visualizations and these dashboards contain only the information that is relevant to the issue on hand. This enables us to save time and cost in querying and visualizing data that don't really matter

    **Specific AWS Checks**:
    1. Check for parameterized/templated dashboards (input fields)
    2. Check for correlation widgets (logs + metrics together)

12. **Adaptive Thresholds Assessment** (`assess_adaptive_thresholds`)
    - Level 1: Alarms are triggered immediately when a metric exceeds a static threshold
    - Level 2: Alarms are triggered when a metric exceeds a static threshold for a period of time
    - Level 3: Alarms are triggered when a metric exhibits anomalous behavior
    - Level 4: Our tool continuously analyzes metrics, determine normal baselines, and surface anomalies with minimal user intervention. Our tool is able to account for the seasonality and trend changes of metrics

    **Specific AWS Checks**:
    1. Check for immediate triggering based on threshold (1 evaluation period, 1 datapoint)
    2. Check for timebased triggering (> 1 evaluation or > 1 data points to alarm)
    3. Check anomaly based alarms

#### Organization Category (Questions 13-17)
13. **Enterprise Strategy Assessment** (`assess_enterprise_strategy`)
    - Level 1: Data collection strategy only
    - Level 2: Unified tools and technologies
    - Level 3: Best practices and training
    - Level 4: Culture of continuous improvement

14. **SLOs Assessment** (`assess_slos_usage`)
    - Level 1: Team experimentation without adoption
    - Level 2: Enterprise adoption for reliability
    - Level 3: Prioritization for users and business
    - Level 4: Integrated platforms with error budgets

15. **ROI Assessment** (`assess_roi_optimization`)
    - Level 1: Want optimization without knowledge
    - Level 2: Vendor consolidation attempts
    - Level 3: Established validation policies
    - Level 4: Business value and cost optimization

16. **AI/ML Assessment** (`assess_aiml_capabilities`)
    - Level 1: No AI/ML features
    - Level 2: Natural language query capability
    - Level 3: Automatic correlation and patterns
    - Level 4: Comprehensive AI/ML with real-time

    **Specific AWS Checks**:
    1. Check DevOps Agent configured
    2. Check CloudWatch Investigations configured
    3. Check anomaly detection configured

17. **RUM Assessment** (`assess_real_user_monitoring`)
    - Level 1: Test users for validation
    - Level 2: Synthetic scripts on schedule
    - Level 3: Scripted interaction tests with correlation
    - Level 4: Real user monitoring with proactive anomalies

## Development Patterns
- **Maturity-driven**: Each assessment maps to 4 progressive levels
- **Evidence-based**: Concrete AWS resource checks for validation
- **Comprehensive**: All 17 questions from CSV fully implemented
- **Extensible**: Easy addition of new assessment categories
- **Actionable**: Specific remediation for each maturity gap