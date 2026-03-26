# Technical Architecture

## Core Technology Stack
- **Language**: Python 3.x
- **AWS Integration**: boto3/AWS CLI
- **Output Format**: HTML with embedded CSS
- **Data Structure**: Dataclasses for type safety
- **Output Directory**: All assessment reports and outputs must be saved to `sample-result/` folder

## Architecture Components

### Multi-Account Assessment Engine (`ComprehensiveObservabilityAssessment`)
- Organization discovery and account enumeration
- Cross-account role assumption for assessment execution
- Parallel assessment across multiple accounts and OUs
- Aggregated scoring and reporting at organization level

#### Cross-Account Data Collection
```python
def assume_cross_account_role(account_id: str, role_name: str):
    sts = boto3.client('sts')
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    return sts.assume_role(RoleArn=role_arn, RoleSessionName="ObservabilityAssessment")
```

#### Organization Discovery
```bash
# List organization accounts
aws organizations list-accounts --query 'Accounts[?Status==`ACTIVE`]'

# Get OU structure
aws organizations list-organizational-units-for-parent --parent-id <root-id>
```

### Assessment Engine (`ComprehensiveObservabilityAssessment`)
- Modular check system covering all 17 assessment questions
- AWS CLI command execution with error handling
- Cross-region and multi-profile support
- Timeout protection for API calls

### Assessment Categories

#### 1. Logs Assessment (Questions 1-4)
- **Collection**: CloudWatch Logs, structured logging, auto-instrumentation
- **Usage**: From diagnostics to automated insights and correlation
- **Access**: Centralized management with enterprise visibility
- **Retention**: Compliance policies and archival solutions

#### 2. Metrics Assessment (Questions 5-7)
- **Collection**: Infrastructure, application, custom, and dimensional metrics
- **Usage**: From manual exploration to AI/ML-driven automation
- **Access**: Centralized collection with anomaly detection

#### 3. Traces Assessment (Questions 8-9)
- **Collection**: Auto-instrumentation to automatic injection
- **Usage**: From basic collection to cross-boundary insights with correlation

#### 4. Dashboards & Alerting Assessment (Questions 10-12)
- **Alarms**: From basic notifications to composite alarms
- **Dashboards**: From monitoring to dynamic visualizations
- **Thresholds**: From static to ML-based adaptive thresholds

#### 5. Organization Assessment (Questions 13-17)
- **Strategy**: Enterprise observability alignment and culture
- **SLOs**: From experimentation to business integration
- **ROI**: Cost optimization and business value realization
- **AI/ML**: Natural language queries to proactive anomaly detection
- **RUM**: From test users to real-time user monitoring

### Data Models
```python
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

@dataclass
class AssessmentResults:
    account_id: str = ""
    user_arn: str = ""
    checks: List[ObservabilityCheck] = field(default_factory=list)
    category_scores: Dict[str, float] = field(default_factory=dict)
    overall_score: float = 0.0
    maturity_level: str = ""
    timestamp: str = ""
```

### Maturity Level Mapping
- **Level 1 (Initial)**: Basic collection and reactive approaches
- **Level 2 (Developing)**: Centralized management with analysis capabilities
- **Level 3 (Defined)**: Correlation, automation, and proactive detection
- **Level 4 (Optimized)**: AI-driven insights, automatic resolution, business alignment

### Assessment Implementation
Each of the 17 questions maps to specific AWS service checks:

1. **Logs Collection**: CloudWatch Logs groups, agents, structured formats
2. **Logs Usage**: Insights queries, correlation patterns, automation triggers
3. **Logs Access**: Cross-account access, RBAC, centralized dashboards
4. **Log Retention**: Lifecycle policies, archival to S3, compliance settings
5. **Metrics Types**: CloudWatch metrics, custom metrics, dimensions
6. **Metrics Usage**: Dashboards, alarms, automation, ML anomaly detection
7. **Metrics Access**: Cross-account metrics, unified dashboards
8. **Traces Collection**: X-Ray integration, auto-instrumentation
9. **Traces Usage**: Service maps, performance analysis, error correlation
10. **Alarms**: CloudWatch alarms, composite alarms, SNS integration
11. **Dashboards**: CloudWatch dashboards, custom widgets, dynamic content
12. **Adaptive Thresholds**: Anomaly detection models, ML-based alerting
13. **Enterprise Strategy**: Tagging, governance, standardization
14. **SLOs**: Service level objectives, error budgets, business alignment
15. **ROI**: Cost optimization, tool consolidation, value measurement
16. **AI/ML**: Natural language queries, anomaly detection, insights
17. **RUM**: Real user monitoring, synthetic monitoring, client-side data

## Key Design Decisions
- **Comprehensive coverage**: All 17 assessment questions implemented
- **Maturity-driven**: 4-level progression for each capability
- **Evidence-based**: Concrete AWS resource checks for each assessment
- **Actionable**: Specific remediation steps for maturity advancement
- **Scalable**: Modular design for easy extension and customization