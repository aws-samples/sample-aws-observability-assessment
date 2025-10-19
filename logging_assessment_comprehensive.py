#!/usr/bin/env python3

import json
import subprocess
import sys
import time
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
import argparse

@dataclass
class Check:
    name: str
    status: str = "incomplete"
    priority: str = "Medium"
    remediation: str = ""
    evidence: List[str] = field(default_factory=list)

@dataclass
class AssessmentResults:
    account_id: str = ""
    user_arn: str = ""
    checks: List[Check] = field(default_factory=list)
    overall_score: float = 0.0
    maturity_level: str = ""
    timestamp: str = ""

class ComprehensiveLoggingAssessment:
    def __init__(self, profile=None, region='us-west-2'):
        self.profile = profile
        self.region = region
        self.results = AssessmentResults()
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.html_file = f"logging_assessment_report_{self.timestamp}.html"
        
    def run_aws_command(self, command):
        """Execute AWS CLI command and return result"""
        if self.profile:
            command = command.replace("aws ", f"aws --profile {self.profile} ")
        
        # Add region to command if not already present
        if "--region" not in command:
            command = command.replace(" --output", f" --region {self.region} --output")
        
        try:
            result = subprocess.run(command.split(), capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                return json.loads(result.stdout) if result.stdout.strip() else {}
            return None
        except:
            return None

    def get_aws_identity(self):
        """Get AWS account identity"""
        identity = self.run_aws_command("aws sts get-caller-identity --output json")
        if identity:
            self.results.account_id = identity.get('Account', 'Unknown')
            self.results.user_arn = identity.get('Arn', 'Unknown')
            return True
        return False

    def check_log_groups(self):
        """1.1 Check Log Groups"""
        check = Check(
            name="Log Groups Collection",
            priority="High",
            remediation="Enable CloudWatch Logs for all services and applications"
        )
        
        log_groups = self.run_aws_command("aws logs describe-log-groups --output json")
        if log_groups and 'logGroups' in log_groups:
            count = len(log_groups['logGroups'])
            check.evidence.append(f"Found {count} CloudWatch log groups")
            check.status = "complete" if count > 10 else "incomplete"
        
        self.results.checks.append(check)

    def check_ec2_logging(self):
        """1.2 EC2 Instance Logging"""
        check = Check(
            name="EC2 CloudWatch Agent",
            priority="High", 
            remediation="Install and configure CloudWatch agent on EC2 instances with proper IAM permissions"
        )
        
        instances = self.run_aws_command("aws ec2 describe-instances --output json")
        if instances and 'Reservations' in instances:
            instance_count = sum(len(r['Instances']) for r in instances['Reservations'])
            check.evidence.append(f"Found {instance_count} EC2 instances in {self.region}")
            
            # Check instance profiles and IAM policies
            instances_with_cw_policy = 0
            for reservation in instances['Reservations']:
                for instance in reservation['Instances']:
                    iam_profile_arn = instance.get('IamInstanceProfile', {}).get('Arn', '')
                    if iam_profile_arn:
                        profile_name = iam_profile_arn.split('/')[-1]
                        # Get role name from instance profile
                        profile_info = self.run_aws_command(f"aws iam get-instance-profile --instance-profile-name {profile_name} --output json")
                        if profile_info and 'InstanceProfile' in profile_info:
                            roles = profile_info['InstanceProfile'].get('Roles', [])
                            if roles:
                                role_name = roles[0]['RoleName']
                                # Check if role has CloudWatch agent policy
                                policies = self.run_aws_command(f"aws iam list-attached-role-policies --role-name {role_name} --output json")
                                if policies and 'AttachedPolicies' in policies:
                                    for policy in policies['AttachedPolicies']:
                                        if 'CloudWatchAgent' in policy['PolicyName']:
                                            instances_with_cw_policy += 1
                                            break
            
            check.evidence.append(f"{instances_with_cw_policy} instances have CloudWatch agent IAM policy")
            
            # Check for CloudWatch agent log groups
            cw_agent_logs = self.run_aws_command("aws logs describe-log-groups --log-group-name-prefix '/aws/amazoncloudwatch-agent' --output json")
            agent_count = 0
            if cw_agent_logs and 'logGroups' in cw_agent_logs:
                agent_count = len(cw_agent_logs['logGroups'])
                check.evidence.append(f"Found {agent_count} CloudWatch agent log groups")
            
            check.status = "complete" if instances_with_cw_policy > 0 else "incomplete"
        
        self.results.checks.append(check)

    def check_eks_control_plane_logging(self):
        """1.3a EKS Control Plane Logging"""
        check = Check(
            name="EKS Control Plane Logging",
            priority="High",
            remediation="Enable EKS control plane logging for API server, audit, authenticator, controller manager, and scheduler"
        )
        
        clusters = self.run_aws_command("aws eks list-clusters --output json")
        if clusters and 'clusters' in clusters:
            cluster_count = len(clusters['clusters'])
            check.evidence.append(f"Found {cluster_count} EKS clusters")
            
            control_plane_enabled = 0
            for cluster_name in clusters['clusters']:
                cluster_info = self.run_aws_command(f"aws eks describe-cluster --name {cluster_name} --output json")
                if cluster_info and 'cluster' in cluster_info:
                    logging_config = cluster_info['cluster'].get('logging', {}).get('clusterLogging', [])
                    for log_config in logging_config:
                        if log_config.get('enabled') and log_config.get('types'):
                            control_plane_enabled += 1
                            break
            
            check.evidence.append(f"{control_plane_enabled} clusters have control plane logging enabled")
            
            # Check EKS control plane log groups
            eks_logs = self.run_aws_command("aws logs describe-log-groups --log-group-name-prefix '/aws/eks' --output json")
            if eks_logs and 'logGroups' in eks_logs:
                eks_log_count = len(eks_logs['logGroups'])
                check.evidence.append(f"Found {eks_log_count} EKS control plane log groups")
            
            check.status = "complete" if control_plane_enabled > 0 else "incomplete"
        
        self.results.checks.append(check)

    def check_eks_workload_logging(self):
        """1.3b EKS Workload Logging"""
        check = Check(
            name="EKS Workload Logging (Container Insights & ADOT)",
            priority="High",
            remediation="Enable Container Insights and configure ADOT operator for comprehensive workload observability"
        )
        
        clusters = self.run_aws_command("aws eks list-clusters --output json")
        if clusters and 'clusters' in clusters:
            cluster_count = len(clusters['clusters'])
            check.evidence.append(f"Found {cluster_count} EKS clusters")
            
            adot_count = 0
            for cluster_name in clusters['clusters']:
                adot_result = self.run_aws_command(f"aws eks describe-addon --cluster-name {cluster_name} --addon-name adot --output json")
                if adot_result and 'addon' in adot_result:
                    adot_count += 1
            
            check.evidence.append(f"{adot_count} clusters have ADOT operator configured")
            
            # Check Container Insights log groups
            ci_logs = self.run_aws_command("aws logs describe-log-groups --log-group-name-prefix '/aws/containerinsights' --output json")
            if ci_logs and 'logGroups' in ci_logs:
                ci_log_count = len(ci_logs['logGroups'])
                check.evidence.append(f"Container Insights enabled: Found {ci_log_count} Container Insights log groups")
                check.status = "complete" if ci_log_count > 0 or adot_count > 0 else "incomplete"
        
        self.results.checks.append(check)

    def check_ecs_logging(self):
        """1.4 ECS Task Definition Logging"""
        check = Check(
            name="ECS Task Definition Logging",
            priority="Medium",
            remediation="Configure awslogs driver in ECS task definitions for all containers"
        )
        
        clusters = self.run_aws_command("aws ecs list-clusters --output json")
        if clusters and 'clusterArns' in clusters:
            cluster_count = len(clusters['clusterArns'])
            check.evidence.append(f"Found {cluster_count} ECS clusters")
            
            tasks_with_logging = 0
            total_tasks = 0
            
            for cluster_arn in clusters['clusterArns']:
                cluster_name = cluster_arn.split('/')[-1]
                # Get task definitions for this cluster
                task_arns = self.run_aws_command(f"aws ecs list-tasks --cluster {cluster_name} --output json")
                if task_arns and 'taskArns' in task_arns:
                    for task_arn in task_arns['taskArns'][:5]:  # Check first 5 tasks
                        task_info = self.run_aws_command(f"aws ecs describe-tasks --cluster {cluster_name} --tasks {task_arn} --output json")
                        if task_info and 'tasks' in task_info and task_info['tasks']:
                            task_def_arn = task_info['tasks'][0].get('taskDefinitionArn', '')
                            if task_def_arn:
                                task_def_name = task_def_arn.split('/')[-1]
                                task_def = self.run_aws_command(f"aws ecs describe-task-definition --task-definition {task_def_name} --output json")
                                if task_def and 'taskDefinition' in task_def:
                                    total_tasks += 1
                                    containers = task_def['taskDefinition'].get('containerDefinitions', [])
                                    for container in containers:
                                        log_config = container.get('logConfiguration', {})
                                        if log_config.get('logDriver') == 'awslogs':
                                            tasks_with_logging += 1
                                            break
            
            check.evidence.append(f"{tasks_with_logging}/{total_tasks} task definitions use awslogs driver")
            
            # Check ECS log groups
            ecs_logs = self.run_aws_command("aws logs describe-log-groups --log-group-name-prefix '/ecs' --output json")
            if ecs_logs and 'logGroups' in ecs_logs:
                ecs_log_count = len(ecs_logs['logGroups'])
                check.evidence.append(f"Found {ecs_log_count} ECS log groups")
            
            check.status = "complete" if tasks_with_logging > 0 else "incomplete"
        
        self.results.checks.append(check)

    def check_lambda_logging(self):
        """1.5 Lambda Logging"""
        check = Check(
            name="Lambda Function Logs",
            priority="Medium",
            remediation="Ensure Lambda functions have proper logging configuration"
        )
        
        lambda_logs = self.run_aws_command("aws logs describe-log-groups --log-group-name-prefix '/aws/lambda' --output json")
        if lambda_logs and 'logGroups' in lambda_logs:
            lambda_count = len(lambda_logs['logGroups'])
            check.evidence.append(f"Found {lambda_count} Lambda log groups")
            check.status = "complete" if lambda_count > 0 else "incomplete"
        
        self.results.checks.append(check)

    def check_rds_logging(self):
        """1.6 RDS Logging"""
        check = Check(
            name="RDS Database Logs",
            priority="Medium",
            remediation="Enable CloudWatch Logs exports for RDS instances"
        )
        
        rds_instances = self.run_aws_command("aws rds describe-db-instances --output json")
        if rds_instances and 'DBInstances' in rds_instances:
            instance_count = len(rds_instances['DBInstances'])
            check.evidence.append(f"Found {instance_count} RDS instances")
            
            enabled_count = 0
            for instance in rds_instances['DBInstances']:
                if instance.get('EnabledCloudwatchLogsExports'):
                    enabled_count += 1
            
            check.evidence.append(f"{enabled_count} instances have CloudWatch logs enabled")
            check.status = "complete" if enabled_count > 0 else "incomplete"
        
        self.results.checks.append(check)

    def check_aurora_logging(self):
        """1.7 Aurora Logging"""
        check = Check(
            name="Aurora Cluster Logs",
            priority="Medium",
            remediation="Enable CloudWatch Logs exports for Aurora clusters (audit, error, general, slowquery for MySQL; postgresql for PostgreSQL)"
        )
        
        # Check Aurora cluster log groups
        aurora_cluster_logs = self.run_aws_command("aws logs describe-log-groups --log-group-name-prefix '/aws/rds/cluster' --output json")
        cluster_log_count = 0
        if aurora_cluster_logs and 'logGroups' in aurora_cluster_logs:
            cluster_log_count = len(aurora_cluster_logs['logGroups'])
            check.evidence.append(f"Found {cluster_log_count} Aurora cluster log groups")
        
        # Check Aurora instance log groups
        aurora_instance_logs = self.run_aws_command("aws logs describe-log-groups --log-group-name-prefix '/aws/rds/instance' --output json")
        instance_log_count = 0
        if aurora_instance_logs and 'logGroups' in aurora_instance_logs:
            aurora_instance_groups = [lg for lg in aurora_instance_logs['logGroups'] if 'aurora' in lg['logGroupName']]
            instance_log_count = len(aurora_instance_groups)
            if instance_log_count > 0:
                check.evidence.append(f"Found {instance_log_count} Aurora instance log groups")
        
        # Check Aurora clusters and their logging configuration
        aurora_clusters = self.run_aws_command("aws rds describe-db-clusters --output json")
        clusters_with_logging = 0
        if aurora_clusters and 'DBClusters' in aurora_clusters:
            aurora_only = [c for c in aurora_clusters['DBClusters'] if c.get('Engine', '').startswith('aurora')]
            cluster_count = len(aurora_only)
            check.evidence.append(f"Found {cluster_count} Aurora clusters")
            
            for cluster in aurora_only:
                if cluster.get('EnabledCloudwatchLogsExports'):
                    clusters_with_logging += 1
            
            check.evidence.append(f"{clusters_with_logging} clusters have CloudWatch logs enabled")
        
        check.status = "complete" if clusters_with_logging > 0 or cluster_log_count > 0 or instance_log_count > 0 else "incomplete"
        self.results.checks.append(check)

    def check_vpc_flow_logs(self):
        """1.9 VPC Flow Logs"""
        check = Check(
            name="VPC Flow Logs",
            priority="High",
            remediation="Enable VPC Flow Logs for network monitoring and security"
        )
        
        flow_logs = self.run_aws_command("aws ec2 describe-flow-logs --output json")
        if flow_logs and 'FlowLogs' in flow_logs:
            flow_count = len(flow_logs['FlowLogs'])
            check.evidence.append(f"Found {flow_count} VPC Flow Logs")
            check.status = "complete" if flow_count > 0 else "incomplete"
        
        self.results.checks.append(check)

    def check_structured_logging(self):
        """2. Check Structured Logging"""
        check = Check(
            name="Structured Logging Usage",
            priority="Medium",
            remediation="Implement JSON structured logging in applications for better parsing and analysis"
        )
        
        # Get all log groups
        log_groups = self.run_aws_command("aws logs describe-log-groups --output json")
        if log_groups and 'logGroups' in log_groups:
            total_groups = len(log_groups['logGroups'])
            structured_count = 0
            unstructured_count = 0
            empty_count = 0
            
            # Analyze ALL log groups
            for lg in log_groups['logGroups']:
                log_group_name = lg['logGroupName']
                
                # Get most recent log stream
                streams = self.run_aws_command(f"aws logs describe-log-streams --log-group-name '{log_group_name}' --order-by LastEventTime --descending --limit 1 --output json")
                if streams and 'logStreams' in streams and streams['logStreams']:
                    stream_name = streams['logStreams'][0]['logStreamName']
                    
                    # Get sample log event
                    events = self.run_aws_command(f"aws logs get-log-events --log-group-name '{log_group_name}' --log-stream-name '{stream_name}' --limit 1 --output json")
                    if events and 'events' in events and events['events']:
                        message = events['events'][0]['message']
                        
                        # Check if message is JSON
                        try:
                            json.loads(message)
                            structured_count += 1
                        except:
                            unstructured_count += 1
                    else:
                        empty_count += 1
                else:
                    empty_count += 1
            
            check.evidence.append(f"Analyzed all {total_groups} log groups")
            check.evidence.append(f"{structured_count} groups have JSON-structured logs")
            check.evidence.append(f"{unstructured_count} groups have unstructured logs")
            
            if empty_count > 0:
                check.evidence.append(f"{empty_count} groups are empty or have no recent events")
            
            # Consider complete if >30% of active groups are structured
            active_groups = structured_count + unstructured_count
            completion_rate = structured_count / max(1, active_groups) if active_groups > 0 else 0
            check.status = "complete" if completion_rate > 0.3 else "incomplete"
        
        self.results.checks.append(check)

    def check_anomaly_detection(self):
        """3. Check Logs Anomaly Detection"""
        check = Check(
            name="CloudWatch Logs Anomaly Detection",
            priority="Low",
            remediation="Enable CloudWatch Logs Anomaly Detection for proactive monitoring"
        )
        
        anomaly_detectors = self.run_aws_command("aws logs list-log-anomaly-detectors --output json")
        if anomaly_detectors and 'anomalyDetectors' in anomaly_detectors:
            detector_count = len(anomaly_detectors['anomalyDetectors'])
            check.evidence.append(f"Found {detector_count} anomaly detectors")
            check.status = "complete" if detector_count > 0 else "incomplete"
        
        self.results.checks.append(check)

    def check_logs_insights(self):
        """4. Check Logs Insights Usage"""
        check = Check(
            name="CloudWatch Logs Insights Queries",
            priority="Medium",
            remediation="Create saved queries in CloudWatch Logs Insights for common investigations"
        )
        
        saved_queries = self.run_aws_command("aws logs describe-query-definitions --output json")
        if saved_queries and 'queryDefinitions' in saved_queries:
            query_count = len(saved_queries['queryDefinitions'])
            check.evidence.append(f"Found {query_count} saved Logs Insights queries")
            check.status = "complete" if query_count > 0 else "incomplete"
        
        self.results.checks.append(check)

    def check_field_indexes(self):
        """4a. Check Field Index Policies"""
        check = Check(
            name="CloudWatch Logs Field Index Policies",
            priority="Low",
            remediation="Create field index policies for frequently queried log fields to improve Logs Insights performance"
        )
        
        # Get all log groups
        log_groups = self.run_aws_command("aws logs describe-log-groups --output json")
        if log_groups and 'logGroups' in log_groups:
            total_groups = len(log_groups['logGroups'])
            groups_with_policies = 0
            groups_with_indexes = 0
            
            # Check each log group for field index policies and automatic indexes
            for lg in log_groups['logGroups'][:10]:  # Sample first 10 to avoid timeout
                log_group_name = lg['logGroupName']
                
                # Check for custom field index policies
                field_policies = self.run_aws_command(f"aws logs describe-index-policies --log-group-identifiers '{log_group_name}' --output json")
                if field_policies and 'indexPolicies' in field_policies and field_policies['indexPolicies']:
                    groups_with_policies += 1
                
                # Check for field indexes (including automatic ones)
                field_indexes = self.run_aws_command(f"aws logs get-log-group-fields --log-group-name '{log_group_name}' --output json")
                if field_indexes and 'logGroupFields' in field_indexes and field_indexes['logGroupFields']:
                    groups_with_indexes += 1
            
            check.evidence.append(f"Checked {min(10, total_groups)} log groups from {total_groups} total")
            check.evidence.append(f"{groups_with_policies} log groups have custom field index policies")
            check.evidence.append(f"{groups_with_indexes} log groups have field indexes (including automatic)")
            
            check.status = "complete" if groups_with_policies > 0 or groups_with_indexes > 0 else "incomplete"
        
        self.results.checks.append(check)

    def check_metric_filters(self):
        """6. Check Metric Filters and Alarms"""
        check = Check(
            name="Log-based Metric Filters & Alarms",
            priority="High",
            remediation="Create metric filters from logs and set up CloudWatch alarms"
        )
        
        metric_filters = self.run_aws_command("aws logs describe-metric-filters --output json")
        if metric_filters and 'metricFilters' in metric_filters:
            filter_count = len(metric_filters['metricFilters'])
            check.evidence.append(f"Found {filter_count} metric filters")
            check.status = "complete" if filter_count > 0 else "incomplete"
        
        self.results.checks.append(check)

    def check_subscription_filters(self):
        """12. Check Subscription Filters"""
        check = Check(
            name="Log Subscription Filters",
            priority="Medium",
            remediation="Set up subscription filters to stream logs to other services"
        )
        
        # Check a sample of log groups for subscription filters
        log_groups = self.run_aws_command("aws logs describe-log-groups --max-items 20 --output json")
        if log_groups and 'logGroups' in log_groups:
            subscription_count = 0
            for lg in log_groups['logGroups'][:5]:  # Check first 5
                filters = self.run_aws_command(f"aws logs describe-subscription-filters --log-group-name '{lg['logGroupName']}' --output json")
                if filters and 'subscriptionFilters' in filters and filters['subscriptionFilters']:
                    subscription_count += len(filters['subscriptionFilters'])
            
            check.evidence.append(f"Found {subscription_count} subscription filters")
            check.status = "complete" if subscription_count > 0 else "incomplete"
        
        self.results.checks.append(check)

    def check_log_retention(self):
        """14. Check Log Retention Settings"""
        check = Check(
            name="Log Retention Policies",
            priority="High",
            remediation="Set appropriate retention periods for all log groups based on compliance requirements"
        )
        
        log_groups = self.run_aws_command("aws logs describe-log-groups --output json")
        if log_groups and 'logGroups' in log_groups:
            retention_stats = {}
            for lg in log_groups['logGroups']:
                retention = lg.get('retentionInDays', 'Never expire')
                retention_stats[retention] = retention_stats.get(retention, 0) + 1
            
            check.evidence.append(f"Retention analysis: {retention_stats}")
            # Consider it complete if most groups have retention set
            never_expire = retention_stats.get('Never expire', 0)
            total = len(log_groups['logGroups'])
            check.status = "complete" if never_expire < total * 0.5 else "incomplete"
        
        self.results.checks.append(check)

    def check_opensearch_integration(self):
        """17. Check OpenSearch for Archived Logs"""
        check = Check(
            name="OpenSearch/Elasticsearch Integration",
            priority="Low",
            remediation="Set up OpenSearch for advanced log analytics and long-term storage"
        )
        
        opensearch_domains = self.run_aws_command("aws opensearch list-domain-names --output json")
        if opensearch_domains and 'DomainNames' in opensearch_domains:
            domain_count = len(opensearch_domains['DomainNames'])
            check.evidence.append(f"Found {domain_count} OpenSearch domains")
            check.status = "complete" if domain_count > 0 else "incomplete"
        
        self.results.checks.append(check)

    def run_assessment(self):
        """Run the complete assessment"""
        print("🚀 AWS Comprehensive Logging Assessment")
        print("=" * 80)
        
        if not self.get_aws_identity():
            print("❌ Failed to connect to AWS")
            return
        
        self.results.timestamp = datetime.now().strftime('%B %d, %Y at %I:%M %p')
        
        # Run all checks
        checks = [
            self.check_log_groups,
            self.check_ec2_logging,
            self.check_eks_control_plane_logging,
            self.check_eks_workload_logging,
            self.check_ecs_logging,
            self.check_lambda_logging,
            self.check_rds_logging,
            self.check_aurora_logging,
            self.check_vpc_flow_logs,
            self.check_structured_logging,
            self.check_anomaly_detection,
            self.check_logs_insights,
            self.check_field_indexes,
            self.check_metric_filters,
            self.check_subscription_filters,
            self.check_log_retention,
            self.check_opensearch_integration
        ]
        
        for check_func in checks:
            try:
                check_func()
            except Exception as e:
                print(f"Error in {check_func.__name__}: {e}")
        
        # Calculate overall score
        complete_checks = sum(1 for check in self.results.checks if check.status == 'complete')
        total_checks = len(self.results.checks)
        self.results.overall_score = (complete_checks / total_checks) * 4.0 if total_checks > 0 else 0
        
        if self.results.overall_score >= 3.0:
            self.results.maturity_level = "Advanced"
        elif self.results.overall_score >= 2.0:
            self.results.maturity_level = "Intermediate"
        elif self.results.overall_score >= 1.0:
            self.results.maturity_level = "Basic"
        else:
            self.results.maturity_level = "Initial"
        
        self.generate_html_report()
        
        print(f"\n🏆 Overall Score: {self.results.overall_score:.1f}/4.0")
        print(f"🎯 Maturity Level: {self.results.maturity_level}")
        print(f"✅ Complete Checks: {complete_checks}/{total_checks}")

    def generate_html_report(self):
        """Generate HTML report"""
        complete_checks = sum(1 for check in self.results.checks if check.status == 'complete')
        total_checks = len(self.results.checks)
        completion_percentage = (complete_checks / total_checks) * 100 if total_checks > 0 else 0
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AWS Logging Assessment Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 2rem; border-radius: 10px; margin-bottom: 2rem; text-align: center; }}
        .header h1 {{ font-size: 2.5rem; margin-bottom: 0.5rem; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }}
        .summary-card {{ background: white; padding: 1.5rem; border-radius: 10px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); text-align: center; }}
        .summary-card h3 {{ color: #667eea; margin-bottom: 0.5rem; }}
        .summary-card .number {{ font-size: 2.5rem; font-weight: bold; margin-bottom: 0.5rem; }}
        .complete {{ color: #10b981; }}
        .incomplete {{ color: #ef4444; }}
        .total {{ color: #667eea; }}
        .progress-bar {{ width: 100%; height: 20px; background-color: #e5e7eb; border-radius: 10px; overflow: hidden; margin-top: 0.5rem; }}
        .progress-fill {{ height: 100%; background: linear-gradient(90deg, #10b981, #059669); }}
        .checks-section {{ background: white; border-radius: 10px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); margin-bottom: 2rem; overflow: hidden; }}
        .section-header {{ background: #f8fafc; padding: 1rem 1.5rem; border-bottom: 1px solid #e5e7eb; }}
        .checks-table {{ width: 100%; border-collapse: collapse; }}
        .checks-table th, .checks-table td {{ padding: 1rem; text-align: left; border-bottom: 1px solid #e5e7eb; }}
        .checks-table th {{ background-color: #f8fafc; font-weight: 600; color: #374151; }}
        .checks-table tr:hover {{ background-color: #f9fafb; }}
        .status-badge {{ padding: 0.25rem 0.75rem; border-radius: 20px; font-size: 0.875rem; font-weight: 500; }}
        .status-complete {{ background-color: #d1fae5; color: #065f46; }}
        .status-incomplete {{ background-color: #fee2e2; color: #991b1b; }}
        .priority-high {{ background-color: #fef3c7; color: #92400e; padding: 0.25rem 0.5rem; border-radius: 12px; font-size: 0.75rem; }}
        .priority-medium {{ background-color: #e0e7ff; color: #3730a3; padding: 0.25rem 0.5rem; border-radius: 12px; font-size: 0.75rem; }}
        .priority-low {{ background-color: #d1fae5; color: #065f46; padding: 0.25rem 0.5rem; border-radius: 12px; font-size: 0.75rem; }}
        .footer {{ text-align: center; padding: 2rem; color: #6b7280; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>AWS Logging Assessment Report</h1>
            <p>Generated on {self.results.timestamp}</p>
            <p>Account: {self.results.account_id}</p>
        </div>
        <div class="summary-grid">
            <div class="summary-card">
                <h3>Overall Score</h3>
                <div class="number total">{self.results.overall_score:.1f}/4.0</div>
                <div class="progress-bar"><div class="progress-fill" style="width: {(self.results.overall_score/4.0)*100:.1f}%"></div></div>
            </div>
            <div class="summary-card">
                <h3>Maturity Level</h3>
                <div class="number total">{self.results.maturity_level}</div>
            </div>
            <div class="summary-card">
                <h3>Checks Complete</h3>
                <div class="number complete">{complete_checks}/{total_checks}</div>
                <div class="progress-bar"><div class="progress-fill" style="width: {completion_percentage:.1f}%"></div></div>
            </div>
        </div>
        <div class="checks-section">
            <div class="section-header"><h2>Assessment Details</h2></div>
            <table class="checks-table">
                <thead>
                    <tr><th>Check</th><th>Status</th><th>Priority</th><th>Remediation</th></tr>
                </thead>
                <tbody>"""
        
        for check in self.results.checks:
            evidence_text = "; ".join(check.evidence) if check.evidence else "No evidence found"
            html_content += f"""
                    <tr>
                        <td><strong>{check.name}</strong><br><small style="color: #6b7280;">{evidence_text}</small></td>
                        <td><span class="status-badge status-{check.status}">{check.status}</span></td>
                        <td><span class="priority-{check.priority.lower()}">{check.priority}</span></td>
                        <td>{check.remediation}</td>
                    </tr>"""
        
        html_content += """
                </tbody>
            </table>
        </div>
        <div class="footer">
            <p>AWS Comprehensive Logging Assessment Tool</p>
        </div>
    </div>
</body>
</html>"""
        
        with open(self.html_file, 'w') as f:
            f.write(html_content)
        
        print(f"🌐 HTML report saved to: {self.html_file}")

def main():
    parser = argparse.ArgumentParser(description='AWS Comprehensive Logging Assessment')
    parser.add_argument('--profile', help='AWS profile to use')
    parser.add_argument('--region', default='us-west-2', help='AWS region to use (default: us-west-2)')
    args = parser.parse_args()
    
    assessment = ComprehensiveLoggingAssessment(profile=args.profile, region=args.region)
    assessment.run_assessment()

if __name__ == "__main__":
    main()
