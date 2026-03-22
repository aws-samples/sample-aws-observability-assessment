#!/usr/bin/env python3

import json
import subprocess
import sys
import time
import csv
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
import argparse
import boto3
from botocore.exceptions import ClientError

@dataclass
class DiscoveryCheck:
    """Individual discovery check with unique ID"""
    id: int
    name: str
    category: str
    command: str
    result: Optional[Any] = None
    status: str = "pending"  # pending, success, failed
    evidence: str = ""

@dataclass
class ObservabilityCheck:
    """Assessment question with maturity levels"""
    question_id: int
    category: str
    question: str
    current_level: int = 1
    target_level: int = 4
    evidence_check_ids: List[int] = field(default_factory=list)
    explanation: str = ""
    remediation: str = ""
    maturity_descriptions: Dict[int, str] = field(default_factory=dict)

@dataclass
class AssessmentResults:
    """Complete assessment results"""
    account_id: str = ""
    user_arn: str = ""
    discovery_checks: List[DiscoveryCheck] = field(default_factory=list)
    assessment_checks: List[ObservabilityCheck] = field(default_factory=list)
    category_scores: Dict[str, float] = field(default_factory=dict)
    overall_score: float = 0.0
    maturity_level: str = ""
    timestamp: str = ""

class ComprehensiveObservabilityAssessment:
    def __init__(self, profile=None, region='us-west-2'):
        self.profile = profile
        self.region = region
        self.results = AssessmentResults()
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.html_file = None  # Will be set after getting account_id
        self.discovery_check_counter = 0
        self.largest_log_groups = None  # Will be populated during setup
        self.csv_file = None  # Will be set after getting account_id
        
    def export_check_to_csv(self, check_name, found_count, total_count, details=None):
        """Export check results to CSV file"""
        if not self.csv_file:
            self.csv_file = f"sample-result/discovery_checks_{self.timestamp}.csv"
            # Create CSV with headers
            with open(self.csv_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Check Name', 'Found Count', 'Total Count', 'Percentage', 'Details'])
        
        percentage = (found_count / total_count * 100) if total_count > 0 else 0
        details_str = json.dumps(details) if details else ""
        
        with open(self.csv_file, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([check_name, found_count, total_count, f"{percentage:.1f}%", details_str])
    
    def export_check_result_to_csv(self, check):
        """Extract counts from check result and export to CSV"""
        if check.id == 1:
            # Already handled in execute_log_groups_categorization_check
            return
        elif check.id == 2:
            # Already handled in execute_top_log_groups_retention_check
            return
        elif check.id == 3:
            # Query definitions
            defs = check.result.get('queryDefinitions', []) if isinstance(check.result, dict) else []
            count = len(defs)
            self.export_check_to_csv("Log Insights Query Definitions", 1 if count > 0 else 0, 1, {'count': count})
        elif check.id == 4:
            # Query history
            queries = check.result.get('queries', []) if isinstance(check.result, dict) else []
            count = len(queries)
            self.export_check_to_csv("Log Insights Query History", 1 if count > 0 else 0, 1, {'count': count})
        elif check.id == 5:
            # Metric filters
            filters = check.result.get('metricFilters', []) if isinstance(check.result, dict) else []
            count = len(filters)
            self.export_check_to_csv("Metric Filters", 1 if count > 0 else 0, 1, {'count': count})
        elif check.id == 6:
            # Subscription filters
            if isinstance(check.result, dict):
                found = check.result.get('log_groups_with_subscriptions', 0)
                total = check.result.get('total_log_groups', 0)
                self.export_check_to_csv("Subscription Filters", 1 if found > 0 else 0, 1, {'log_groups_with_subscriptions': found, 'total_log_groups': total})
        elif check.id == 7:
            # EC2 CloudWatch Agent - handled in custom function
            if isinstance(check.result, dict):
                found = check.result.get('logging_configured_count', 0)
                total = check.result.get('total_instances', 0)
                self.export_check_to_csv("EC2 CloudWatch Agent", found, total)
        elif check.id == 8:
            # Lambda JSON logging
            if isinstance(check.result, dict):
                found = check.result.get('json_logging_count', 0)
                total = check.result.get('total_functions', 0)
                self.export_check_to_csv("Lambda JSON Structured Logging", found, total)
        elif check.id == 9:
            # ECS structured logging - handled in custom function
            if isinstance(check.result, dict):
                found = check.result.get('json_logging_count', 0)
                total = check.result.get('total_tasks', 0)
                self.export_check_to_csv("ECS Structured Logging", found, total)
        elif check.id == 10:
            # EKS control plane logs
            if isinstance(check.result, dict):
                enabled = check.result.get('enabled_types', 0)
                total = check.result.get('total_types', 5)
                self.export_check_to_csv("EKS Control Plane Logs", enabled, total)
        elif check.id == 11:
            # EKS CloudWatch Observability add-on
            if isinstance(check.result, dict):
                obs = check.result.get('observability_clusters', 0)
                total = check.result.get('total_clusters', 0)
                self.export_check_to_csv("EKS CloudWatch Observability Add-on", obs, total if total > 0 else 1)
            else:
                self.export_check_to_csv("EKS CloudWatch Observability Add-on", 0, 1)
        elif check.id == 15:
            # CloudWatch cross-account observability (OAM)
            if isinstance(check.result, dict):
                links = check.result.get('links_count', 0)
                sinks = check.result.get('sinks_count', 0)
                has_oam = links > 0 or sinks > 0
                self.export_check_to_csv("CloudWatch Cross-Account Observability", 1 if has_oam else 0, 1, {'links': links, 'sinks': sinks})
            else:
                self.export_check_to_csv("CloudWatch Cross-Account Observability", 0, 1)
        else:
            # Default handler for checks 12-50: binary yes/no based on result existence
            if check.id >= 12 and check.id <= 50:
                # Extract check name from the check object
                check_name = check.name[:50] if len(check.name) > 50 else check.name
                # Binary: 1 if result exists and has data, 0 otherwise
                has_result = check.result is not None and (
                    (isinstance(check.result, dict) and len(check.result) > 0) or
                    (isinstance(check.result, list) and len(check.result) > 0) or
                    (isinstance(check.result, (str, int, float, bool)))
                )
                self.export_check_to_csv(check_name, 1 if has_result else 0, 1)
        
    def run_aws_command(self, command):
        """Execute AWS CLI command and return result"""
        if self.profile:
            command = command.replace("aws ", f"aws --profile {self.profile} ")
        
        if "--region" not in command:
            command = command.replace(" --output", f" --region {self.region} --output")
        
        try:
            # Use shell=True to handle complex commands with quotes
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                return json.loads(result.stdout) if result.stdout.strip() else {}
            return None
        except:
            return None

    def add_discovery_check(self, name: str, category: str, command: str) -> int:
        """Add a discovery check, combining duplicates with comma-separated categories"""
        # Check if this check already exists (same name and command)
        existing_check = next((c for c in self.results.discovery_checks if c.name == name and c.command == command), None)
        
        if existing_check:
            # Add category to existing check if not already present
            categories = existing_check.category.split(', ')
            if category not in categories:
                categories.append(category)
                existing_check.category = ', '.join(sorted(categories))
            return existing_check.id
        else:
            # Create new check
            self.discovery_check_counter += 1
            check = DiscoveryCheck(
                id=self.discovery_check_counter,
                name=name,
                category=category,
                command=command
            )
            self.results.discovery_checks.append(check)
            return self.discovery_check_counter

    def execute_discovery_check(self, check_id: int):
        """Execute a specific discovery check"""
        check = next((c for c in self.results.discovery_checks if c.id == check_id), None)
        if not check:
            return
        
        from datetime import datetime
        start_time = datetime.now().strftime('%H:%M:%S')
        print(f"  [{start_time}] Running check #{check.id}: {check.name}...", flush=True)
        
        try:
            if check.command == "custom_ec2_cloudwatch_agent_check":
                check.result = self.execute_ec2_cloudwatch_agent_check()
            elif check.command == "custom_lambda_json_logging_check":
                check.result = self.execute_lambda_json_logging_check()
            elif check.command == "custom_ecs_task_log_check":
                check.result = self.execute_ecs_task_log_check()
            elif check.command == "custom_eks_control_plane_logs_check":
                check.result = self.execute_eks_control_plane_logs_check()
            elif check.command == "custom_field_indexes_per_log_group_check":
                check.result = self.execute_field_indexes_per_log_group_check()
            elif check.command == "custom_eks_addons_check":
                check.result = self.execute_eks_addons_check()
            elif check.command == "custom_lambda_insights_check":
                check.result = self.execute_lambda_insights_check()
            elif check.command == "custom_metrics_namespaces_check":
                check.result = self.execute_custom_metrics_namespaces_check()
            elif check.command == "custom_cloudwatch_alarms_check":
                check.result = self.execute_cloudwatch_alarms_check()
            elif check.command == "custom_log_export_tasks_per_log_group_check":
                check.result = self.execute_log_export_tasks_per_log_group_check()
            elif check.command == "custom_top_log_groups_retention_check":
                check.result = self.execute_top_log_groups_retention_check()
            elif check.command == "custom_subscription_filters_coverage_check":
                check.result = self.execute_subscription_filters_coverage_check()
            elif check.command == "custom_log_centralization_analysis_check":
                check.result = self.execute_log_centralization_analysis_check()
            elif check.command == "custom_oam_links_and_sinks_check":
                check.result = self.execute_oam_links_and_sinks_check()
            elif check.command == "custom_json_structured_logs_check":
                check.result = self.execute_json_structured_logs_check()
            elif check.command == "custom_alarm_sns_configuration_check":
                check.result = self.execute_alarm_sns_configuration_check()
            elif check.command == "custom_anomaly_detection_bands_check":
                check.result = self.execute_anomaly_detection_bands_check()
            elif check.command == "custom_alarm_opsitem_actions_check":
                check.result = self.execute_alarm_opsitem_actions_check()
            elif check.command == "custom_devops_agent_spaces_check":
                check.result = self.execute_devops_agent_spaces_check()
            elif check.command == "custom_alarm_lambda_actions_check":
                check.result = self.execute_alarm_lambda_actions_check()
            elif check.command == "custom_alarm_investigations_actions_check":
                check.result = self.execute_alarm_investigations_actions_check()
            elif check.command == "custom_alarm_ec2_actions_check":
                check.result = self.execute_alarm_ec2_actions_check()
            elif check.command == "custom_dashboard_variables_check":
                check.result = self.execute_dashboard_variables_check()
            elif check.command == "custom_xray_service_graph_check":
                check.result = self.execute_xray_service_graph_check()
            elif check.command == "custom_xray_sampling_rules_check":
                check.result = self.execute_xray_sampling_rules_check()
            elif check.command == "custom_log_groups_categorization_check":
                check.result = self.execute_log_groups_categorization_check()
            elif check.command == "custom_log_group_tags_check":
                check.result = self.execute_log_group_tags_check()
            elif check.command == "custom_app_signals_list_services_check":
                check.result = self.execute_app_signals_list_services_check()
            else:
                check.result = self.run_aws_command(check.command)
            
            if check.result is not None:
                check.status = "success"
                # Export to CSV for checks 1-50
                if 1 <= check.id <= 50:
                    self.export_check_result_to_csv(check)
                # Generate detailed evidence based on check type
                try:
                    check.evidence = self.generate_detailed_evidence(check)
                except Exception as e:
                    print(f"DEBUG: Exception in evidence generation for {check.name}: {e}")
                    check.evidence = f"Account: {self.results.account_id}, Region: {self.region} - Evidence generation failed: {str(e)}"
            else:
                check.status = "failed"
                check.evidence = f"No resources found"
                # Export failed checks to CSV as well
                if 1 <= check.id <= 50:
                    check_name = check.name[:50] if len(check.name) > 50 else check.name
                    self.export_check_to_csv(check_name, 0, 1)
        except Exception as e:
            check.status = "failed"
            check.evidence = f"No resources found"

    def generate_detailed_evidence(self, check: DiscoveryCheck) -> str:
        """Generate detailed evidence with summary and expandable details"""
        base_info = f"Account: {self.results.account_id}, Region: {self.region}"
        
        if not check.result:
            return f"No resources found"
        
        # Handle specific checks first to avoid generic handler conflicts
        if check.name == "Have you configured metric streams for real-time export to third-party tools or data lakes?":
            entries = check.result.get('Entries', [])
            if entries:
                summary = f"Found {len(entries)} metric streams"
                
                # Create detailed breakdown
                details = ""
                for i, stream in enumerate(entries, 1):
                    name = stream.get('Name', 'Unknown')
                    state = stream.get('State', 'Unknown')
                    output_format = stream.get('OutputFormat', 'Unknown')
                    firehose_arn = stream.get('FirehoseArn', 'Unknown')
                    creation_date = stream.get('CreationDate', 'Unknown')
                    
                    details += f"{i}. <strong>{name}</strong><br>"
                    details += f"   State: {state}<br>"
                    details += f"   Output Format: {output_format}<br>"
                    details += f"   Firehose: {firehose_arn.split('/')[-1] if '/' in str(firehose_arn) else firehose_arn}<br>"
                    details += f"   Created: {creation_date}<br><br>"
                
                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return f"No metric streams found"
        
        elif check.name == "Do you use composite alarms to reduce alarm noise?":
            composite_alarms = check.result.get('CompositeAlarms', [])
            if composite_alarms:
                summary = f"Found {len(composite_alarms)} composite alarms"
                
                # Create detailed breakdown
                details = ""
                for i, alarm in enumerate(composite_alarms, 1):
                    alarm_name = alarm.get('AlarmName', 'Unknown')
                    state_value = alarm.get('StateValue', 'Unknown')
                    alarm_rule = alarm.get('AlarmRule', 'No rule')
                    actions_enabled = alarm.get('ActionsEnabled', False)
                    alarm_actions = alarm.get('AlarmActions', [])
                    
                    details += f"{i}. <strong>{alarm_name}</strong><br>"
                    details += f"   State: {state_value}<br>"
                    details += f"   Rule: {alarm_rule}<br>"
                    details += f"   Actions Enabled: {actions_enabled}<br>"
                    if alarm_actions:
                        details += f"   Actions: {len(alarm_actions)} configured<br>"
                        for j, action in enumerate(alarm_actions[:3], 1):
                            action_type = "SNS" if "sns:" in action else "SSM" if "ssm:" in action else "Other"
                            details += f"     {j}. {action_type}: {action.split(':')[-1]}<br>"
                    details += "<br>"
                
                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return f"No composite alarms found"
        
        elif check.name == "What percentage of Lambda functions have Lambda Insights enabled for enhanced metrics?":
            if check.result:
                total_functions = check.result.get('total_functions', 0)
                insights_functions = check.result.get('insights_functions', 0)
                functions_with_insights = check.result.get('functions_with_insights', [])
                
                summary = f"{insights_functions}/{total_functions} Lambda functions have Lambda Insights enabled"
                
                if insights_functions > 0:
                    # Create detailed breakdown
                    details = f"<strong>Lambda Functions with Insights Enabled ({insights_functions}):</strong><br>"
                    for i, func_name in enumerate(functions_with_insights, 1):
                        details += f"{i}. {func_name}<br>"
                    
                    details += f"<br><strong>Functions without Insights ({total_functions - insights_functions}):</strong><br>"
                    details += f"Total functions without Lambda Insights: {total_functions - insights_functions}<br>"
                    
                    return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
                
                return summary
            return f"No Lambda functions found"
        
        elif check.name == "Are you publishing custom business and application metrics to CloudWatch?":
            if check.result:
                custom_namespaces = check.result.get('custom_namespaces', [])
                total_custom_metrics = check.result.get('total_custom_metrics', 0)
                sample_metrics = check.result.get('sample_metrics', [])
                
                if custom_namespaces:
                    summary = f"Found {len(custom_namespaces)} custom namespaces with {total_custom_metrics} total metrics"
                    
                    # Create detailed breakdown
                    details = f"<strong>Custom Metrics Namespaces ({len(custom_namespaces)}):</strong><br>"
                    for i, namespace in enumerate(custom_namespaces, 1):
                        details += f"{i}. {namespace}<br>"
                    
                    if sample_metrics:
                        details += f"<br><strong>Sample Custom Metrics ({len(sample_metrics)}):</strong><br>"
                        for i, metric in enumerate(sample_metrics, 1):
                            namespace = metric.get('Namespace', 'Unknown')
                            metric_name = metric.get('MetricName', 'Unknown')
                            dimensions = metric.get('Dimensions', [])
                            dim_info = f" | Dimensions: {len(dimensions)}" if dimensions else ""
                            details += f"{i}. {namespace}/{metric_name}{dim_info}<br>"
                    
                    return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
                
                return f"Found {len(custom_namespaces)} custom namespaces with {total_custom_metrics} metrics"
            return f"No custom metrics found"
        
        elif check.name == "Have you created metric filters to extract KPIs from logs?":
            command_info = f"Command: {check.command}"
            metric_filters = check.result.get('metricFilters', [])
            if metric_filters:
                summary = f"Found {len(metric_filters)} metric filters"
                
                # Create detailed breakdown
                details = ""
                for i, mf in enumerate(metric_filters, 1):
                    filter_name = mf.get('filterName', 'Unnamed')
                    log_group = mf.get('logGroupName', 'Unknown')
                    pattern = mf.get('filterPattern', 'No pattern')
                    metric_transformations = mf.get('metricTransformations', [])
                    
                    details += f"{i}. <strong>{filter_name}</strong><br>"
                    details += f"   Log Group: {log_group}<br>"
                    details += f"   Pattern: {pattern}<br>"
                    
                    if metric_transformations:
                        for j, mt in enumerate(metric_transformations):
                            metric_name = mt.get('metricName', 'Unknown')
                            metric_namespace = mt.get('metricNamespace', 'Unknown')
                            metric_value = mt.get('metricValue', 'Unknown')
                            details += f"   Metric {j+1}: {metric_namespace}/{metric_name} = {metric_value}<br>"
                    else:
                        details += f"   No metric transformations<br>"
                    details += "<br>"
                
                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return f"{command_info} | No metric filters found - no log groups are configured to extract metrics from log events"
        
        elif check.name == "What percentage of log groups have subscription filters for real-time processing?":
            if check.result:
                total_groups = check.result.get('total_log_groups', 0)
                groups_with_filters = check.result.get('groups_with_subscription_filters', 0)
                sample_groups = check.result.get('sample_filtered_groups', [])
                filter_details = check.result.get('subscription_filter_details', [])
                
                if groups_with_filters > 0:
                    summary = f"Found {groups_with_filters}/{total_groups} log groups with subscription filters"
                    
                    # Create detailed breakdown
                    details = ""
                    if filter_details:
                        for i, detail in enumerate(filter_details, 1):
                            log_group = detail.get('log_group', 'Unknown')
                            filter_name = detail.get('filter_name', 'Unknown')
                            destination_arn = detail.get('destination_arn', 'Unknown')
                            filter_pattern = detail.get('filter_pattern', 'No pattern')
                            
                            details += f"{i}. <strong>{log_group}</strong><br>"
                            details += f"   Filter Name: {filter_name}<br>"
                            details += f"   Destination: {destination_arn}<br>"
                            details += f"   Pattern: {filter_pattern}<br><br>"
                    else:
                        # Fallback to sample groups if no detailed info
                        for i, group in enumerate(sample_groups, 1):
                            details += f"{i}. {group}<br>"
                    
                    return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
                return f"Checked {total_groups} log groups - {groups_with_filters}/{total_groups} have subscription filters"
            return f"No log groups checked for subscription filters"
        
        elif check.name == "What percentage of EC2 instances have CloudWatch Agent installed with both system metrics AND application logs configured?":
            instances = check.result.get('instances', [])
            ssm_instances = check.result.get('ssm_instances', [])
            cw_agent_instances = check.result.get('cw_agent_instances', [])
            logging_configured_instances = check.result.get('logging_configured_instances', [])
            
            total_instances = len(instances)
            ssm_count = len(ssm_instances)
            cw_agent_count = len(cw_agent_instances)
            logging_count = len(logging_configured_instances)
            
            if total_instances > 0:
                summary = f"Total: {total_instances} instances | SSM: {ssm_count}/{total_instances} | CW Agent: {cw_agent_count}/{ssm_count if ssm_count > 0 else 0} | Logging: {logging_count}/{total_instances}"
                
                # Create detailed breakdown
                details = ""
                details += f"<strong>All EC2 Instances ({total_instances}):</strong><br>"
                for i, instance in enumerate(instances[:10], 1):
                    details += f"{i}. {instance}<br>"
                if len(instances) > 10:
                    details += f"... and {len(instances) - 10} more instances<br>"
                
                details += f"<br><strong>SSM Managed Instances ({ssm_count}):</strong><br>"
                for i, instance in enumerate(ssm_instances[:10], 1):
                    details += f"{i}. {instance}<br>"
                if len(ssm_instances) > 10:
                    details += f"... and {len(ssm_instances) - 10} more instances<br>"
                
                details += f"<br><strong>CloudWatch Agent Running ({cw_agent_count}):</strong><br>"
                for i, instance in enumerate(cw_agent_instances[:10], 1):
                    details += f"{i}. {instance}<br>"
                if len(cw_agent_instances) > 10:
                    details += f"... and {len(cw_agent_instances) - 10} more instances<br>"
                
                details += f"<br><strong>Logging Configured ({logging_count}):</strong><br>"
                for i, instance in enumerate(logging_configured_instances[:10], 1):
                    details += f"{i}. {instance}<br>"
                if len(logging_configured_instances) > 10:
                    details += f"... and {len(logging_configured_instances) - 10} more instances<br>"
                
                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return f"No EC2 instances found"
        
        elif check.name == "What percentage of Lambda functions use JSON structured logging?":
            if isinstance(check.result, dict):
                total = check.result.get('total_functions', 0)
                json_count = check.result.get('json_logging_count', 0)
                functions = check.result.get('functions_with_json', [])
                
                if total > 0:
                    percentage = (json_count / total) * 100
                    summary = f"Lambda functions: {total} | JSON logging: {json_count}/{total} ({percentage:.1f}%)"
                    if functions:
                        details = "<br>".join(functions[:10])
                        if len(functions) > 10:
                            details += f"<br>... and {len(functions) - 10} more"
                        return f"{summary}<details><summary>Show Functions</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
                    return summary
            return "No Lambda functions found"
        
        elif check.name == "What percentage of ECS tasks use structured logging (JSON)?":
            if check.result:
                clusters = check.result.get('clusters', [])
                running_tasks = check.result.get('running_tasks', [])
                tasks_with_logging = check.result.get('tasks_with_logging', [])
                logging_configs = check.result.get('logging_configs', [])
                
                if running_tasks:
                    summary = f"ECS clusters: {len(clusters)} | Running tasks: {len(running_tasks)} | Tasks with logging: {len(tasks_with_logging)}/{len(running_tasks)}"
                    
                    # Create detailed breakdown
                    details = ""
                    details += f"<strong>ECS Clusters ({len(clusters)}):</strong><br>"
                    for i, cluster in enumerate(clusters, 1):
                        details += f"{i}. {cluster}<br>"
                    
                    details += f"<br><strong>Running Tasks ({len(running_tasks)}):</strong><br>"
                    for i, task in enumerate(running_tasks[:10], 1):
                        details += f"{i}. {task}<br>"
                    if len(running_tasks) > 10:
                        details += f"... and {len(running_tasks) - 10} more tasks<br>"
                    
                    details += f"<br><strong>Tasks with Logging ({len(tasks_with_logging)}):</strong><br>"
                    for i, task in enumerate(tasks_with_logging[:10], 1):
                        details += f"{i}. {task}<br>"
                    if len(tasks_with_logging) > 10:
                        details += f"... and {len(tasks_with_logging) - 10} more tasks<br>"
                    
                    if logging_configs:
                        details += f"<br><strong>Logging Configurations ({len(logging_configs)}):</strong><br>"
                        for i, config in enumerate(logging_configs, 1):
                            task_def = config.get('taskDefinition', 'Unknown')
                            containers = config.get('containers', [])
                            details += f"{i}. <strong>Task Definition:</strong> {task_def}<br>"
                            for j, container in enumerate(containers, 1):
                                container_name = container.get('name', 'Unknown')
                                log_driver = container.get('logDriver', 'none')
                                log_group = container.get('logGroup', 'N/A')
                                details += f"   Container {j}: {container_name} | Driver: {log_driver} | Group: {log_group}<br>"
                            details += "<br>"
                    
                    return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
                return f"No running ECS tasks found"
            return f"No ECS task log configuration data available"
        
        elif check.name == "Is the EKS CloudWatch Observability add-on deployed with Container Insights and Application Signals enabled?":
            if check.result and isinstance(check.result, dict):
                total = check.result.get('total_clusters', 0)
                obs_count = check.result.get('observability_clusters', 0)
                clusters = check.result.get('clusters_with_observability', [])
                if total == 0:
                    return "No EKS clusters found in this account"
                summary = f"{obs_count}/{total} EKS clusters have CloudWatch Observability add-on installed"
                if clusters:
                    details = "<strong>Clusters with add-on:</strong><br>" + "<br>".join(clusters)
                    return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
                return summary
            return "No EKS clusters found in this account"
        
        elif check.name == "Have you enabled anomaly detection?":
            anomaly_detectors = check.result.get('anomalyDetectors', [])
            if anomaly_detectors:
                summary = f"Found {len(anomaly_detectors)} log anomaly detectors"
                details = []
                for detector in anomaly_detectors[:5]:  # Show first 5 detectors
                    detector_name = detector.get('detectorName', 'Unknown')
                    status = detector.get('anomalyDetectorStatus', 'Unknown')
                    log_groups = detector.get('logGroupArnList', [])
                    log_group_names = [lg.split(':')[-1] for lg in log_groups]
                    details.append(f"Name: {detector_name}<br>Status: {status}<br>Log Groups: {', '.join(log_group_names[:2])}<br>")
                
                details_html = "<br>".join(details)
                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details_html}</div></details>"
            return f"No log anomaly detectors found"
        
        elif check.name == "Do you have log export tasks configured for archival?":
            if check.result:
                total_groups = check.result.get('total_log_groups', 0)
                exported_groups = check.result.get('exported_log_groups', 0)
                sample_groups = check.result.get('sample_exported_groups', [])
                export_details = check.result.get('export_task_details', [])
                
                if exported_groups > 0:
                    summary = f"Found {exported_groups}/{total_groups} log groups with export history"
                    
                    # Create detailed breakdown
                    details = f"<strong>Log Groups with Export History ({exported_groups}):</strong><br>"
                    
                    if export_details:
                        for i, detail in enumerate(export_details, 1):
                            log_group = detail.get('log_group', 'Unknown')
                            task_count = detail.get('task_count', 0)
                            latest_task = detail.get('latest_task', {})
                            
                            details += f"{i}. <strong>{log_group}</strong><br>"
                            details += f"   Export Tasks: {task_count}<br>"
                            
                            if latest_task:
                                task_id = latest_task.get('taskId', 'Unknown')
                                status = latest_task.get('status', 'Unknown')
                                destination = latest_task.get('destination', 'Unknown')
                                from_time = latest_task.get('from', 'Unknown')
                                to_time = latest_task.get('to', 'Unknown')
                                
                                details += f"   Latest Task: {task_id}<br>"
                                details += f"   Status: {status}<br>"
                                details += f"   Destination: {destination}<br>"
                                details += f"   Time Range: {from_time} to {to_time}<br>"
                            details += "<br>"
                    else:
                        # Fallback to sample groups
                        for i, group in enumerate(sample_groups, 1):
                            details += f"{i}. {group}<br>"
                    
                    return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
                return f"Checked {total_groups} log groups - {exported_groups}/{total_groups} have export history"
            return f"No log groups checked for export tasks"
        
        elif check.name == "Have you implemented Cross-Account and Cross-Region Log Centralization?":
            if check.result:
                patterns = check.result.get('centralization_patterns', [])
                account_type = check.result.get('account_type', 'Unknown')
                org_status = check.result.get('organization_status', 'Unknown')
                
                summary = f"Account type: {account_type} | Org status: {org_status}"
                
                if patterns:
                    summary += f" | Found {len(patterns)} centralization patterns"
                    
                    # Create detailed breakdown
                    details = f"<strong>Account Information:</strong><br>"
                    details += f"Account Type: {account_type}<br>"
                    details += f"Organization Status: {org_status}<br><br>"
                    
                    details += f"<strong>Centralization Patterns ({len(patterns)}):</strong><br>"
                    for i, pattern in enumerate(patterns, 1):
                        details += f"{i}. {pattern}<br>"
                    
                    return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
                else:
                    summary += " | No centralization patterns detected"
                
                return summary
            return f"No centralization analysis data available"
        
        elif check.name == "Are you using CloudWatch cross-account observability?":
            if check.result:
                account_type = check.result.get('account_type', 'Unknown')
                links_count = check.result.get('links_count', 0)
                sinks_count = check.result.get('sinks_count', 0)
                config_details = check.result.get('configuration_details', [])
                
                summary = f"Account Type: {account_type}"
                if links_count > 0 or sinks_count > 0:
                    summary += f" | Links: {links_count}, Sinks: {sinks_count}"
                    if config_details:
                        details_text = "<br>".join(config_details)
                        return f"{summary}<details><summary>Show Configuration Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details_text}</div></details>"
                return summary
            return f"OAM configuration check failed"
        
        elif check.name == "Do you have field index policies configured for faster log queries?":
            if check.result:
                total_groups = check.result.get('total_log_groups', 0)
                indexed_groups = check.result.get('indexed_log_groups', 0)
                sample_groups = check.result.get('sample_indexed_groups', [])
                field_details = check.result.get('field_index_details', [])
                
                if indexed_groups > 0:
                    sample_info = f"Examples: {', '.join(sample_groups[:3])}" if sample_groups else ""
                    
                    # Add field index details
                    if field_details:
                        details_html = ""
                        for detail in field_details[:3]:  # Show first 3 with field names
                            log_group = detail.get('log_group', 'Unknown')
                            field_names = detail.get('field_names', [])
                            details_html += f"<strong>{log_group}</strong><br>Fields: {', '.join(field_names[:5])}<br><br>"
                        
                        return f"Found {indexed_groups}/{total_groups} log groups with field indexes (top 20 largest by size) | {sample_info}<details><summary>Show Field Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details_html}</div></details>"
                    
                    return f"Found {indexed_groups}/{total_groups} log groups with field indexes (top 20 largest by size) | {sample_info}"
                return f"Checked {total_groups} log groups (top 20 largest by size) - {indexed_groups}/{total_groups} have field indexes"
            return f"No log groups checked for field indexes"
        
        elif check.name == "What percentage of production EC2 instances have detailed monitoring (1-minute metrics) enabled?":
            if isinstance(check.result, list):
                # Count instances with detailed monitoring enabled
                enabled_instances = []
                for reservation in check.result:
                    if isinstance(reservation, list):
                        enabled_instances.extend(reservation)
                
                if enabled_instances:
                    summary = f"Found {len(enabled_instances)} EC2 instances with detailed monitoring enabled"
                    
                    # Create detailed breakdown
                    details = f"<strong>Instances with Detailed Monitoring ({len(enabled_instances)}):</strong><br>"
                    for i, instance in enumerate(enabled_instances, 1):
                        instance_id = instance.get('InstanceId', 'Unknown')
                        instance_type = instance.get('InstanceType', 'Unknown')
                        state = instance.get('State', {}).get('Name', 'Unknown')
                        monitoring = instance.get('Monitoring', {}).get('State', 'Unknown')
                        
                        details += f"{i}. <strong>{instance_id}</strong><br>"
                        details += f"   Type: {instance_type}<br>"
                        details += f"   State: {state}<br>"
                        details += f"   Monitoring: {monitoring}<br><br>"
                    
                    return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
                else:
                    return f"No EC2 instances have detailed monitoring enabled - all instances using basic (5-minute) monitoring"
            return f"EC2 detailed monitoring check completed"
        
        elif check.name == "What percentage of ECS Clusters have monitoring enabled?":
            cluster_arns = check.result.get('clusterArns', [])
            if cluster_arns:
                cluster_names = [arn.split('/')[-1] for arn in cluster_arns]
                summary = f"Found {len(cluster_arns)} ECS clusters"
                details = "<br>".join(cluster_names[:10])
                if len(cluster_names) > 10:
                    details += f"<br>... and {len(cluster_names) - 10} more clusters"
                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return f"No ECS clusters found"
        
        elif check.name == "Do you have ECS clusters with Container Insights enabled?":
            clusters = check.result.get('clusters', [])
            if clusters:
                insights_enabled = []
                insights_disabled = []
                
                for cluster in clusters:
                    cluster_name = cluster.get('clusterName', 'Unknown')
                    cluster_arn = cluster.get('clusterArn', 'Unknown')
                    status = cluster.get('status', 'Unknown')
                    settings = cluster.get('settings', [])
                    
                    insights_value = 'disabled'  # default
                    for setting in settings:
                        if setting.get('name') == 'containerInsights':
                            insights_value = setting.get('value', 'disabled')
                            break
                    
                    cluster_info = {
                        'name': cluster_name,
                        'arn': cluster_arn,
                        'status': status,
                        'insights': insights_value
                    }
                    
                    if insights_value in ['enabled', 'enhanced']:
                        insights_enabled.append(cluster_info)
                    else:
                        insights_disabled.append(cluster_info)
                
                summary = f"Found {len(clusters)} ECS clusters | Container Insights: {len(insights_enabled)} enabled, {len(insights_disabled)} disabled"
                
                # Create detailed breakdown
                details = ""
                if insights_enabled:
                    details += f"<strong>Clusters with Container Insights Enabled ({len(insights_enabled)}):</strong><br>"
                    for i, cluster in enumerate(insights_enabled, 1):
                        details += f"{i}. <strong>{cluster['name']}</strong><br>"
                        details += f"   Status: {cluster['status']}<br>"
                        details += f"   Container Insights: {cluster['insights']}<br>"
                        details += f"   ARN: {cluster['arn']}<br><br>"
                
                if insights_disabled:
                    details += f"<strong>Clusters with Container Insights Disabled ({len(insights_disabled)}):</strong><br>"
                    for i, cluster in enumerate(insights_disabled, 1):
                        details += f"{i}. <strong>{cluster['name']}</strong><br>"
                        details += f"   Status: {cluster['status']}<br>"
                        details += f"   Container Insights: {cluster['insights']}<br>"
                        details += f"   ARN: {cluster['arn']}<br><br>"
                
                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return f"No ECS clusters found"
        
        elif check.name == "Do you have EKS clusters with CloudWatch Observability add-on enabled?":
            if check.result:
                total_clusters = check.result.get('total_clusters', 0)
                observability_clusters = check.result.get('observability_clusters', 0)
                clusters_with_obs = check.result.get('clusters_with_observability', [])
                cluster_details = check.result.get('cluster_addon_details', [])
                
                summary = f"Found {observability_clusters}/{total_clusters} EKS clusters with CloudWatch Observability add-on"
                
                if observability_clusters > 0:
                    # Create detailed breakdown
                    details = f"<strong>EKS Clusters with CloudWatch Observability Add-on ({observability_clusters}):</strong><br>"
                    
                    if cluster_details:
                        for i, detail in enumerate(cluster_details, 1):
                            cluster_name = detail.get('cluster_name', 'Unknown')
                            addon_version = detail.get('addon_version', 'Unknown')
                            addon_status = detail.get('addon_status', 'Unknown')
                            
                            details += f"{i}. <strong>{cluster_name}</strong><br>"
                            details += f"   Add-on Version: {addon_version}<br>"
                            details += f"   Status: {addon_status}<br><br>"
                    else:
                        # Fallback to cluster names
                        for i, cluster in enumerate(clusters_with_obs, 1):
                            details += f"{i}. {cluster}<br>"
                    
                    return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
                
                return f"Checked {total_clusters} EKS clusters - {observability_clusters}/{total_clusters} have CloudWatch Observability add-on"
            return f"No EKS clusters checked for add-ons"
        
        # Handle different AWS service responses with expandable details
        if check.name == "Do you have standardized Log Insights queries for common troubleshooting scenarios (errors, latency, security events)?":
            query_definitions = check.result.get('queryDefinitions', [])
            if query_definitions:
                summary = f"Found {len(query_definitions)} saved query definitions"
                details = ""
                for i, query_def in enumerate(query_definitions[:10], 1):
                    name = query_def.get('name', 'Unnamed')
                    query_string = query_def.get('queryString', 'No query string')[:150]
                    log_groups = query_def.get('logGroupNames', [])
                    log_group_info = f"Groups: {', '.join(log_groups[:3])}" if log_groups else "No log groups"
                    details += f"<strong>{i}. {name}</strong><br>Query: {query_string}<br>{log_group_info}<br><br>"
                if len(query_definitions) > 10:
                    details += f"... and {len(query_definitions) - 10} more queries"
                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return f"No saved query definitions found - users haven't saved any custom CloudWatch Logs Insights queries for reuse"
        
        elif check.name == "Do you have CloudWatch alarms configured for your resources?":
            metric_alarms = check.result.get('MetricAlarms', [])
            composite_alarms = check.result.get('CompositeAlarms', [])
            total_alarms = len(metric_alarms) + len(composite_alarms)
            if total_alarms > 0:
                summary = f"Found {total_alarms} alarms ({len(metric_alarms)} metric, {len(composite_alarms)} composite)"
                details = "<strong>Metric Alarms:</strong><br>" + "<br>".join([alarm.get('AlarmName', 'Unknown') for alarm in metric_alarms[:10]])
                if len(metric_alarms) > 10:
                    details += f"<br>... and {len(metric_alarms) - 10} more metric alarms"
                if composite_alarms:
                    details += "<br><br><strong>Composite Alarms:</strong><br>" + "<br>".join([alarm.get('AlarmName', 'Unknown') for alarm in composite_alarms[:10]])
                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return f"No alarms found"
        
        elif check.name == "Do you have CloudWatch dashboards for visualizing metrics and logs?":
            dashboards = check.result.get('DashboardEntries', [])
            if dashboards:
                summary = f"Found {len(dashboards)} dashboards"
                details = "<br>".join([dash.get('DashboardName', 'Unknown') for dash in dashboards[:15]])
                if len(dashboards) > 15:
                    details += f"<br>... and {len(dashboards) - 15} more dashboards"
                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return f"No dashboards found"
        
        elif check.name == "Do your alarms send notifications to SNS topics?":
            if check.result:
                total_checked = check.result.get('total_alarms_checked', 0)
                alarms_with_sns = check.result.get('alarms_with_sns', 0)
                alarms_without_sns = check.result.get('alarms_without_sns', 0)
                alarms_with_sns_details = check.result.get('alarms_with_sns_details', [])
                alarms_without_sns_details = check.result.get('alarms_without_sns_details', [])
                
                summary = f"SNS configured for {alarms_with_sns} of {total_checked} alarms checked"
                
                # Create detailed breakdown
                details = f"<strong>Alarms with SNS Configuration ({alarms_with_sns}):</strong><br>"
                for i, alarm in enumerate(alarms_with_sns_details, 1):
                    alarm_name = alarm.get('AlarmName', 'Unknown')
                    sns_topics = alarm.get('SNSTopics', [])
                    details += f"{i}. <strong>{alarm_name}</strong><br>"
                    details += f"   SNS Topics: {len(sns_topics)}<br>"
                    for j, topic in enumerate(sns_topics[:2], 1):
                        topic_name = topic.split(':')[-1] if ':' in topic else topic
                        details += f"     {j}. {topic_name}<br>"
                    if len(sns_topics) > 2:
                        details += f"     ... and {len(sns_topics) - 2} more topics<br>"
                    details += "<br>"
                
                if alarms_without_sns > 0:
                    details += f"<br><strong>Alarms without SNS Configuration ({alarms_without_sns}):</strong><br>"
                    for i, alarm in enumerate(alarms_without_sns_details[:10], 1):
                        alarm_name = alarm.get('AlarmName', 'Unknown')
                        details += f"{i}. {alarm_name}<br>"
                    if len(alarms_without_sns_details) > 10:
                        details += f"... and {len(alarms_without_sns_details) - 10} more alarms without SNS<br>"
                
                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return f"No alarms found to check"
        
        elif check.name == "Do you use anomaly detection models for adaptive alarming?":
            if check.result:
                total_bands = check.result.get('total_bands', 0)
                bands_details = check.result.get('bands_details', [])
                
                if total_bands > 0:
                    summary = f"Found {total_bands} anomaly detection bands configured"
                    
                    # Create detailed breakdown
                    details = f"<strong>Anomaly Detection Bands ({total_bands}):</strong><br>"
                    for i, band in enumerate(bands_details, 1):
                        namespace = band.get('Namespace', 'Unknown')
                        metric_name = band.get('MetricName', 'Unknown')
                        dimensions = band.get('Dimensions', 'None')
                        state = band.get('State', 'Unknown')
                        
                        details += f"{i}. <strong>{namespace}/{metric_name}</strong><br>"
                        details += f"   State: {state}<br>"
                        if dimensions and dimensions != 'None':
                            details += f"   Dimensions: {dimensions}<br>"
                        details += "<br>"
                    
                    return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
                else:
                    return f"No anomaly detection bands configured"
            return f"No anomaly detection bands found"
        
        elif check.name == "Do your log groups have resource tags for retention governance and metadata-based search?":
            tagged = check.result.get('tagged_log_groups', []) if check.result else []
            if tagged:
                summary = f"Found {len(tagged)} tagged log groups"
                details = ""
                for i, lg in enumerate(tagged[:15], 1):
                    tag_str = ', '.join(f"{k}={v}" for k, v in lg['tags'].items())
                    details += f"{i}. <strong>{lg['name']}</strong><br>   Tags: {tag_str}<br><br>"
                if len(tagged) > 15:
                    details += f"... and {len(tagged) - 15} more tagged log groups"
                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return f"No tagged log groups found"

        elif check.name == "Do you use resource tags for organizing and managing AWS resources?":
            resources = check.result.get('ResourceTagMappingList', []) if check.result else []
            if resources:
                summary = f"Found {len(resources)} tagged resources"
                details = ""
                for i, resource in enumerate(resources[:15], 1):
                    resource_arn = resource.get('ResourceARN', 'Unknown')
                    resource_type = resource_arn.split(':')[2] if ':' in resource_arn else 'Unknown'
                    resource_name = resource_arn.split('/')[-1] if '/' in resource_arn else resource_arn.split(':')[-1]
                    tags = resource.get('Tags', [])
                    tag_count = len(tags)
                    details += f"{i}. <strong>{resource_type}</strong>: {resource_name}<br>   Tags: {tag_count}<br><br>"
                if len(resources) > 15:
                    details += f"... and {len(resources) - 15} more tagged resources"
                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return f"No tagged resources found"
        
        elif check.name == "Do you use CloudWatch Synthetics to monitor application endpoints?":
            canaries = check.result.get('Canaries', []) if check.result else []
            if canaries:
                summary = f"Found {len(canaries)} synthetic canaries"
                details = ""
                for i, canary in enumerate(canaries, 1):
                    name = canary.get('Name', 'Unknown')
                    status = canary.get('Status', {}).get('State', 'Unknown')
                    runtime_version = canary.get('RuntimeVersion', 'Unknown')
                    details += f"{i}. <strong>{name}</strong><br>   Status: {status}<br>   Runtime: {runtime_version}<br><br>"
                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return f"No synthetic canaries found"
        
        elif check.name == "Do you use CloudWatch RUM to monitor real user experiences?":
            apps = check.result.get('AppMonitorSummaries', []) if check.result else []
            if apps:
                summary = f"Found {len(apps)} RUM applications"
                details = ""
                for i, app in enumerate(apps, 1):
                    name = app.get('Name', 'Unknown')
                    domain = app.get('Domain', 'Unknown')
                    state = app.get('State', 'Unknown')
                    details += f"{i}. <strong>{name}</strong><br>   Domain: {domain}<br>   State: {state}<br><br>"
                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return f"No RUM applications found"
        
        elif check.name == "Do you have any Systems Manager OpsCenter actions configured with your alarms?":
            if check.result:
                total_checked = check.result.get('total_alarms_checked', 0)
                alarms_with_opsitem = check.result.get('alarms_with_opsitem', 0)
                alarms_without_opsitem = check.result.get('alarms_without_opsitem', 0)
                alarms_with_opsitem_details = check.result.get('alarms_with_opsitem_details', [])
                alarms_without_opsitem_details = check.result.get('alarms_without_opsitem_details', [])
                
                summary = f"OpsItem actions configured for {alarms_with_opsitem} of {total_checked} alarms checked"
                
                # Create detailed breakdown
                details = f"<strong>Alarms with OpsItem Actions ({alarms_with_opsitem}):</strong><br>"
                for i, alarm in enumerate(alarms_with_opsitem_details, 1):
                    alarm_name = alarm.get('AlarmName', 'Unknown')
                    opsitem_actions = alarm.get('OpsItemActions', [])
                    details += f"{i}. <strong>Alarm:</strong> {alarm_name}<br>"
                    details += f"   <strong>OpsItem Actions ({len(opsitem_actions)}):</strong><br>"
                    for j, action in enumerate(opsitem_actions, 1):
                        details += f"     {j}. ARN: {action}<br>"
                    details += "<br>"
                
                if alarms_without_opsitem > 0:
                    details += f"<br><strong>Alarms without OpsItem Actions ({alarms_without_opsitem}):</strong><br>"
                    for i, alarm in enumerate(alarms_without_opsitem_details[:10], 1):
                        alarm_name = alarm.get('AlarmName', 'Unknown')
                        details += f"{i}. {alarm_name}<br>"
                    if len(alarms_without_opsitem_details) > 10:
                        details += f"... and {len(alarms_without_opsitem_details) - 10} more alarms without OpsItem actions<br>"
                
                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return f"No alarms found to check"
        
        elif check.name == "Do you use AWS Application Signals to monitor application services?":
            services = check.result.get('Services', []) if check.result else []
            if services:
                summary = f"Found {len(services)} Application Signals services"
                details = ""
                for i, service in enumerate(services[:10], 1):
                    service_name = service.get('ServiceName', 'Unknown')
                    namespace = service.get('Namespace', 'Unknown')
                    details += f"{i}. <strong>{service_name}</strong><br>   Namespace: {namespace}<br><br>"
                if len(services) > 10:
                    details += f"... and {len(services) - 10} more services"
                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return f"No Application Signals services found"
        
        elif check.name == "Have you defined Service Level Objectives (SLOs) for critical application services?":
            slos = check.result.get('SloSummaries', []) if check.result else []
            if slos:
                summary = f"Found {len(slos)} Application Signals SLOs"
                details = ""
                for i, slo in enumerate(slos, 1):
                    name = slo.get('Name', 'Unknown')
                    service_name = slo.get('ServiceName', 'Unknown')
                    details += f"{i}. <strong>{name}</strong><br>   Service: {service_name}<br><br>"
                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return f"No Application Signals SLOs found"
        
        elif check.name == "Anomaly Detectors":
            anomaly_detectors = check.result.get('AnomalyDetectors', []) if check.result else []
            if anomaly_detectors:
                summary = f"Found {len(anomaly_detectors)} anomaly detectors"
                details = ""
                for i, detector in enumerate(anomaly_detectors, 1):
                    namespace = detector.get('Namespace', 'Unknown')
                    metric_name = detector.get('MetricName', 'Unknown')
                    state = detector.get('StateValue', 'Unknown')
                    dimensions = detector.get('Dimensions', [])
                    dim_str = ', '.join([f"{d.get('Name', 'Unknown')}={d.get('Value', 'Unknown')}" for d in dimensions])
                    
                    details += f"{i}. <strong>{namespace}/{metric_name}</strong><br>"
                    details += f"   State: {state}<br>"
                    if dim_str:
                        details += f"   Dimensions: {dim_str}<br>"
                    details += "<br>"
                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return f"No anomaly detectors found"
        
        elif check.name == "Do you use AWS DevOps Agent for AI-assisted troubleshooting?":
            if check.result:
                total_spaces = check.result.get('total_spaces', 0)
                spaces_details = check.result.get('spaces_details', [])
                regions_checked = check.result.get('regions_checked', [])
                
                if total_spaces > 0:
                    summary = f"Found {total_spaces} DevOps Agent spaces"
                    
                    # Create detailed breakdown
                    details = f"<strong>DevOps Agent Spaces ({total_spaces}):</strong><br>"
                    details += f"<em>Regions checked: {', '.join(regions_checked)}</em><br><br>"
                    
                    for i, space in enumerate(spaces_details, 1):
                        name = space.get('name', 'Unknown')
                        space_id = space.get('agentSpaceId', 'Unknown')
                        created_at = space.get('createdAt', 'Unknown')
                        updated_at = space.get('updatedAt', 'Unknown')
                        region = space.get('region', 'Unknown')
                        
                        details += f"{i}. <strong>{name}</strong> ({region})<br>"
                        details += f"   ID: {space_id}<br>"
                        details += f"   Created: {created_at}<br>"
                        details += f"   Updated: {updated_at}<br><br>"
                    
                    return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
                else:
                    regions_str = ', '.join(regions_checked) if regions_checked else 'none'
                    return f"No DevOps Agent spaces found (checked regions: {regions_str})"
            return f"DevOps Agent service not accessible"
        
        elif check.name == "Do you have any Lambda actions configured with your alarms?":
            if check.result:
                total_checked = check.result.get('total_alarms_checked', 0)
                alarms_with_lambda = check.result.get('alarms_with_lambda', 0)
                alarms_without_lambda = check.result.get('alarms_without_lambda', 0)
                alarms_with_lambda_details = check.result.get('alarms_with_lambda_details', [])
                alarms_without_lambda_details = check.result.get('alarms_without_lambda_details', [])
                
                summary = f"Lambda actions configured for {alarms_with_lambda} of {total_checked} alarms checked"
                
                # Create detailed breakdown - only show alarms with Lambda actions
                details = f"<strong>Alarms with Lambda Actions ({alarms_with_lambda}):</strong><br>"
                for i, alarm in enumerate(alarms_with_lambda_details, 1):
                    alarm_name = alarm.get('AlarmName', 'Unknown')
                    lambda_actions = alarm.get('LambdaActions', [])
                    details += f"{i}. <strong>Alarm:</strong> {alarm_name}<br>"
                    details += f"   <strong>Lambda Actions ({len(lambda_actions)}):</strong><br>"
                    for j, action in enumerate(lambda_actions, 1):
                        function_name = action.split(':')[-1] if ':' in action else action
                        details += f"     {j}. Function: {function_name}<br>"
                        details += f"        ARN: {action}<br>"
                    details += "<br>"
                
                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return f"No alarms found to check"
        
        elif check.name == "Have you configured CloudWatch Investigations action for any alarms?":
            if check.result:
                total_checked = check.result.get('total_alarms_checked', 0)
                alarms_with_investigations = check.result.get('alarms_with_investigations', 0)
                alarms_without_investigations = check.result.get('alarms_without_investigations', 0)
                alarms_with_investigations_details = check.result.get('alarms_with_investigations_details', [])
                alarms_without_investigations_details = check.result.get('alarms_without_investigations_details', [])
                
                summary = f"CloudWatch Investigations actions configured for {alarms_with_investigations} of {total_checked} alarms checked"
                
                # Create detailed breakdown
                details = f"<strong>Alarms with CloudWatch Investigations Actions ({alarms_with_investigations}):</strong><br>"
                for i, alarm in enumerate(alarms_with_investigations_details, 1):
                    alarm_name = alarm.get('AlarmName', 'Unknown')
                    investigations_actions = alarm.get('InvestigationsActions', [])
                    details += f"{i}. <strong>Alarm:</strong> {alarm_name}<br>"
                    details += f"   <strong>Investigations Actions ({len(investigations_actions)}):</strong><br>"
                    for j, action in enumerate(investigations_actions, 1):
                        details += f"     {j}. ARN: {action}<br>"
                    details += "<br>"
                
                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return f"No alarms found to check"
        
        elif check.name == "Do you have any EC2 actions configured with your alarms?":
            if check.result:
                total_checked = check.result.get('total_alarms_checked', 0)
                alarms_with_ec2 = check.result.get('alarms_with_ec2', 0)
                alarms_with_ec2_details = check.result.get('alarms_with_ec2_details', [])
                
                summary = f"EC2 actions configured for {alarms_with_ec2} of {total_checked} alarms checked"
                
                # Create detailed breakdown - only show alarms with EC2 actions
                details = f"<strong>Alarms with EC2 Actions ({alarms_with_ec2}):</strong><br>"
                for i, alarm in enumerate(alarms_with_ec2_details, 1):
                    alarm_name = alarm.get('AlarmName', 'Unknown')
                    ec2_actions = alarm.get('EC2Actions', [])
                    details += f"{i}. <strong>Alarm:</strong> {alarm_name}<br>"
                    details += f"   <strong>EC2 Actions ({len(ec2_actions)}):</strong><br>"
                    for j, action in enumerate(ec2_actions, 1):
                        details += f"     {j}. ARN: {action}<br>"
                    details += "<br>"
                
                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return f"No alarms found to check"
        
        elif check.name == "What percentage of log groups have retention policies aligned with your compliance requirements (security: 90+ days, operational: 30 days, debug: 7 days)?":
            if check.result:
                top_groups = check.result.get('top_log_groups', [])
                groups_with_retention = check.result.get('groups_with_retention', 0)
                total_size_gb = check.result.get('total_size_gb', 0)
                
                if top_groups:
                    summary = f"Analyzed top 10 largest log groups ({total_size_gb:.1f} GB total) | {groups_with_retention}/10 have retention policies"
                    
                    # Create detailed breakdown
                    details = ""
                    for i, group in enumerate(top_groups, 1):
                        name = group.get('name', 'Unknown')
                        size_mb = group.get('size_mb', 0)
                        retention = group.get('retention_days', 'Never expire')
                        retention_str = f"{retention} days" if retention != 'Never expire' else retention
                        details += f"{i}. {name}<br>   Size: {size_mb:.1f} MB | Retention: {retention_str}<br><br>"
                    
                    return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
                return f"{base_info} | No large log groups found for retention analysis"
            return f"{base_info} - No retention analysis performed"
        
        elif check.name == "Do you have X-Ray groups configured for focused trace analysis?":
            groups = check.result.get('Groups', []) if check.result else []
            # Filter out the Default group
            custom_groups = [g for g in groups if g.get('GroupName') != 'Default']
            
            if custom_groups:
                summary = f"Found {len(custom_groups)} custom X-Ray groups"
                details = ""
                for i, group in enumerate(custom_groups, 1):
                    name = group.get('GroupName', 'Unknown')
                    filter_expr = group.get('FilterExpression', 'No filter')
                    insights = group.get('InsightsConfiguration', {})
                    insights_enabled = insights.get('InsightsEnabled', False)
                    
                    details += f"{i}. <strong>{name}</strong><br>"
                    details += f"   Filter: {filter_expr}<br>"
                    details += f"   Insights: {'Enabled' if insights_enabled else 'Disabled'}<br><br>"
                
                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            else:
                return f"No custom X-Ray groups configured (only Default group exists)"
        
        elif check.name == "Do you have custom X-Ray sampling rules configured?":
            sampling_rules = check.result.get('SamplingRuleRecords', []) if check.result else []
            custom_rules = [rule for rule in sampling_rules if rule.get('SamplingRule', {}).get('RuleName') != 'Default']
            
            if custom_rules:
                summary = f"Found {len(custom_rules)} custom sampling rules"
                details = ""
                for i, record in enumerate(custom_rules, 1):
                    rule = record.get('SamplingRule', {})
                    name = rule.get('RuleName', 'Unknown')
                    priority = rule.get('Priority', 'Unknown')
                    fixed_rate = rule.get('FixedRate', 0)
                    service = rule.get('ServiceName', '*')
                    details += f"{i}. <strong>{name}</strong><br>"
                    details += f"   Priority: {priority}<br>"
                    details += f"   Fixed Rate: {fixed_rate * 100}%<br>"
                    details += f"   Service: {service}<br><br>"
                
                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            else:
                default_count = len(sampling_rules)
                return f"No custom sampling rules configured (only {default_count} default rule exists)"
        
        elif check.name == "What percentage of your log groups are categorized by source type (AWS Service Vended Logs, Custom Logs)":
            if isinstance(check.result, dict):
                total = check.result.get('total_log_groups', 0)
                vended_count = check.result.get('vended_count', 0)
                custom_count = check.result.get('custom_count', 0)
                vended_logs = check.result.get('vended_logs', [])
                custom_logs = check.result.get('custom_logs', [])
                
                summary = f"Total: {total} log groups | Vended: {vended_count} | Custom: {custom_count}"
                details = ""
                
                if vended_logs:
                    details += "<strong>AWS Vended/Service Logs:</strong><br>"
                    for log in vended_logs:
                        details += f"  • {log}<br>"
                    details += "<br>"
                
                if custom_logs:
                    details += "<strong>Custom Application Logs:</strong><br>"
                    for log in custom_logs:
                        details += f"  • {log}<br>"
                
                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            else:
                return "No log groups found"
        
        elif check.name == "Are all five EKS control plane log types enabled (api, audit, authenticator, controllerManager, scheduler)?":
            if isinstance(check.result, dict):
                clusters = check.result.get('clusters', [])
                enabled_types = check.result.get('enabled_types', 0)
                if clusters:
                    cluster_summary = ', '.join([f"{c['cluster']} ({len(c['enabled_types'])}/5)" for c in clusters[:3]])
                    return f"Found {len(clusters)} EKS cluster(s) with {enabled_types}/5 log types enabled across all clusters (e.g., {cluster_summary})"
                return f"No EKS clusters found"
            return f"No EKS control plane log configuration found"
        
        elif check.name == "Do you have dashboards configured with variables?":
            if check.result:
                total_dashboards = check.result.get('total_dashboards', 0)
                dashboards_with_variables = check.result.get('dashboards_with_variables', 0)
                dashboards_with_variables_details = check.result.get('dashboards_with_variables_details', [])
                
                if dashboards_with_variables > 0:
                    summary = f"{base_info} | {dashboards_with_variables}/{total_dashboards} dashboards have dynamic variables"
                    
                    # Create detailed breakdown
                    details = f"<strong>Dashboards with Variables ({dashboards_with_variables}):</strong><br>"
                    for i, dashboard in enumerate(dashboards_with_variables_details, 1):
                        name = dashboard.get('DashboardName', 'Unknown')
                        indicators = dashboard.get('VariableIndicators', [])
                        size = dashboard.get('Size', 0)
                        details += f"{i}. <strong>{name}</strong><br>"
                        details += f"   Variable Features: {', '.join(indicators)}<br>"
                        details += f"   Size: {size} bytes<br><br>"
                    
                    return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
                
                return f"{base_info} | {dashboards_with_variables}/{total_dashboards} dashboards have dynamic variables"
            return f"{base_info} | No dashboards found"
        
        # Default handler for other checks
        else:
            # Provide specific context for known checks that might return empty results
            if check.name == "Is the EKS CloudWatch Observability add-on deployed with Container Insights and Application Signals enabled?":
                return f"{base_info} | {command_info} | No EKS clusters found or CloudWatch Observability add-on not installed"
            elif check.name == "Have you enabled anomaly detection?":
                return f"{command_info} | No log anomaly detectors found - CloudWatch Logs anomaly detection not configured"
            elif check.name == "Are you using CloudWatch cross-account observability?":
                return f"{command_info} | No OAM links found - CloudWatch Observability Access Manager not configured for cross-account log access"
            
            # Try to find common patterns in the result
            if isinstance(check.result, dict):
                # Count items in common AWS response patterns
                item_count = 0
                items = []
                
                # Common AWS response patterns
                for key in ['Items', 'Resources', 'Clusters', 'Services', 'Policies', 'Rules', 'Metrics']:
                    if key in check.result:
                        items = check.result[key]
                        item_count = len(items)
                        break
                
                if item_count > 0:
                    summary = f"Found {item_count} items"
                    # Try to extract names or IDs
                    details = ""
                    for i, item in enumerate(items[:15]):
                        if isinstance(item, dict):
                            # Look for common name fields
                            name = item.get('Name') or item.get('name') or item.get('Id') or item.get('id') or str(item)[:100]
                            details += f"{name}<br>"
                        else:
                            details += f"{str(item)[:100]}<br>"
                    if len(items) > 15:
                        details += f"... and {len(items) - 15} more items"
                    return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
                else:
                    return f"No items found"
            else:
                return f"Command executed successfully"

        if check.name == "Saved Log Insights Queries":
            query_definitions = check.result.get('queryDefinitions', [])
            if query_definitions:
                query_details = []
                for query_def in query_definitions[:3]:  # Show first 3 saved queries
                    name = query_def.get('name', 'Unnamed')
                    query_string = query_def.get('queryString', 'No query string')[:100]
                    log_groups = query_def.get('logGroupNames', [])
                    log_group_info = f"Groups: {', '.join(log_groups[:2])}" if log_groups else "No log groups"
                    query_details.append(f"Name:{name} Query:{query_string} {log_group_info}")
                
                return f"{command_info} | Found {len(query_definitions)} saved query definitions | Details: {' | '.join(query_details)}"
            return f"{command_info} | No saved query definitions found"
        
        elif check.name == "Do you have a history of Log Insights queries being executed?":
            queries = check.result.get('queries', [])
            if queries:
                # Filter out system/default queries (Application Signals, etc.)
                custom_queries = []
                for query in queries:
                    query_string = query.get('queryString', '')
                    # Skip queries that look like system-generated ones
                    if not any(pattern in query_string for pattern in [
                        'SOURCE "/aws/application-signals/',
                        '/aws/containerinsights/',  # Container Insights auto queries
                    ]):
                        custom_queries.append(query)
                
                if custom_queries:
                    query_details = []
                    for query in custom_queries[:3]:  # Show first 3 custom queries
                        query_id = query.get('queryId', 'Unknown')[:8]  # Shorter ID
                        query_string = query.get('queryString', 'No query string')[:80]
                        status = query.get('status', 'Unknown')
                        query_details.append(f"ID:{query_id} Status:{status} Query:{query_string}")
                    
                    return f"{command_info} | Found {len(custom_queries)} custom queries (filtered from {len(queries)} total) | Details: {' | '.join(query_details)}"
                else:
                    return f"{command_info} | Found {len(queries)} total queries but no custom user-generated queries (all appear to be system/auto-generated)"
            return f"{command_info} | No query history found - no CloudWatch Logs Insights queries have been executed recently"
        
        
        
        elif check.name == "Do you have CloudWatch alarms configured for your resources?":
            metric_alarms = check.result.get('MetricAlarms', [])
            composite_alarms = check.result.get('CompositeAlarms', [])
            total_alarms = len(metric_alarms) + len(composite_alarms)
            if total_alarms > 0:
                summary = f"Found {total_alarms} alarms ({len(metric_alarms)} metric, {len(composite_alarms)} composite)"
                details = "<strong>Metric Alarms:</strong><br>" + "<br>".join([alarm.get('AlarmName', 'Unknown') for alarm in metric_alarms[:10]])
                if len(metric_alarms) > 10:
                    details += f"<br>... and {len(metric_alarms) - 10} more metric alarms"
                if composite_alarms:
                    details += "<br><br><strong>Composite Alarms:</strong><br>" + "<br>".join([alarm.get('AlarmName', 'Unknown') for alarm in composite_alarms[:10]])
                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return f"No alarms found"
        
        elif check.name == "Do you have CloudWatch dashboards for visualizing metrics and logs?":
            dashboards = check.result.get('DashboardEntries', [])
            if dashboards:
                sample_names = [dash.get('DashboardName', 'Unknown') for dash in dashboards[:3]]
                return f"Found {len(dashboards)} dashboards (e.g., {', '.join(sample_names)})"
            return f"No dashboards found"
        
        elif check.name == "SNS Topics":
            topics = check.result.get('Topics', [])
            if topics:
                sample_arns = [topic.get('TopicArn', 'Unknown').split(':')[-1] for topic in topics[:3]]
                return f"Found {len(topics)} SNS topics (e.g., {', '.join(sample_arns)})"
            return f"No SNS topics found"
        
        elif check.name == "VPC Flow Logs":
            flow_logs = check.result.get('FlowLogs', [])
            if flow_logs:
                sample_ids = [fl.get('FlowLogId', 'Unknown') for fl in flow_logs[:3]]
                return f"Found {len(flow_logs)} VPC flow logs (e.g., {', '.join(sample_ids)})"
            return f"No VPC flow logs found"
        
        elif check.name == "CloudTrail Trails":
            trails = check.result.get('trailList', [])
            if trails:
                sample_names = [trail.get('Name', 'Unknown') for trail in trails[:3]]
                return f"Found {len(trails)} CloudTrail trails (e.g., {', '.join(sample_names)})"
            return f"No CloudTrail trails found"
        
        elif check.name == "What percentage of Lambda functions use JSON structured logging?":
            if isinstance(check.result, dict):
                total = check.result.get('total_functions', 0)
                json_count = check.result.get('json_logging_count', 0)
                
                if total > 0:
                    percentage = int((json_count / total) * 100)
                    return f"{command_info} | {json_count}/{total} Lambda functions ({percentage}%) have JSON structured logging configured"
                else:
                    return f"{command_info} | No Lambda functions found"
            return f"{command_info} | No Lambda functions found"
        elif check.name == "What percentage of ECS tasks use structured logging (JSON)?":
            clusters = check.result.get('clusters', [])
            running_tasks = check.result.get('running_tasks', [])
            tasks_with_logging = check.result.get('tasks_with_logging', [])
            logging_configs = check.result.get('logging_configs', [])
            
            total_running = len(running_tasks)
            logging_count = len(tasks_with_logging)
            
            if total_running > 0:
                percentage = int((logging_count / total_running) * 100)
                
                # Show detailed logging configurations
                config_details = []
                for config in logging_configs:
                    task_def = config['taskDefinition']
                    containers_info = []
                    for container in config['containers']:
                        driver = container['logDriver']
                        if driver == 'awslogs':
                            log_group = container['options'].get('awslogs-group', 'Unknown')
                            containers_info.append(f"{container['container']}:awslogs->{log_group}")
                        elif driver != 'none':
                            containers_info.append(f"{container['container']}:{driver}")
                        else:
                            containers_info.append(f"{container['container']}:no-logging")
                    config_details.append(f"{task_def}[{','.join(containers_info)}]")
                
                configs_summary = " | ".join(config_details[:3])  # Show first 3
                return f"Command: Multi-step ECS task logging analysis | {logging_count}/{total_running} running tasks ({percentage}%) have logging configured | Configs: {configs_summary}"
            elif clusters:
                return f"Command: Multi-step ECS task logging analysis | No running tasks found | Clusters checked: {len(clusters)}"
            else:
                return f"Command: Multi-step ECS task logging analysis | No ECS clusters found"
        
        elif check.name == "EC2 CloudWatch Agent IAM":
            policies = check.result.get('AttachedPolicies', [])
            if policies:
                policy_names = [p.get('PolicyName', 'Unknown') for p in policies[:3]]
                return f"Found {len(policies)} IAM policies for CloudWatch Agent (e.g., {', '.join(policy_names)})"
            return f"No CloudWatch Agent IAM policies found"
        
        elif check.name == "Have you enabled anomaly detection?":
            anomaly_detectors = check.result.get('anomalyDetectors', [])
            if anomaly_detectors:
                detector_details = []
                for detector in anomaly_detectors:
                    detector_name = detector.get('detectorName', 'Unknown')
                    status = detector.get('anomalyDetectorStatus', 'Unknown')
                    log_groups = detector.get('logGroupArnList', [])
                    
                    # Extract log group names from ARNs
                    log_group_names = []
                    for arn in log_groups:
                        log_group_name = arn.split(':')[-1] if ':' in arn else arn
                        log_group_names.append(log_group_name)
                    
                    groups_summary = ', '.join(log_group_names[:2])  # Show first 2 groups
                    detector_details.append(f"{detector_name}({status})->{groups_summary}")
                
                detectors_summary = " | ".join(detector_details)
                return f"{command_info} | Found {len(anomaly_detectors)} log anomaly detectors | Details: {detectors_summary}"
            return f"{command_info} | No log anomaly detectors found"
        
        elif check.name == "Do you have log export tasks configured for archival?":
            if check.result:
                total_groups = check.result.get('total_log_groups', 0)
                exported_groups = check.result.get('exported_log_groups', 0)
                sample_groups = check.result.get('sample_exported_groups', [])
                
                if exported_groups > 0:
                    sample_info = f"Examples: {', '.join(sample_groups[:3])}" if sample_groups else ""
                    return f"Found {exported_groups}/{total_groups} log groups with export task history | {sample_info}"
                return f"Checked {total_groups} log groups - {exported_groups}/{total_groups} have export task history"
            return f"No log groups checked for export tasks"
        
        elif check.name == "Have you implemented Cross-Account and Cross-Region Log Centralization?":
            if check.result:
                patterns = check.result.get('centralization_patterns', [])
                account_type = check.result.get('account_type', 'Unknown')
                org_status = check.result.get('organization_status', 'Unknown')
                
                if patterns:
                    pattern_summary = ', '.join(patterns)
                    return f"Account type: {account_type} | Organization: {org_status} | Centralization patterns: {pattern_summary}"
                return f"Account type: {account_type} | Organization: {org_status} | No centralization patterns detected"
            return f"No centralization analysis performed"
        
        elif check.name == "What percentage of application logs use structured JSON format for easier parsing and analysis?":
            if check.result:
                total_checked = check.result.get('total_groups_checked', 0)
                json_groups = check.result.get('json_groups', 0)
                sample_groups = check.result.get('sample_groups', [])
                
                if json_groups > 0:
                    sample_info = f"Examples: {', '.join(sample_groups[:3])}" if sample_groups else ""
                    return f"Analyzed {total_checked} largest log groups | {json_groups}/{total_checked} have JSON structured logs | {sample_info}"
                return f"Analyzed {total_checked} largest log groups | {json_groups}/{total_checked} have JSON structured logs"
            return f"No JSON structured log analysis performed"
        

        elif check.name == "Do you have field index policies configured for faster log queries?":
            if check.result:
                total_groups = check.result.get('total_log_groups', 0)
                indexed_groups = check.result.get('indexed_log_groups', 0)
                sample_groups = check.result.get('sample_indexed_groups', [])
                
                if indexed_groups > 0:
                    sample_info = f"Examples: {', '.join(sample_groups[:3])}" if sample_groups else ""
                    return f"Checked {total_groups} largest log groups by size - {indexed_groups}/{total_groups} have field index policies | {sample_info}"
                return f"Checked {total_groups} largest log groups by size - {indexed_groups}/{total_groups} have field index policies"
            return f"No largest log groups checked for field indexes"

        elif check.name == "Do you have EKS clusters with CloudWatch Observability add-on enabled?":
            if check.result:
                total_clusters = check.result.get('total_clusters', 0)
                observability_clusters = check.result.get('observability_clusters', 0)
                clusters_with_obs = check.result.get('clusters_with_observability', [])
                
                if observability_clusters > 0:
                    examples = f"Examples: {', '.join(clusters_with_obs[:3])}" if clusters_with_obs else ""
                    return f"{observability_clusters}/{total_clusters} EKS clusters have amazon-cloudwatch-observability add-on | {examples}"
                return f"{observability_clusters}/{total_clusters} EKS clusters have amazon-cloudwatch-observability add-on"
            return f"{base_info} | No EKS clusters found"

        elif check.name == "Do you use X-Ray service maps to visualize application architecture?":
            services = check.result.get('Services', [])
            if services:
                sample_names = [svc.get('Name', 'Unknown') for svc in services[:3]]
                return f"{base_info} | Found {len(services)} X-Ray services (e.g., {', '.join(sample_names)})"
            return f"{base_info} | No X-Ray services found"
        
        # Generic handling for other checks
        elif isinstance(check.result, dict):
            # Try to find common list keys first
            for key in ['Items', 'Resources', 'Entries', 'Rules', 'Policies', 'Canaries', 'AppMonitors', 'Queries', 'metricFilters', 'SamplingRuleRecords', 'ClusterArns', 'Metrics', 'Subscriptions', 'Policies', 'OpsItemSummaries', 'IncidentRecordSummaries']:
                if key in check.result:
                    items = check.result[key]
                    if items:
                        return f"{command_info} | Found {len(items)} {key.lower()}"
                    return f"{command_info} | No {key.lower()} found"
            
            # Check for specific response patterns
            if 'EncryptionConfig' in check.result:
                return f"{command_info} | X-Ray encryption configuration retrieved"
            elif 'Organization' in check.result:
                return f"{command_info} | Organization configuration retrieved"
            elif 'AccountHealth' in check.result:
                return f"{command_info} | DevOps Guru account health retrieved"
            
            # If it's a dict with meaningful data, be more specific
            if check.result and len(check.result) > 0:
                # Count non-empty values
                non_empty_keys = [k for k, v in check.result.items() if v]
                if non_empty_keys:
                    return f"{command_info} | Configuration retrieved ({len(non_empty_keys)} properties)"
                else:
                    return f"{command_info} | Empty configuration returned"
            return f"{command_info} | No configuration found"
        
        elif isinstance(check.result, list):
            if check.result:
                return f"{command_info} | Found {len(check.result)} items"
            return f"{command_info} | No items found"
        
        return f"{command_info} | Data retrieved successfully"

    def setup_discovery_checks(self):
        """Setup all discovery checks across all categories"""
        print("🔍 Setting up discovery checks...")
        
        # Get largest log groups by compute type for later use
        print("📊 Identifying largest log groups by compute type...")
        self.largest_log_groups = self.get_largest_log_groups_by_compute_type()
        total_groups = sum(len(groups) for groups in self.largest_log_groups.values())
        print(f"   Found {total_groups} largest log groups: EC2({len(self.largest_log_groups['EC2'])}), ECS({len(self.largest_log_groups['ECS'])}), Lambda({len(self.largest_log_groups['Lambda'])}), EKS({len(self.largest_log_groups['EKS'])})")
        
        # Logs Discovery Checks (Enhanced)
        self.add_discovery_check("What percentage of your log groups are categorized by source type (AWS Service Vended Logs, Custom Logs)", "Logs", "custom_log_groups_categorization_check")
        self.add_discovery_check("What percentage of log groups have retention policies aligned with your compliance requirements (security: 90+ days, operational: 30 days, debug: 7 days)?", "Logs", "custom_top_log_groups_retention_check")
        self.add_discovery_check("Do you have standardized Log Insights queries for common troubleshooting scenarios (errors, latency, security events)?", "Logs", "aws logs describe-query-definitions --output json")
        self.add_discovery_check("Do you have a history of Log Insights queries being executed?", "Logs", "aws logs describe-queries --output json")
        self.add_discovery_check("Have you created metric filters to extract KPIs from logs?", "Logs", "aws logs describe-metric-filters --output json")
        self.add_discovery_check("What percentage of log groups have subscription filters for real-time processing?", "Logs", "custom_subscription_filters_coverage_check")
        
        # Service-Specific Log Collection
        self.add_discovery_check("What percentage of EC2 instances have CloudWatch Agent installed with both system metrics AND application logs configured?", "Logs", "custom_ec2_cloudwatch_agent_check")
        self.add_discovery_check("What percentage of Lambda functions use JSON structured logging?", "Logs", "custom_lambda_json_logging_check")
        self.add_discovery_check("What percentage of ECS tasks use structured logging (JSON)?", "Logs", "custom_ecs_task_log_check")
        self.add_discovery_check("Are all five EKS control plane log types enabled (api, audit, authenticator, controllerManager, scheduler)?", "Logs", "custom_eks_control_plane_logs_check")
        self.add_discovery_check("Is the EKS CloudWatch Observability add-on deployed with Container Insights and Application Signals enabled?", "Logs", "custom_eks_addons_check")
        
        # Advanced Log Analysis
        self.add_discovery_check("Have you enabled anomaly detection?", "Logs", "aws logs list-log-anomaly-detectors --output json")
        self.add_discovery_check("Do you have log export tasks configured for archival?", "Logs", "custom_log_export_tasks_per_log_group_check")
        self.add_discovery_check("Have you implemented Cross-Account and Cross-Region Log Centralization?", "Logs", "custom_log_centralization_analysis_check")
        self.add_discovery_check("Are you using CloudWatch cross-account observability?", "Logs", "custom_oam_links_and_sinks_check")
        self.add_discovery_check("What percentage of application logs use structured JSON format for easier parsing and analysis?", "Logs", "custom_json_structured_logs_check")
        self.add_discovery_check("Do you have field index policies configured for faster log queries?", "Logs", "custom_field_indexes_per_log_group_check")
        
        # Metrics Discovery Checks (Detailed)
        self.add_discovery_check("What percentage of production EC2 instances have detailed monitoring (1-minute metrics) enabled?", "Metrics", "aws ec2 describe-instances --query 'Reservations[].Instances[?Monitoring.State==`enabled`]' --output json")
        self.add_discovery_check("What percentage of ECS Clusters have monitoring enabled?", "Metrics", "aws ecs list-clusters --output json")
        self.add_discovery_check("Do you have ECS clusters with Container Insights enabled?", "Metrics", "aws ecs describe-clusters --clusters PetsiteECS-cluster --include SETTINGS --output json")
        self.add_discovery_check("Do you have EKS clusters with CloudWatch Observability add-on enabled?", "Metrics", "custom_eks_addons_check")
        self.add_discovery_check("What percentage of Lambda functions have Lambda Insights enabled for enhanced metrics?", "Metrics", "custom_lambda_insights_check")

        self.add_discovery_check("Are you publishing custom business and application metrics to CloudWatch?", "Metrics", "custom_metrics_namespaces_check")
        self.add_discovery_check("Are CloudWatch Agents configured to collect system-level metrics?", "Metrics", "aws cloudwatch list-metrics --namespace CWAgent --output json")
        self.add_discovery_check("Have you configured metric streams for real-time export to third-party tools or data lakes?", "Metrics", "aws cloudwatch list-metric-streams --output json")
        
        # Traces Discovery Checks (Detailed)
        self.add_discovery_check("Do you use X-Ray service maps to visualize application architecture?", "Traces", "custom_xray_service_graph_check")
        self.add_discovery_check("Do you have custom X-Ray sampling rules configured?", "Traces", "custom_xray_sampling_rules_check")
        self.add_discovery_check("Do you have X-Ray groups configured for focused trace analysis?", "Traces", "aws xray get-groups --output json")
        self.add_discovery_check("Do you have transaction search enabled?", "Traces", "aws logs describe-log-groups --log-group-name-prefix aws/spans --output json")
        self.add_discovery_check("Do your Lambda functions have X-Ray tracing enabled?", "Traces", "aws lambda list-functions --query 'Functions[?TracingConfig.Mode==`Active`]' --output json")
        self.add_discovery_check("Do you have X-Ray Insights configured for anomaly detection?", "Traces", "aws xray get-insight-summaries --output json")
        
        # Dashboards & Alarms Discovery Checks (Detailed)
        self.add_discovery_check("Do you have CloudWatch dashboards for visualizing metrics and logs?", "Dashboards", "aws cloudwatch list-dashboards --output json")
        self.add_discovery_check("Do you have CloudWatch alarms configured for your resources?", "Alarms", "custom_cloudwatch_alarms_check")

        self.add_discovery_check("Do you use composite alarms to reduce alarm noise?", "Alarms", "aws cloudwatch describe-alarms --alarm-types CompositeAlarm --output json")

        self.add_discovery_check("Do your alarms send notifications to SNS topics?", "Alarms", "custom_alarm_sns_configuration_check")
        self.add_discovery_check("Do you use anomaly detection models for adaptive alarming?", "Alarms", "custom_anomaly_detection_bands_check")
        
        # Organization Discovery Checks (Detailed)
        self.add_discovery_check("Do you use resource tags for organizing and managing AWS resources?", "Organization", "aws resourcegroupstaggingapi get-resources --output json")
        self.add_discovery_check("Do you use CloudWatch Synthetics to monitor application endpoints?", "Organization", "aws synthetics describe-canaries --output json")
        self.add_discovery_check("Do you use CloudWatch RUM to monitor real user experiences?", "Organization", "aws rum list-app-monitors --output json")
        self.add_discovery_check("Do you have any Systems Manager OpsCenter actions configured with your alarms?", "Organization", "custom_alarm_opsitem_actions_check")
        self.add_discovery_check("Do you use AWS DevOps Agent for AI-assisted troubleshooting?", "Organization", "custom_devops_agent_spaces_check")
        self.add_discovery_check("Do you have any Lambda actions configured with your alarms?", "Alarms", "custom_alarm_lambda_actions_check")
        self.add_discovery_check("Have you configured CloudWatch Investigations action for any alarms?", "Alarms", "custom_alarm_investigations_actions_check")
        self.add_discovery_check("Do you have any EC2 actions configured with your alarms?", "Alarms", "custom_alarm_ec2_actions_check")
        self.add_discovery_check("Do you have dashboards configured with variables?", "Dashboards", "custom_dashboard_variables_check")
        
        # Cross-Category Checks (checks that apply to multiple categories)
        # Application Signals - applies to Metrics, Traces, and Organization
        self.add_discovery_check("Do you use AWS Application Signals to monitor application services?", "Metrics", "custom_app_signals_list_services_check")
        self.add_discovery_check("Do you use AWS Application Signals to monitor application services?", "Traces", "custom_app_signals_list_services_check")
        self.add_discovery_check("Have you defined Service Level Objectives (SLOs) for critical application services?", "Metrics", "aws application-signals list-service-level-objectives --output json")
        self.add_discovery_check("Have you defined Service Level Objectives (SLOs) for critical application services?", "Organization", "aws application-signals list-service-level-objectives --output json")
        
        # CloudWatch Dashboards - applies to Logs, Metrics, Traces access
        self.add_discovery_check("Do you have CloudWatch dashboards for visualizing metrics and logs?", "Logs", "aws cloudwatch list-dashboards --output json")
        self.add_discovery_check("Do you have CloudWatch dashboards for visualizing metrics and logs?", "Metrics", "aws cloudwatch list-dashboards --output json")
        
        # Log Group Tags - applies to Logs retention (metadata-based search)
        self.add_discovery_check("Do your log groups have resource tags for retention governance and metadata-based search?", "Logs", "custom_log_group_tags_check")

    def get_largest_log_groups_by_compute_type(self):
        """Get 10 largest log groups for each compute type (EC2, ECS, Lambda, EKS)"""
        try:
            log_groups_result = self.run_aws_command("aws logs describe-log-groups --output json")
            if not log_groups_result or 'logGroups' not in log_groups_result:
                return {'EC2': [], 'ECS': [], 'Lambda': [], 'EKS': []}
            
            all_log_groups = log_groups_result['logGroups']
            
            # Categorize log groups by compute type
            compute_groups = {'EC2': [], 'ECS': [], 'Lambda': [], 'EKS': []}
            
            for lg in all_log_groups:
                group_name = lg.get('logGroupName', '')
                size_bytes = lg.get('storedBytes', 0)
                
                if '/aws/lambda/' in group_name:
                    compute_groups['Lambda'].append((group_name, size_bytes))
                elif '/aws/ecs/' in group_name or ('/aws/containerinsights/' in group_name and 'ecs' in group_name.lower()) or '/ecs/' in group_name or 'ecs' in group_name.lower():
                    compute_groups['ECS'].append((group_name, size_bytes))
                elif '/aws/eks/' in group_name or ('/aws/containerinsights/' in group_name and 'eks' in group_name.lower()):
                    compute_groups['EKS'].append((group_name, size_bytes))
                elif '/aws/ec2/' in group_name or any(keyword in group_name.lower() for keyword in ['ec2', 'instance', 'server']):
                    compute_groups['EC2'].append((group_name, size_bytes))
            
            # Get top 10 largest for each compute type
            largest_groups = {}
            for compute_type, groups in compute_groups.items():
                # Sort by size (descending) and take top 10
                sorted_groups = sorted(groups, key=lambda x: x[1], reverse=True)[:10]
                largest_groups[compute_type] = [group[0] for group in sorted_groups]  # Just the names
            
            return largest_groups
            
        except Exception as e:
            return {'EC2': [], 'ECS': [], 'Lambda': [], 'EKS': []}
            
            # Step 2: Categorize log groups by service
            service_groups = {'Lambda': [], 'EC2': [], 'ECS': [], 'EKS': []}
            
            for lg in log_groups_result['logGroups']:
                group_name = lg.get('logGroupName', '')
                if '/aws/lambda/' in group_name:
                    service_groups['Lambda'].append(group_name)
                elif '/aws/ec2/' in group_name or 'ec2' in group_name.lower():
                    service_groups['EC2'].append(group_name)
                elif '/aws/ecs/' in group_name or ('/aws/containerinsights/' in group_name and 'ecs' in group_name.lower()):
                    service_groups['ECS'].append(group_name)
                elif '/aws/eks/' in group_name or ('/aws/containerinsights/' in group_name and 'eks' in group_name.lower()):
                    service_groups['EKS'].append(group_name)
            
            # Step 3: Check log streams for first log group from each service (up to 5 total)
            all_streams = []
            checked_groups = []
            
            for service, groups in service_groups.items():
                if groups and len(checked_groups) < 5:
                    group_name = groups[0]  # Take first group from each service
                    try:
                        # Properly quote the log group name for shell execution
                        command = f'aws logs describe-log-streams --log-group-name "{group_name}" --limit 10 --output json'
                        streams_result = self.run_aws_command(command)
                        if streams_result and 'logStreams' in streams_result:
                            all_streams.extend(streams_result['logStreams'])
                            checked_groups.append(group_name)
                    except Exception as e:
                        # If individual group fails, continue with others
                        continue
            
            return {'logStreams': all_streams, 'checkedGroups': checked_groups}
            
        except Exception as e:
            return {'logStreams': []}

    def execute_ec2_cloudwatch_agent_check(self):
        """Custom check for EC2 CloudWatch Agent - SSM agent, CW agent deployment, and logging config"""
        try:
            # Step 1: Get all EC2 instances
            ec2_result = self.run_aws_command("aws ec2 describe-instances --output json")
            if not ec2_result or 'Reservations' not in ec2_result:
                return {'instances': [], 'ssm_instances': [], 'cw_agent_instances': [], 'logging_configured_instances': []}
            
            # Extract all instances
            all_instances = []
            for reservation in ec2_result['Reservations']:
                all_instances.extend(reservation.get('Instances', []))
            
            # Filter running instances
            running_instances = [inst for inst in all_instances if inst.get('State', {}).get('Name') == 'running']
            
            if not running_instances:
                return {'instances': [], 'ssm_instances': [], 'cw_agent_instances': [], 'logging_configured_instances': []}
            
            # Step 2: Check SSM agent status for running instances
            instance_ids = [inst.get('InstanceId') for inst in running_instances]
            ssm_instances = []
            
            try:
                ssm_result = self.run_aws_command("aws ssm describe-instance-information --output json")
                if ssm_result and 'InstanceInformationList' in ssm_result:
                    ssm_instance_ids = [info.get('InstanceId') for info in ssm_result['InstanceInformationList']]
                    ssm_instances = [inst_id for inst_id in instance_ids if inst_id in ssm_instance_ids]
            except:
                pass
            
            # Step 3: Check CloudWatch agent status on SSM-enabled instances
            cw_agent_instances = []
            logging_configured_instances = []
            
            for instance_id in ssm_instances[:5]:  # Limit to first 5 for performance
                try:
                    # Check multiple ways CloudWatch agent can be running
                    command_result = self.run_aws_command(f'aws ssm send-command --instance-ids {instance_id} --document-name "AWS-RunShellScript" --parameters \'commands=["pgrep -f amazon-cloudwatch-agent >/dev/null && echo PROCESS_RUNNING || echo PROCESS_NOT_RUNNING","systemctl is-active amazon-cloudwatch-agent 2>/dev/null || echo SERVICE_NOT_ACTIVE","ps aux | grep -E cloudwatch | grep -v grep | wc -l"]\' --output json')
                    
                    if command_result and 'Command' in command_result:
                        command_id = command_result['Command']['CommandId']
                        
                        # Wait and get command output
                        import time
                        time.sleep(3)
                        
                        output_result = self.run_aws_command(f'aws ssm get-command-invocation --command-id {command_id} --instance-id {instance_id} --output json')
                        
                        if output_result and output_result.get('Status') == 'Success':
                            stdout = output_result.get('StandardOutputContent', '')
                            print(f"DEBUG: Instance {instance_id} CW agent check output: {repr(stdout[:100])}")
                            
                            # Check if agent is running (process, service, or container)
                            if ('PROCESS_RUNNING' in stdout or 
                                'active' in stdout.lower() or 
                                any(int(line.strip()) > 0 for line in stdout.split('\n') if line.strip().isdigit())):
                                
                                print(f"DEBUG: Instance {instance_id} has CW agent running")
                                cw_agent_instances.append(instance_id)
                                
                                # Step 4: Check for actual log collection configuration (not agent's own logs)
                                config_command = self.run_aws_command(f'aws ssm send-command --instance-ids {instance_id} --document-name "AWS-RunShellScript" --parameters \'commands=["find /opt/aws/amazon-cloudwatch-agent/etc/ -name *.json -exec grep -l log_group_name {{}} \\\\; 2>/dev/null | wc -l"]\' --output json')
                                if config_command and 'Command' in config_command:
                                    config_command_id = config_command['Command']['CommandId']
                                    time.sleep(3)
                                    
                                    config_output = self.run_aws_command(f'aws ssm get-command-invocation --command-id {config_command_id} --instance-id {instance_id} --output json')
                                    
                                    if config_output and config_output.get('Status') == 'Success':
                                        config_content = config_output.get('StandardOutputContent', '')
                                        
                                        # Check if actual log collection configuration is found (not just agent logs)
                                        lines = config_content.strip().split('\n')
                                        print(f"DEBUG: Instance {instance_id} config content: {repr(config_content[:200])}")
                                        print(f"DEBUG: First line: {repr(lines[0]) if lines else 'No lines'}")
                                        # First line should be the count, check if it's > 0
                                        if lines and lines[0].strip().isdigit() and int(lines[0].strip()) > 0:
                                            print(f"DEBUG: Adding {instance_id} to logging_configured_instances")
                                            logging_configured_instances.append(instance_id)
                except:
                    continue  # Skip instances that fail
            
            return {
                'instances': instance_ids,
                'ssm_instances': ssm_instances,
                'cw_agent_instances': cw_agent_instances,
                'logging_configured_instances': logging_configured_instances,
                'total_instances': len(instance_ids),
                'logging_configured_count': len(logging_configured_instances)
            }
            
        except Exception as e:
            return {'instances': [], 'ssm_instances': [], 'cw_agent_instances': [], 'logging_configured_instances': [], 'total_instances': 0, 'logging_configured_count': 0}

    def execute_lambda_json_logging_check(self):
        """Check Lambda functions for JSON structured logging configuration"""
        try:
            # Get all Lambda functions
            functions_result = self.run_aws_command("aws lambda list-functions --output json")
            if not functions_result or 'Functions' not in functions_result:
                return {'total_functions': 0, 'json_logging_count': 0, 'functions_with_json': []}
            
            functions = functions_result['Functions']
            total_functions = len(functions)
            functions_with_json = []
            
            # Check each function's logging configuration
            for func in functions[:20]:  # Limit to first 20 for performance
                func_name = func.get('FunctionName', '')
                
                try:
                    # Get function configuration
                    config_result = self.run_aws_command(f'aws lambda get-function-configuration --function-name {func_name} --output json')
                    if config_result:
                        # Check environment variables for JSON logging indicators
                        env_vars = config_result.get('Environment', {}).get('Variables', {})
                        
                        # Common JSON logging indicators
                        json_indicators = [
                            'LOG_FORMAT' in env_vars and 'json' in env_vars.get('LOG_FORMAT', '').lower(),
                            'LOGGING_FORMAT' in env_vars and 'json' in env_vars.get('LOGGING_FORMAT', '').lower(),
                            'LOG_LEVEL' in env_vars and 'JSON' in env_vars.get('LOG_LEVEL', '').upper(),
                            'POWERTOOLS_LOG_FORMAT' in env_vars and 'json' in env_vars.get('POWERTOOLS_LOG_FORMAT', '').lower(),
                            'AWS_LAMBDA_LOG_FORMAT' in env_vars and 'json' in env_vars.get('AWS_LAMBDA_LOG_FORMAT', '').lower()
                        ]
                        
                        if any(json_indicators):
                            functions_with_json.append(func_name)
                except:
                    continue
            
            return {
                'total_functions': total_functions,
                'json_logging_count': len(functions_with_json),
                'functions_with_json': functions_with_json
            }
            
        except Exception as e:
            return {'total_functions': 0, 'json_logging_count': 0, 'functions_with_json': []}

    def execute_ecs_task_log_check(self):
        """Custom check for ECS running tasks and their logging configuration"""
        try:
            # Step 1: Get ECS clusters
            clusters_result = self.run_aws_command("aws ecs list-clusters --output json")
            if not clusters_result or 'clusterArns' not in clusters_result:
                return {'running_tasks': [], 'tasks_with_logging': [], 'clusters': [], 'logging_configs': []}
            
            clusters = clusters_result['clusterArns']
            all_running_tasks = []
            tasks_with_logging = []
            logging_configs = []
            
            # Step 2: For each cluster, get running tasks
            for cluster in clusters[:3]:  # Limit to first 3 clusters for performance
                try:
                    tasks_result = self.run_aws_command(f'aws ecs list-tasks --cluster {cluster} --desired-status RUNNING --output json')
                    if tasks_result and 'taskArns' in tasks_result:
                        task_arns = tasks_result['taskArns']
                        all_running_tasks.extend(task_arns)
                        
                        if task_arns:
                            # Step 3: Get task details to find task definition
                            tasks_detail = self.run_aws_command(f'aws ecs describe-tasks --cluster {cluster} --tasks {" ".join(task_arns)} --output json')
                            if tasks_detail and 'tasks' in tasks_detail:
                                for task in tasks_detail['tasks']:
                                    task_def_arn = task.get('taskDefinitionArn', '')
                                    if task_def_arn:
                                        # Step 4: Check task definition for logging configuration
                                        task_def_result = self.run_aws_command(f'aws ecs describe-task-definition --task-definition {task_def_arn} --output json')
                                        if task_def_result and 'taskDefinition' in task_def_result:
                                            task_def = task_def_result['taskDefinition']
                                            task_def_name = task_def.get('family', 'Unknown')
                                            containers = task_def.get('containerDefinitions', [])
                                            
                                            # Check each container's logging configuration
                                            has_logging = False
                                            container_configs = []
                                            for container in containers:
                                                container_name = container.get('name', 'Unknown')
                                                log_config = container.get('logConfiguration', {})
                                                if log_config:
                                                    log_driver = log_config.get('logDriver', 'none')
                                                    log_options = log_config.get('options', {})
                                                    container_configs.append({
                                                        'container': container_name,
                                                        'logDriver': log_driver,
                                                        'options': log_options
                                                    })
                                                    if log_driver in ['awslogs', 'json-file', 'syslog']:
                                                        has_logging = True
                                                else:
                                                    container_configs.append({
                                                        'container': container_name,
                                                        'logDriver': 'none',
                                                        'options': {}
                                                    })
                                            
                                            logging_configs.append({
                                                'taskDefinition': task_def_name,
                                                'taskDefArn': task_def_arn,
                                                'containers': container_configs
                                            })
                                            
                                            if has_logging:
                                                tasks_with_logging.append(task.get('taskArn', ''))
                except:
                    continue  # Skip clusters that fail
            
            return {
                'clusters': clusters,
                'running_tasks': all_running_tasks,
                'tasks_with_logging': tasks_with_logging,
                'logging_configs': logging_configs,
                'total_tasks': len(all_running_tasks),
                'json_logging_count': len(tasks_with_logging)
            }
            
        except Exception as e:
            return {'clusters': [], 'running_tasks': [], 'tasks_with_logging': [], 'logging_configs': [], 'total_tasks': 0, 'json_logging_count': 0}

    def execute_eks_control_plane_logs_check(self):
        """Check if all 5 EKS control plane log types are enabled"""
        try:
            # Get list of EKS clusters
            clusters_result = self.run_aws_command("aws eks list-clusters --output json")
            if not clusters_result or 'clusters' not in clusters_result:
                return {'clusters': [], 'enabled_types': 0, 'total_types': 5}
            
            clusters = clusters_result['clusters']
            required_types = {'api', 'audit', 'authenticator', 'controllerManager', 'scheduler'}
            all_enabled_types = set()
            cluster_configs = []
            
            # Check each cluster's logging configuration
            for cluster_name in clusters[:5]:  # Limit to first 5 clusters
                try:
                    cluster_result = self.run_aws_command(f'aws eks describe-cluster --name {cluster_name} --output json')
                    if cluster_result and 'cluster' in cluster_result:
                        logging_config = cluster_result['cluster'].get('logging', {})
                        cluster_logging = logging_config.get('clusterLogging', [])
                        
                        enabled_types = set()
                        for log_config in cluster_logging:
                            if log_config.get('enabled', False):
                                enabled_types.update(log_config.get('types', []))
                        
                        all_enabled_types.update(enabled_types)
                        cluster_configs.append({
                            'cluster': cluster_name,
                            'enabled_types': list(enabled_types),
                            'all_enabled': enabled_types == required_types
                        })
                except:
                    continue
            
            # Return count of unique enabled types across all clusters
            return {
                'clusters': cluster_configs,
                'enabled_types': len(all_enabled_types),
                'total_types': 5,
                'all_types_enabled': all_enabled_types == required_types
            }
            
        except Exception as e:
            return {'clusters': [], 'enabled_types': 0, 'total_types': 5}

    def execute_field_indexes_per_log_group_check(self):
        """Custom check for field indexes on top 20 largest log groups by size"""
        try:
            # Get all log groups and sort by size
            log_groups_result = self.run_aws_command("aws logs describe-log-groups --output json")
            if not log_groups_result or 'logGroups' not in log_groups_result:
                return {'total_log_groups': 0, 'indexed_log_groups': 0, 'sample_indexed_groups': [], 'field_index_details': []}
            
            all_log_groups = log_groups_result['logGroups']
            
            # Sort by size and get top 20, excluding system-generated log groups
            # Filter out Lambda Insights, Container Insights, and Application Signals log groups
            filtered_groups = []
            for lg in all_log_groups:
                log_group_name = lg.get('logGroupName', '')
                # Skip system-generated log groups
                if (log_group_name.startswith('/aws/lambda-insights') or 
                    log_group_name.startswith('/aws/containerinsights/') or
                    log_group_name.startswith('/aws/application-signals/')):
                    continue
                filtered_groups.append(lg)
            
            sorted_groups = sorted(filtered_groups, key=lambda x: x.get('storedBytes', 0), reverse=True)[:20]
            target_log_groups = [lg.get('logGroupName', '') for lg in sorted_groups]
            
            if not target_log_groups:
                return {'total_log_groups': 0, 'indexed_log_groups': 0, 'sample_indexed_groups': [], 'field_index_details': []}
            
            total_groups = len(target_log_groups)
            indexed_groups = []
            field_index_details = []
            
            # Check each target log group for field indexes
            for log_group_name in target_log_groups:
                try:
                    # Check for field indexes on this log group
                    import shlex
                    escaped_name = shlex.quote(log_group_name)
                    index_result = self.run_aws_command(f'aws logs describe-field-indexes --log-group-identifiers {escaped_name} --output json')
                    if index_result and index_result.get('fieldIndexes'):
                        # Filter out default/system field indexes (those starting with @)
                        custom_indexes = [fi for fi in index_result['fieldIndexes'] if not fi.get('fieldIndexName', '').startswith('@')]
                        
                        if custom_indexes:  # Only count if there are custom field indexes
                            indexed_groups.append(log_group_name)
                            # Collect custom field index names only
                            field_names = [fi.get('fieldIndexName', 'Unknown') for fi in custom_indexes]
                            field_index_details.append({
                                'log_group': log_group_name,
                                'field_names': field_names
                            })
                except:
                    continue  # Skip groups that fail
            
            return {
                'total_log_groups': total_groups,
                'indexed_log_groups': len(indexed_groups),
                'sample_indexed_groups': indexed_groups,
                'field_index_details': field_index_details
            }
            
        except Exception as e:
            return {'total_log_groups': 0, 'indexed_log_groups': 0, 'sample_indexed_groups': [], 'field_index_details': []}

    def execute_log_export_tasks_per_log_group_check(self):
        """Custom check for log export task history across ALL log groups"""
        try:
            # Step 1: Get all log groups
            log_groups_result = self.run_aws_command("aws logs describe-log-groups --output json")
            if not log_groups_result or 'logGroups' not in log_groups_result:
                return {'total_log_groups': 0, 'exported_log_groups': 0, 'sample_exported_groups': []}
            
            log_groups = log_groups_result['logGroups']
            total_groups = len(log_groups)
            exported_groups = []
            
            # Step 2: Get all export tasks (current and historical)
            export_tasks_result = self.run_aws_command("aws logs describe-export-tasks --output json")
            if not export_tasks_result or 'exportTasks' not in export_tasks_result:
                return {'total_log_groups': total_groups, 'exported_log_groups': 0, 'sample_exported_groups': []}
            
            export_tasks = export_tasks_result['exportTasks']
            
            # Step 3: Create set of log groups that have had export tasks
            exported_log_group_names = set()
            for task in export_tasks:
                log_group_name = task.get('logGroupName', '')
                if log_group_name:
                    exported_log_group_names.add(log_group_name)
            
            # Step 4: Check which of our log groups have export history
            for log_group in log_groups:
                log_group_name = log_group.get('logGroupName', '')
                if log_group_name in exported_log_group_names:
                    exported_groups.append(log_group_name)
            
            return {
                'total_log_groups': total_groups,
                'exported_log_groups': len(exported_groups),
                'sample_exported_groups': exported_groups
            }
            
        except Exception as e:
            return {'total_log_groups': 0, 'exported_log_groups': 0, 'sample_exported_groups': []}

    def execute_top_log_groups_retention_check(self):
        """Custom check for retention policies on the top 10 largest log groups"""
        try:
            # Step 1: Get all log groups with their sizes
            log_groups_result = self.run_aws_command("aws logs describe-log-groups --output json")
            if not log_groups_result or 'logGroups' not in log_groups_result:
                return {'top_log_groups': [], 'groups_with_retention': 0, 'total_size_gb': 0}
            
            log_groups = log_groups_result['logGroups']
            
            # Step 2: Sort by storedBytes (largest first) and take top 10
            sorted_groups = sorted(log_groups, key=lambda x: x.get('storedBytes', 0), reverse=True)
            top_10_groups = sorted_groups[:10]
            
            # Step 3: Analyze retention policies for top 10
            groups_with_retention = 0
            total_size_bytes = 0
            top_groups_info = []
            
            for group in top_10_groups:
                name = group.get('logGroupName', 'Unknown')
                size_bytes = group.get('storedBytes', 0)
                retention_days = group.get('retentionInDays')
                
                total_size_bytes += size_bytes
                
                if retention_days is not None:
                    groups_with_retention += 1
                
                top_groups_info.append({
                    'name': name,
                    'size_bytes': size_bytes,
                    'size_mb': round(size_bytes / 1048576, 1),
                    'retention_days': retention_days
                })
            
            total_size_gb = round(total_size_bytes / 1073741824, 1)
            
            # Export to CSV
            self.export_check_to_csv(
                check_name="Log Groups Retention Policies",
                found_count=groups_with_retention,
                total_count=10,
                details={'with_retention': groups_with_retention, 'without_retention': 10 - groups_with_retention}
            )
            
            return {
                'top_log_groups': top_groups_info,
                'groups_with_retention': groups_with_retention,
                'total_size_gb': total_size_gb
            }
            
        except Exception as e:
            return {'top_log_groups': [], 'groups_with_retention': 0, 'total_size_gb': 0}

    def execute_subscription_filters_coverage_check(self):
        """Custom check for subscription filter coverage across top log groups"""
        try:
            # Use the pre-identified largest log groups instead of all log groups
            if not self.largest_log_groups:
                return {'total_log_groups': 0, 'groups_with_subscription_filters': 0, 'sample_filtered_groups': []}
            
            # Flatten the largest log groups from all compute types
            top_log_groups = []
            for compute_type, groups in self.largest_log_groups.items():
                top_log_groups.extend(groups)
            
            total_groups = len(top_log_groups)
            filtered_groups = []
            
            # Check only the top log groups for subscription filters
            for log_group_name in top_log_groups:
                try:
                    # Check for subscription filters on this log group
                    import shlex
                    escaped_name = shlex.quote(log_group_name)
                    filters_result = self.run_aws_command(f'aws logs describe-subscription-filters --log-group-name {escaped_name} --output json')
                    if filters_result and filters_result.get('subscriptionFilters'):
                        filtered_groups.append(log_group_name)
                except Exception as e:
                    continue  # Skip groups that fail
            
            return {
                'total_log_groups': total_groups,
                'groups_with_subscription_filters': len(filtered_groups),
                'sample_filtered_groups': filtered_groups
            }
            
        except Exception as e:
            return {'total_log_groups': 0, 'groups_with_subscription_filters': 0, 'sample_filtered_groups': []}

    def check_centralization_rules_sdk(self):
        """Check for CloudWatch Logs centralization rules using boto3 SDK"""
        try:
            session = boto3.Session(profile_name=self.profile, region_name=self.region)
            client = session.client('observabilityadmin')
            
            # Check all regions for centralization rules
            response = client.list_centralization_rules_for_organization(AllRegions=True)
            return response.get('CentralizationRuleSummaries', [])
        except ClientError as e:
            if e.response['Error']['Code'] == 'UnauthorizedException':
                return None  # Not authorized (expected for non-management accounts)
            return []
        except Exception:
            return []
    def execute_log_centralization_analysis_check(self):
        """Comprehensive check for log centralization patterns"""
        try:
            patterns = []
            account_type = "Standalone"
            org_status = "Not in Organization"
            
            # 1. Check AWS Organizations status (for context only)
            org_result = self.run_aws_command("aws organizations describe-organization --output json")
            if org_result and 'Organization' in org_result:
                org_status = "Organization Management Account"
            else:
                # Check if this is a member account
                try:
                    account_result = self.run_aws_command("aws organizations describe-account --account-id $(aws sts get-caller-identity --query Account --output text) --output json")
                    if account_result:
                        org_status = "Organization Member Account"
                except:
                    pass
            
            # 2. Check for CloudWatch Logs Centralization Rules (native centralization) using CLI
            try:
                centralization_rules = self.run_aws_command("aws observabilityadmin list-centralization-rules-for-organization --all-regions --output json")
                if centralization_rules and centralization_rules.get('CentralizationRuleSummaries'):
                    rules = centralization_rules['CentralizationRuleSummaries']
                    rule_count = len(rules)
                    healthy_rules = len([r for r in rules if r.get('RuleHealth') == 'Healthy'])
                    patterns.append(f"CloudWatch Logs Centralization Rules ({rule_count} rules, {healthy_rules} healthy)")
            except:
                pass
            
            # 3. Check for CloudWatch Observability Access Manager
            try:
                oam_sinks = self.run_aws_command("aws oam list-sinks --output json")
                oam_links = self.run_aws_command("aws oam list-links --output json")
                
                if oam_sinks and oam_sinks.get('Items'):
                    patterns.append("Observability Access Manager Sink (Central Monitoring)")
                
                if oam_links and oam_links.get('Items'):
                    patterns.append("Observability Access Manager Link (Source Account)")
            except:
                pass
            
            # 4. Check for cross-account subscription filters
            try:
                sub_filters = self.run_aws_command("aws logs describe-subscription-filters --output json")
                if sub_filters and sub_filters.get('subscriptionFilters'):
                    cross_account_filters = 0
                    for filter_item in sub_filters['subscriptionFilters']:
                        dest_arn = filter_item.get('destinationArn', '')
                        if ':' in dest_arn and dest_arn.split(':')[4] != self.results.account_id:
                            cross_account_filters += 1
                    
                    if cross_account_filters > 0:
                        patterns.append(f"Cross-account Subscription Filters ({cross_account_filters} filters)")
            except:
                pass
            
            # 5. Check for Kinesis/Firehose destinations
            try:
                kinesis_streams = self.run_aws_command("aws kinesis list-streams --output json")
                if kinesis_streams and kinesis_streams.get('StreamNames'):
                    stream_count = len(kinesis_streams['StreamNames'])
                    patterns.append(f"Kinesis Data Streams ({stream_count} streams)")
                
                firehose_streams = self.run_aws_command("aws firehose list-delivery-streams --output json")
                if firehose_streams and firehose_streams.get('DeliveryStreamNames'):
                    firehose_details = []
                    for stream_name in firehose_streams['DeliveryStreamNames']:
                        stream_desc = self.run_aws_command(f"aws firehose describe-delivery-stream --delivery-stream-name {stream_name} --output json")
                        if stream_desc and stream_desc.get('DeliveryStreamDescription'):
                            desc = stream_desc['DeliveryStreamDescription']
                            destinations = desc.get('Destinations', [])
                            if destinations:
                                dest = destinations[0]
                                if 'S3DestinationDescription' in dest:
                                    bucket_arn = dest['S3DestinationDescription'].get('BucketARN', 'Unknown')
                                    bucket_name = bucket_arn.split(':::')[-1] if ':::' in bucket_arn else bucket_arn
                                    firehose_details.append(f"{stream_name} → S3 bucket {bucket_name} (same account)")
                                elif 'ExtendedS3DestinationDescription' in dest:
                                    bucket_arn = dest['ExtendedS3DestinationDescription'].get('BucketARN', 'Unknown')
                                    bucket_name = bucket_arn.split(':::')[-1] if ':::' in bucket_arn else bucket_arn
                                    firehose_details.append(f"{stream_name} → S3 bucket {bucket_name} (same account)")
                                else:
                                    firehose_details.append(f"{stream_name} → Unknown destination")
                    
                    if firehose_details:
                        patterns.append(f"Kinesis Data Firehose: {', '.join(firehose_details)}")
            except:
                pass
            
            # 6. Check for centralized S3 buckets with log-like naming
            # Removed - keyword-based detection is not reliable
            
            # 7. Check for log destination policies (cross-account)
            try:
                destinations = self.run_aws_command("aws logs describe-destinations --output json")
                if destinations and destinations.get('destinations'):
                    dest_count = len(destinations['destinations'])
                    patterns.append(f"CloudWatch Logs Destinations ({dest_count} destinations)")
            except:
                pass
            
            # Determine account type based on actual configurations
            if not patterns:
                account_type = "No Centralization Detected"
            
            return {
                'centralization_patterns': patterns,
                'account_type': account_type,
                'organization_status': org_status
            }
            
        except Exception as e:
            return {'centralization_patterns': [], 'account_type': 'Unknown', 'organization_status': 'Unknown'}

    def execute_oam_links_and_sinks_check(self):
        """Check both OAM links and sinks to determine account type and centralization setup"""
        try:
            # Check for OAM links (source account perspective)
            links_result = self.run_aws_command("aws oam list-links --output json")
            links = links_result.get('Items', []) if links_result else []
            
            # Check for OAM sinks (monitoring account perspective)  
            sinks_result = self.run_aws_command("aws oam list-sinks --output json")
            sinks = sinks_result.get('Items', []) if sinks_result else []
            
            # Determine account type and configuration
            account_type = "Unknown"
            configuration_details = []
            
            if links and sinks:
                account_type = "Hybrid Account (Both Links and Sinks)"
                configuration_details.append(f"{len(links)} OAM links configured")
                configuration_details.append(f"{len(sinks)} OAM sinks configured")
            elif links and not sinks:
                account_type = "Source Account (Has Links)"
                configuration_details.append(f"{len(links)} OAM links sending data to monitoring accounts")
                # Add link details
                for link in links[:3]:
                    sink_arn = link.get('SinkArn', 'Unknown')
                    link_id = link.get('Id', 'Unknown')
                    configuration_details.append(f"Link {link_id} → {sink_arn}")
            elif sinks and not links:
                account_type = "Monitoring Account (Has Sinks)"
                configuration_details.append(f"{len(sinks)} OAM sinks receiving data from source accounts")
                # Add sink details
                for sink in sinks[:3]:
                    sink_name = sink.get('Name', 'Unknown')
                    sink_arn = sink.get('Arn', 'Unknown')
                    configuration_details.append(f"Sink {sink_name}: {sink_arn}")
            else:
                account_type = "No OAM Configuration"
                configuration_details.append("No OAM links or sinks found")
            
            return {
                'account_type': account_type,
                'links_count': len(links),
                'sinks_count': len(sinks),
                'links': links,
                'sinks': sinks,
                'configuration_details': configuration_details
            }
            
        except Exception as e:
            return {
                'account_type': 'Check Failed',
                'links_count': 0,
                'sinks_count': 0,
                'links': [],
                'sinks': [],
                'configuration_details': [f"Error: {str(e)}"]
            }

    def execute_json_structured_logs_check(self):
        """Check for JSON structured logs by examining field indexes (fast method)"""
        try:
            if not self.largest_log_groups:
                return {'total_groups_checked': 0, 'json_groups': 0, 'sample_groups': []}
            
            # Combine all largest log groups
            all_target_groups = []
            for compute_type, groups in self.largest_log_groups.items():
                all_target_groups.extend(groups)
            
            if not all_target_groups:
                return {'total_groups_checked': 0, 'json_groups': 0, 'sample_groups': []}
            
            json_groups = []
            
            # Check each log group for field indexes (indicates JSON structured logs)
            for group_name in all_target_groups:
                try:
                    import shlex
                    escaped_name = shlex.quote(group_name)
                    # Check if log group has field indexes (indicates structured JSON logs)
                    result = self.run_aws_command(f'aws logs list-log-group-field-indexes --log-group-identifier {escaped_name} --output json')
                    
                    if result and result.get('fieldIndexes'):
                        # Filter out default @timestamp and @message indexes
                        custom_indexes = [idx for idx in result['fieldIndexes'] 
                                        if idx.get('fieldIndexName') not in ['@timestamp', '@message']]
                        if custom_indexes:
                            json_groups.append(group_name)
                            
                except Exception:
                    continue  # Skip groups that fail
            
            return {
                'total_groups_checked': len(all_target_groups),
                'json_groups': len(json_groups),
                'sample_groups': json_groups[:5]  # Show first 5 as examples
            }
            
        except Exception as e:
            return {'total_groups_checked': 0, 'json_groups': 0, 'sample_groups': []}
        """Custom check for field index policies across log groups"""
        try:
            # Step 1: Get all log groups
            log_groups_result = self.run_aws_command("aws logs describe-log-groups --output json")
            if not log_groups_result or 'logGroups' not in log_groups_result:
                return {'total_log_groups': 0, 'indexed_log_groups': 0, 'sample_indexed_groups': []}
            
            log_groups = log_groups_result['logGroups']
            total_groups = len(log_groups)
            indexed_groups = []
            
            # Step 2: Check first 10 log groups for field index policies (to avoid API limits)
            for log_group in log_groups[:10]:
                log_group_name = log_group.get('logGroupName', '')
                try:
                    # Check for field index policies on this log group
                    index_result = self.run_aws_command(f'aws logs describe-index-policies --log-group-identifiers "{log_group_name}" --output json')
                    if index_result and index_result.get('indexPolicies'):
                        indexed_groups.append(log_group_name)
                except:
                    continue  # Skip groups that fail
            
            return {
                'total_log_groups': total_groups,
                'indexed_log_groups': len(indexed_groups),
                'sample_indexed_groups': indexed_groups
            }
            
        except Exception as e:
            return {'total_log_groups': 0, 'indexed_log_groups': 0, 'sample_indexed_groups': []}

    def execute_all_discovery_checks(self):
        """Execute all discovery checks"""
        print(f"🚀 Executing {len(self.results.discovery_checks)} discovery checks...")
        
        for i, check in enumerate(self.results.discovery_checks, 1):
            self.execute_discovery_check(check.id)
        
        successful_checks = len([c for c in self.results.discovery_checks if c.status == "success"])
        print(f"✅ Discovery complete: {successful_checks}/{len(self.results.discovery_checks)} checks successful")

    def setup_assessment_questions(self):
        """Setup all 17 assessment questions with maturity levels"""
        
        # Logs Category (Questions 1-4)
        self.results.assessment_checks.extend([
            ObservabilityCheck(
                question_id=1,
                category="Logs",
                question="How do you collect logs?",
                maturity_descriptions={
                    1: "Basic log groups exist, some services logging",
                    2: "Centralized collection with analytics (Logs Insights queries)",
                    3: "Correlation patterns, anomaly detection models",
                    4: "Automated insights, ML-based analysis"
                }
            ),
            ObservabilityCheck(
                question_id=2,
                category="Logs",
                question="How do you use logs?",
                maturity_descriptions={
                    1: "Manual log searches and basic queries",
                    2: "Structured queries with faster analysis",
                    3: "Automated correlation and anomaly detection",
                    4: "Automated resolution and MTTR reduction"
                }
            ),
            ObservabilityCheck(
                question_id=3,
                category="Logs",
                question="How do you access logs?",
                maturity_descriptions={
                    1: "Basic centralized collection",
                    2: "Enterprise-wide visibility with prioritization",
                    3: "Single pane correlation and anomaly detection",
                    4: "Automated insights with proactive root cause"
                }
            ),
            ObservabilityCheck(
                question_id=4,
                category="Logs",
                question="What is your log retention policy?",
                maturity_descriptions={
                    1: "Disparate retention policies",
                    2: "Enterprise-wide compliance-based policies",
                    3: "Automated archival with cost optimization",
                    4: "Easy retrieval with metadata-based search"
                }
            )
        ])
        
        # Metrics Category (Questions 5-7)
        self.results.assessment_checks.extend([
            ObservabilityCheck(
                question_id=5,
                category="Metrics",
                question="What type of metrics do you collect?",
                maturity_descriptions={
                    1: "Infrastructure metrics only (cpu, memory, disk utilization)",
                    2: "Infrastructure and application metrics (latency, errors, volume)",
                    3: "Infrastructure, application, and custom metrics",
                    4: "All metrics with dimensions for critical metadata"
                }
            ),
            ObservabilityCheck(
                question_id=6,
                category="Metrics",
                question="How do you use metrics?",
                maturity_descriptions={
                    1: "Manually explore metrics when diagnosing issues",
                    2: "Dashboards and alerting for manual reaction",
                    3: "Infrastructure automation and operational reviews",
                    4: "AI/ML capabilities for proactive issue identification"
                }
            ),
            ObservabilityCheck(
                question_id=7,
                category="Metrics",
                question="How do you access metrics?",
                maturity_descriptions={
                    1: "Centralized metric collection mechanism",
                    2: "Enterprise-wide visibility for analysis and troubleshooting",
                    3: "Correlation and anomaly detection for root cause",
                    4: "Automated insights with proactive resolution options"
                }
            )
        ])
        
        # Traces Category (Questions 8-9)
        self.results.assessment_checks.extend([
            ObservabilityCheck(
                question_id=8,
                category="Traces",
                question="How do you collect traces?",
                maturity_descriptions={
                    1: "Auto-instrumented SDKs for monitoring",
                    2: "Auto + manual instrumentation",
                    3: "End-to-end visibility with correlation",
                    4: "Automatic injection with proactive alerts"
                }
            ),
            ObservabilityCheck(
                question_id=9,
                category="Traces",
                question="How do you use traces?",
                maturity_descriptions={
                    1: "Centralized trace collection mechanism",
                    2: "Analyze and troubleshoot issues based on captured information",
                    3: "360 view for correlation and anomaly detection",
                    4: "Cross-boundary insights with proactive root cause identification"
                }
            )
        ])
        
        # Dashboards & Alerting Category (Questions 10-12)
        self.results.assessment_checks.extend([
            ObservabilityCheck(
                question_id=10,
                category="Dashboards & Alerting",
                question="How do you use alarms?",
                maturity_descriptions={
                    1: "Alarms with notifications when metrics meet triggers",
                    2: "Clear priority for alerts with urgency and customer impact",
                    3: "Actionable alarms based on anomaly detection",
                    4: "Composite alarms for aggregated health indicators"
                }
            ),
            ObservabilityCheck(
                question_id=11,
                category="Dashboards & Alerting",
                question="How do you use dashboards?",
                maturity_descriptions={
                    1: "Basic resource monitoring",
                    2: "Single pane of glass with visibility into various data sources",
                    3: "Flexible dashboards with dynamic content based on input fields",
                    4: "Automatically created dynamic visualizations relevant to issues"
                }
            ),
            ObservabilityCheck(
                question_id=12,
                category="Dashboards & Alerting",
                question="How adaptive are your alarm thresholds?",
                maturity_descriptions={
                    1: "Alarms triggered immediately when metric exceeds static threshold",
                    2: "Alarms triggered when metric exceeds threshold for a period of time",
                    3: "Alarms triggered when metric exhibits anomalous behavior",
                    4: "Continuously analyze metrics, determine baselines, surface anomalies"
                }
            )
        ])
        
        # Organization Category (Questions 13-17)
        self.results.assessment_checks.extend([
            ObservabilityCheck(
                question_id=13,
                category="Organization",
                question="Do you have an enterprise observability strategy?",
                maturity_descriptions={
                    1: "Data collection strategy only",
                    2: "Unified tools and technologies",
                    3: "Best practices and training",
                    4: "Culture of continuous improvement"
                }
            ),
            ObservabilityCheck(
                question_id=14,
                category="Organization",
                question="How do you use SLOs?",
                maturity_descriptions={
                    1: "Team experimentation without adoption",
                    2: "Enterprise adoption for reliability",
                    3: "Prioritization for users and business",
                    4: "Integrated platforms with error budgets"
                }
            ),
            ObservabilityCheck(
                question_id=15,
                category="Organization",
                question="Are you getting ROI from your observability tools?",
                maturity_descriptions={
                    1: "Want optimization without knowledge",
                    2: "Vendor consolidation attempts",
                    3: "Established validation policies",
                    4: "Business value and cost optimization"
                }
            ),
            ObservabilityCheck(
                question_id=16,
                category="Organization",
                question="Do you use any AI/ML capability today?",
                maturity_descriptions={
                    1: "No AI/ML features",
                    2: "Natural language query capability",
                    3: "Automatic correlation and patterns",
                    4: "Comprehensive AI/ML with real-time insights"
                }
            ),
            ObservabilityCheck(
                question_id=17,
                category="Organization",
                question="Do you have real end-user monitoring?",
                maturity_descriptions={
                    1: "Test users for validation",
                    2: "Synthetic scripts on schedule",
                    3: "Scripted interaction tests with correlation",
                    4: "Real user monitoring with proactive anomalies"
                }
            )
        ])
        
        print("📋 Assessment questions configured")

    def assess_all_categories(self):
        """Assess maturity for all categories based on discovery checks"""
        self.assess_logs_maturity()
        self.assess_metrics_maturity()
        self.assess_traces_maturity()
        self.assess_dashboards_alarms_maturity()
        self.assess_organization_maturity()

    def assess_logs_maturity(self):
        """Assess logs maturity based on discovery checks"""
        log_checks = [c for c in self.results.assessment_checks if c.category == "Logs"]
        
        for check in log_checks:
            if check.question_id == 1:  # How do you collect logs?
                # Discovery checks for log collection
                log_groups_check = next((c for c in self.results.discovery_checks if c.name == "What percentage of your log groups are categorized by source type (AWS Service Vended Logs, Custom Logs)"), None)
                ec2_agent_check = next((c for c in self.results.discovery_checks if c.name == "What percentage of EC2 instances have CloudWatch Agent installed with both system metrics AND application logs configured?"), None)
                lambda_logs_check = next((c for c in self.results.discovery_checks if c.name == "What percentage of Lambda functions use JSON structured logging?"), None)
                ecs_logs_check = next((c for c in self.results.discovery_checks if c.name == "What percentage of ECS tasks use structured logging (JSON)?"), None)
                eks_logs_check = next((c for c in self.results.discovery_checks if c.name == "Are all five EKS control plane log types enabled (api, audit, authenticator, controllerManager, scheduler)?"), None)
                eks_addon_check = next((c for c in self.results.discovery_checks if c.name == "Is the EKS CloudWatch Observability add-on deployed with Container Insights and Application Signals enabled?" and c.category == "Logs"), None)
                structured_json_check = next((c for c in self.results.discovery_checks if c.name == "What percentage of application logs use structured JSON format for easier parsing and analysis?"), None)
                centralization_check = next((c for c in self.results.discovery_checks if c.name == "Have you implemented Cross-Account and Cross-Region Log Centralization?"), None)
                oam_check = next((c for c in self.results.discovery_checks if c.name == "Are you using CloudWatch cross-account observability?"), None)
                anomaly_detection_check = next((c for c in self.results.discovery_checks if c.name == "Have you enabled anomaly detection?"), None)

                check.evidence_check_ids = [c.id for c in [log_groups_check, ec2_agent_check, lambda_logs_check, ecs_logs_check, eks_logs_check, eks_addon_check, structured_json_check, centralization_check, oam_check, anomaly_detection_check] if c]

                # Determine which compute types are in use based on largest log groups
                compute_in_use = {k: v for k, v in self.largest_log_groups.items() if v}
                compute_with_logging = {}

                if 'EC2' in compute_in_use and ec2_agent_check and ec2_agent_check.status == 'success':
                    compute_with_logging['EC2'] = "CloudWatch Agent configured"
                if 'Lambda' in compute_in_use and lambda_logs_check and lambda_logs_check.status == 'success':
                    compute_with_logging['Lambda'] = "JSON structured logging"
                if 'ECS' in compute_in_use and ecs_logs_check and ecs_logs_check.status == 'success':
                    compute_with_logging['ECS'] = "task logging configured"
                if 'EKS' in compute_in_use and eks_logs_check and eks_logs_check.status == 'success':
                    compute_with_logging['EKS'] = "control plane logs enabled"

                # Coverage ratio of compute types that have logging vs compute types in use
                coverage = len(compute_with_logging) / len(compute_in_use) if compute_in_use else 0

                # Check higher-level signals
                has_structured_json = (structured_json_check and isinstance(structured_json_check.result, dict) and structured_json_check.result.get('json_groups', 0) > 0) or \
                    (lambda_logs_check and isinstance(lambda_logs_check.result, dict) and lambda_logs_check.result.get('json_logging_count', 0) > 0) or \
                    (ecs_logs_check and isinstance(ecs_logs_check.result, dict) and ecs_logs_check.result.get('json_logging_count', 0) > 0)
                has_centralization = (centralization_check and centralization_check.status == 'success') or (oam_check and isinstance(oam_check.result, dict) and (oam_check.result.get('links_count', 0) > 0 or oam_check.result.get('sinks_count', 0) > 0))
                has_eks_addon = eks_addon_check and isinstance(eks_addon_check.result, dict) and eks_addon_check.result.get('observability_clusters', 0) > 0
                has_anomaly_detection = anomaly_detection_check and anomaly_detection_check.status == 'success'
                has_log_groups = log_groups_check and log_groups_check.result and log_groups_check.result.get('logGroups')

                evidence_refs = f"(Checks #{', #'.join(str(id) for id in check.evidence_check_ids)})"
                compute_summary = ', '.join(f"{k}: {v}" for k, v in compute_with_logging.items())
                in_use_summary = ', '.join(compute_in_use.keys())

                # L4: Automated collection with ML-based analysis
                if coverage >= 0.75 and has_structured_json and has_centralization and (has_eks_addon or has_anomaly_detection):
                    check.current_level = 4
                    extras = []
                    if has_eks_addon: extras.append("EKS Observability add-on for auto-instrumented collection")
                    if has_anomaly_detection: extras.append("log anomaly detection")
                    check.explanation = f"Automated log collection with ML-based analysis. Compute coverage: {compute_summary}. Additional: {', '.join(extras)}. Structured JSON logging and centralization in place {evidence_refs}."
                # L3: Correlation patterns via centralization + structured logs
                elif coverage >= 0.75 and has_structured_json and has_centralization:
                    check.current_level = 3
                    check.explanation = f"Centralized log collection with correlation patterns. Compute coverage: {compute_summary}. Structured JSON logging enables correlation across services. Cross-account/region centralization provides unified view {evidence_refs}."
                # L2: Good coverage of in-use compute types with structured logging
                elif coverage >= 0.5 and (has_structured_json or len(compute_with_logging) >= 2):
                    check.current_level = 2
                    check.explanation = f"Centralized collection with analytics across compute types in use ({in_use_summary}). Logging configured for: {compute_summary} {evidence_refs}."
                # L1: Some logging exists
                elif has_log_groups or compute_with_logging:
                    check.current_level = 1
                    if compute_with_logging:
                        check.explanation = f"Basic log collection. Compute types in use: {in_use_summary}. Logging configured for: {compute_summary}. Coverage gap needs attention {evidence_refs}."
                    else:
                        check.explanation = f"Basic log groups exist but compute-specific log collection not fully configured for in-use types ({in_use_summary}) {evidence_refs}."
                else:
                    check.current_level = 1
                    check.explanation = f"Minimal log collection detected {evidence_refs}."
            
            elif check.question_id == 2:  # How do you use logs?
                # Discovery checks for log usage
                query_definitions_check = next((c for c in self.results.discovery_checks if c.name == "Do you have standardized Log Insights queries for common troubleshooting scenarios (errors, latency, security events)?"), None)
                metric_filters_check = next((c for c in self.results.discovery_checks if c.name == "Have you created metric filters to extract KPIs from logs?"), None)
                anomaly_detection_check = next((c for c in self.results.discovery_checks if c.name == "Have you enabled anomaly detection?"), None)
                structured_json_check = next((c for c in self.results.discovery_checks if c.name == "What percentage of application logs use structured JSON format for easier parsing and analysis?"), None)
                field_indexes_check = next((c for c in self.results.discovery_checks if c.name == "Do you have field index policies configured for faster log queries?"), None)
                devops_agent_check = next((c for c in self.results.discovery_checks if c.name == "Do you use AWS DevOps Agent for AI-assisted troubleshooting?"), None)
                lambda_json_check = next((c for c in self.results.discovery_checks if c.name == "What percentage of Lambda functions use JSON structured logging?"), None)
                ecs_json_check = next((c for c in self.results.discovery_checks if c.name == "What percentage of ECS tasks use structured logging (JSON)?"), None)

                check.evidence_check_ids = [c.id for c in [query_definitions_check, metric_filters_check, anomaly_detection_check, structured_json_check, field_indexes_check, devops_agent_check, lambda_json_check, ecs_json_check] if c]

                has_saved_queries = query_definitions_check and query_definitions_check.result and query_definitions_check.result.get('queryDefinitions')
                has_metric_filters = metric_filters_check and metric_filters_check.result and metric_filters_check.result.get('metricFilters')
                has_anomaly_detection = anomaly_detection_check and anomaly_detection_check.status == 'success'
                has_structured_json = (structured_json_check and isinstance(structured_json_check.result, dict) and structured_json_check.result.get('json_groups', 0) > 0) or \
                    (lambda_json_check and isinstance(lambda_json_check.result, dict) and lambda_json_check.result.get('json_logging_count', 0) > 0) or \
                    (ecs_json_check and isinstance(ecs_json_check.result, dict) and ecs_json_check.result.get('json_logging_count', 0) > 0)
                has_field_indexes = field_indexes_check and isinstance(field_indexes_check.result, dict) and field_indexes_check.result.get('indexed_log_groups', 0) > 0
                has_devops_agent = devops_agent_check and isinstance(devops_agent_check.result, dict) and devops_agent_check.result.get('total_spaces', 0) > 0

                evidence_refs = f"(Checks #{', #'.join(str(id) for id in check.evidence_check_ids)})"
                capabilities = []
                if has_saved_queries:
                    q_count = len(query_definitions_check.result['queryDefinitions'])
                    capabilities.append(f"{q_count} saved Logs Insights queries")
                if has_metric_filters:
                    mf_count = len(metric_filters_check.result['metricFilters'])
                    capabilities.append(f"{mf_count} metric filters")
                if has_anomaly_detection: capabilities.append("log anomaly detection")
                if has_structured_json: capabilities.append("structured JSON logging")
                if has_field_indexes: capabilities.append("field index policies")
                if has_devops_agent: capabilities.append("DevOps Agent for AI-assisted troubleshooting")

                # L4: Automated resolution — anomaly detection + metric filters (logs→metrics→alarms) + AI resolution
                if has_anomaly_detection and has_metric_filters and has_devops_agent:
                    check.current_level = 4
                    check.explanation = f"Automated resolution and MTTR reduction with {', '.join(capabilities)}. Logs drive automated alerting via metric filters, anomaly detection identifies issues proactively, and DevOps Agent enables AI-assisted resolution {evidence_refs}."
                # L3: Automated correlation and anomaly detection
                elif has_anomaly_detection and (has_metric_filters or has_saved_queries):
                    check.current_level = 3
                    check.explanation = f"Automated correlation and anomaly detection with {', '.join(capabilities)}. Anomaly detection proactively identifies issues while structured analysis capabilities enable faster root cause identification {evidence_refs}."
                # L2: Structured queries with faster analysis
                elif has_saved_queries or has_metric_filters or (has_structured_json and has_field_indexes):
                    check.current_level = 2
                    check.explanation = f"Structured queries with faster analysis using {', '.join(capabilities)}. Repeatable analysis patterns and log-derived metrics enable faster troubleshooting beyond manual searches {evidence_refs}."
                # L1: Manual log searches
                else:
                    check.current_level = 1
                    if capabilities:
                        check.explanation = f"Basic log usage with {', '.join(capabilities)}. Limited structured analysis — primarily manual log searches for troubleshooting {evidence_refs}."
                    else:
                        check.explanation = f"Log usage limited to manual searches and basic queries. No saved queries, metric filters, or anomaly detection detected {evidence_refs}."
            
            elif check.question_id == 3:  # How do you access logs?
                # Discovery checks for log access
                log_groups_check = next((c for c in self.results.discovery_checks if c.name == "What percentage of your log groups are categorized by source type (AWS Service Vended Logs, Custom Logs)"), None)
                dashboards_check = next((c for c in self.results.discovery_checks if c.name == "Do you have CloudWatch dashboards for visualizing metrics and logs?" and "Logs" in c.category), None)
                subscription_filters_check = next((c for c in self.results.discovery_checks if c.name == "What percentage of log groups have subscription filters for real-time processing?"), None)
                centralization_check = next((c for c in self.results.discovery_checks if c.name == "Have you implemented Cross-Account and Cross-Region Log Centralization?"), None)
                oam_check = next((c for c in self.results.discovery_checks if c.name == "Are you using CloudWatch cross-account observability?"), None)
                anomaly_detection_check = next((c for c in self.results.discovery_checks if c.name == "Have you enabled anomaly detection?"), None)
                devops_agent_check = next((c for c in self.results.discovery_checks if c.name == "Do you use AWS DevOps Agent for AI-assisted troubleshooting?"), None)
                investigations_check = next((c for c in self.results.discovery_checks if c.name == "Have you configured CloudWatch Investigations action for any alarms?"), None)

                check.evidence_check_ids = [c.id for c in [log_groups_check, dashboards_check, subscription_filters_check, centralization_check, oam_check, anomaly_detection_check, devops_agent_check, investigations_check] if c]

                has_log_groups = log_groups_check and log_groups_check.result and log_groups_check.result.get('logGroups')
                has_dashboards = dashboards_check and dashboards_check.result and dashboards_check.result.get('DashboardEntries')
                has_subscription_filters = subscription_filters_check and subscription_filters_check.result and subscription_filters_check.result.get('groups_with_subscription_filters', 0) > 0
                has_centralization = centralization_check and centralization_check.status == 'success'
                has_oam = oam_check and isinstance(oam_check.result, dict) and (oam_check.result.get('links_count', 0) > 0 or oam_check.result.get('sinks_count', 0) > 0)
                has_anomaly_detection = anomaly_detection_check and anomaly_detection_check.status == 'success'
                has_devops_agent = devops_agent_check and isinstance(devops_agent_check.result, dict) and devops_agent_check.result.get('total_spaces', 0) > 0
                has_investigations = investigations_check and isinstance(investigations_check.result, dict) and investigations_check.result.get('alarms_with_investigations', 0) > 0
                has_enterprise_access = has_centralization or has_oam or has_subscription_filters

                evidence_refs = f"(Checks #{', #'.join(str(id) for id in check.evidence_check_ids)})"
                capabilities = []
                if has_dashboards: capabilities.append(f"{len(dashboards_check.result['DashboardEntries'])} dashboards")
                if has_centralization: capabilities.append("cross-account/region log centralization")
                if has_oam: capabilities.append("CloudWatch cross-account observability (OAM)")
                if has_subscription_filters:
                    sf_count = subscription_filters_check.result.get('groups_with_subscription_filters', 0)
                    capabilities.append(f"{sf_count} log groups with subscription filters")
                if has_anomaly_detection: capabilities.append("log anomaly detection")
                if has_devops_agent: capabilities.append("DevOps Agent")
                if has_investigations: capabilities.append("CloudWatch Investigations")

                # L4: Automated insights with proactive root cause
                if has_enterprise_access and has_anomaly_detection and (has_devops_agent or has_investigations):
                    check.current_level = 4
                    check.explanation = f"Automated insights with proactive root cause identification via {', '.join(capabilities)}. Enterprise-wide log access with anomaly detection and AI-assisted root cause analysis {evidence_refs}."
                # L3: Single pane correlation and anomaly detection
                elif has_enterprise_access and has_anomaly_detection:
                    check.current_level = 3
                    check.explanation = f"Single pane correlation and anomaly detection with {', '.join(capabilities)}. Centralized access combined with anomaly detection enables immediate root cause determination {evidence_refs}."
                # L2: Enterprise-wide visibility
                elif has_dashboards and has_enterprise_access:
                    check.current_level = 2
                    check.explanation = f"Enterprise-wide visibility with {', '.join(capabilities)}. Relevant teams can analyze and troubleshoot based on captured information with centralized access patterns {evidence_refs}."
                # L1: Basic centralized collection
                elif has_log_groups:
                    check.current_level = 1
                    if capabilities:
                        check.explanation = f"Basic centralized log access with {', '.join(capabilities)}. Foundation for enterprise visibility but lacks unified cross-account access or correlation capabilities {evidence_refs}."
                    else:
                        check.explanation = f"Basic centralized collection — log groups exist but no dashboards, centralization, or cross-account access detected {evidence_refs}."
                else:
                    check.current_level = 1
                    check.explanation = f"Minimal log access detected. No centralized collection or access mechanisms found {evidence_refs}."
            
            elif check.question_id == 4:  # What is your log retention policy?
                # Discovery checks for log retention
                top_groups_retention_check = next((c for c in self.results.discovery_checks if c.name == "What percentage of log groups have retention policies aligned with your compliance requirements (security: 90+ days, operational: 30 days, debug: 7 days)?"), None)
                export_tasks_check = next((c for c in self.results.discovery_checks if c.name == "Do you have log export tasks configured for archival?"), None)
                subscription_filters_check = next((c for c in self.results.discovery_checks if c.name == "What percentage of log groups have subscription filters for real-time processing?"), None)
                centralization_check = next((c for c in self.results.discovery_checks if c.name == "Have you implemented Cross-Account and Cross-Region Log Centralization?"), None)
                tags_check = next((c for c in self.results.discovery_checks if c.name == "Do your log groups have resource tags for retention governance and metadata-based search?"), None)

                check.evidence_check_ids = [c.id for c in [top_groups_retention_check, export_tasks_check, subscription_filters_check, centralization_check, tags_check] if c]

                # Analyze retention coverage from top 10 largest log groups
                retention_ratio = 0.0
                total_groups_checked = 0
                groups_with_retention = 0
                if top_groups_retention_check and top_groups_retention_check.result:
                    groups_with_retention = top_groups_retention_check.result.get('groups_with_retention', 0)
                    total_groups_checked = len(top_groups_retention_check.result.get('top_log_groups', []))
                    if total_groups_checked > 0:
                        retention_ratio = groups_with_retention / total_groups_checked

                has_export_tasks = export_tasks_check and isinstance(export_tasks_check.result, dict) and export_tasks_check.result.get('exported_log_groups', 0) > 0
                has_subscription_archival = subscription_filters_check and isinstance(subscription_filters_check.result, dict) and subscription_filters_check.result.get('groups_with_subscription_filters', 0) > 0
                has_centralization = centralization_check and centralization_check.status == 'success'
                has_archival = has_export_tasks or has_subscription_archival or has_centralization
                has_log_group_tags = tags_check and isinstance(tags_check.result, dict) and tags_check.result.get('total_tagged_log_groups', 0) > 0

                evidence_refs = f"(Checks #{', #'.join(str(id) for id in check.evidence_check_ids)})"
                capabilities = []
                if total_groups_checked > 0:
                    capabilities.append(f"retention policies on {groups_with_retention}/{total_groups_checked} largest log groups ({retention_ratio:.0%} coverage)")
                if has_export_tasks:
                    capabilities.append(f"export tasks on {export_tasks_check.result.get('exported_log_groups', 0)} log groups")
                if has_subscription_archival:
                    capabilities.append(f"subscription filters on {subscription_filters_check.result.get('groups_with_subscription_filters', 0)} log groups for streaming/archival")
                if has_centralization: capabilities.append("cross-account/region log centralization")
                if has_log_group_tags: capabilities.append(f"log group tagging ({tags_check.result.get('total_tagged_log_groups', 0)} tagged log groups)")

                # L4: Easy retrieval with metadata-based search (high retention coverage + archival + tagging)
                if retention_ratio >= 0.75 and has_archival and has_log_group_tags:
                    check.current_level = 4
                    check.explanation = f"Comprehensive retention strategy with {', '.join(capabilities)}. High retention coverage combined with archival pipelines and resource tagging enables metadata-based search and easy retrieval {evidence_refs}."
                # L3: Automated archival with cost optimization (good retention + archival)
                elif retention_ratio >= 0.50 and has_archival:
                    check.current_level = 3
                    check.explanation = f"Automated archival with cost optimization via {', '.join(capabilities)}. Retention policies combined with archival mechanisms (export/subscription/centralization) provide tiered storage for cost optimization {evidence_refs}."
                # L2: Enterprise-wide compliance-based policies (retention policies on majority of groups)
                elif retention_ratio >= 0.50:
                    check.current_level = 2
                    check.explanation = f"Enterprise-wide retention policies with {', '.join(capabilities)}. Consistent retention settings across major log groups indicate compliance-based lifecycle management {evidence_refs}."
                # L1: Disparate retention policies
                elif groups_with_retention > 0:
                    check.current_level = 1
                    check.explanation = f"Partial retention coverage with {', '.join(capabilities)}. Some log groups have retention policies but coverage is below 50%, indicating disparate department-level policies {evidence_refs}."
                else:
                    check.current_level = 1
                    check.explanation = f"No retention policies detected on largest log groups. Logs may be using default 'Never expire' settings, leading to uncontrolled storage costs {evidence_refs}."

    def assess_metrics_maturity(self):
        """Assess metrics maturity based on discovery checks"""
        metrics_checks = [c for c in self.results.assessment_checks if c.category == "Metrics"]
        
        for check in metrics_checks:
            if check.question_id == 5:  # What type of metrics do you collect?
                # Discovery checks for metrics collection
                custom_metrics_check = next((c for c in self.results.discovery_checks if c.name == "Are you publishing custom business and application metrics to CloudWatch?"), None)
                ec2_detailed_check = next((c for c in self.results.discovery_checks if c.name == "What percentage of production EC2 instances have detailed monitoring (1-minute metrics) enabled?"), None)
                ecs_monitoring_check = next((c for c in self.results.discovery_checks if c.name == "What percentage of ECS Clusters have monitoring enabled?"), None)
                ecs_insights_check = next((c for c in self.results.discovery_checks if c.name == "Do you have ECS clusters with Container Insights enabled?"), None)
                eks_addon_check = next((c for c in self.results.discovery_checks if c.name == "Do you have EKS clusters with CloudWatch Observability add-on enabled?"), None)
                lambda_insights_check = next((c for c in self.results.discovery_checks if c.name == "What percentage of Lambda functions have Lambda Insights enabled for enhanced metrics?"), None)
                cwagent_check = next((c for c in self.results.discovery_checks if c.name == "Are CloudWatch Agents configured to collect system-level metrics?"), None)
                app_signals_check = next((c for c in self.results.discovery_checks if c.name == "Do you use AWS Application Signals to monitor application services?"), None)

                check.evidence_check_ids = [c.id for c in [custom_metrics_check, ec2_detailed_check, ecs_monitoring_check, ecs_insights_check, eks_addon_check, lambda_insights_check, cwagent_check, app_signals_check] if c]

                # Determine which compute types are in use
                active_compute = set(self.largest_log_groups.keys()) if self.largest_log_groups else set()

                # Check infrastructure metrics (enhanced monitoring per compute type)
                infra_signals = []
                if 'EC2' in active_compute:
                    if ec2_detailed_check and ec2_detailed_check.result and isinstance(ec2_detailed_check.result, list) and len(ec2_detailed_check.result) > 0:
                        infra_signals.append("EC2 detailed monitoring")
                    if cwagent_check and cwagent_check.result and isinstance(cwagent_check.result, dict) and cwagent_check.result.get('Metrics'):
                        infra_signals.append("CloudWatch Agent metrics")
                if 'ECS' in active_compute:
                    if ecs_insights_check and ecs_insights_check.result and isinstance(ecs_insights_check.result, dict):
                        clusters = ecs_insights_check.result.get('clusters', [])
                        if any(s.get('value') == 'enabled' for c in clusters for s in c.get('settings', []) if s.get('name') == 'containerInsights'):
                            infra_signals.append("ECS Container Insights")
                if 'EKS' in active_compute and eks_addon_check and eks_addon_check.result and isinstance(eks_addon_check.result, dict) and eks_addon_check.result.get('clusters_with_addon', 0) > 0:
                    infra_signals.append("EKS CloudWatch Observability add-on")
                if 'Lambda' in active_compute and lambda_insights_check and isinstance(lambda_insights_check.result, dict) and lambda_insights_check.result.get('insights_functions', 0) > 0:
                    infra_signals.append("Lambda Insights")

                has_custom = custom_metrics_check and isinstance(custom_metrics_check.result, dict) and custom_metrics_check.result.get('total_custom_metrics', 0) > 0
                has_app_signals = app_signals_check and isinstance(app_signals_check.result, dict) and app_signals_check.result.get('Services')

                evidence_refs = f"(Checks #{', #'.join(str(id) for id in check.evidence_check_ids)})"
                capabilities = list(infra_signals)
                if has_custom:
                    capabilities.append(f"{custom_metrics_check.result.get('total_custom_metrics', 0)} custom metrics in {', '.join(custom_metrics_check.result.get('custom_namespaces', []))}")
                if has_app_signals:
                    capabilities.append(f"Application Signals ({len(app_signals_check.result['Services'])} services)")

                # L4: Infrastructure + application + custom + dimensions/app signals
                if has_custom and has_app_signals and infra_signals:
                    check.current_level = 4
                    check.explanation = f"Comprehensive metrics with {', '.join(capabilities)}. Infrastructure, application, and custom metrics with Application Signals providing dimensional metadata for diagnosing issues {evidence_refs}."
                # L3: Infrastructure + application + custom metrics
                elif has_custom and infra_signals:
                    check.current_level = 3
                    check.explanation = f"Infrastructure, application, and custom metrics with {', '.join(capabilities)} {evidence_refs}."
                # L2: Infrastructure + application metrics (enhanced monitoring)
                elif infra_signals:
                    check.current_level = 2
                    check.explanation = f"Infrastructure and application metrics via {', '.join(capabilities)} {evidence_refs}."
                # L1: Basic infrastructure metrics only
                else:
                    check.current_level = 1
                    check.explanation = f"Basic infrastructure metrics only. No enhanced monitoring, custom metrics, or application-level metrics detected {evidence_refs}."
            
            elif check.question_id == 6:  # How do you use metrics?
                # Discovery checks for metrics usage
                dashboards_check = next((c for c in self.results.discovery_checks if c.name == "Do you have CloudWatch dashboards for visualizing metrics and logs?" and "Metrics" in c.category), None)
                alarms_check = next((c for c in self.results.discovery_checks if c.name == "Do you have CloudWatch alarms configured for your resources?"), None)
                anomaly_check = next((c for c in self.results.discovery_checks if c.name == "Do you use anomaly detection models for adaptive alarming?"), None)
                devops_agent_check = next((c for c in self.results.discovery_checks if c.name == "Do you use AWS DevOps Agent for AI-assisted troubleshooting?"), None)

                check.evidence_check_ids = [c.id for c in [dashboards_check, alarms_check, anomaly_check, devops_agent_check] if c]

                has_dashboards = dashboards_check and isinstance(dashboards_check.result, dict) and dashboards_check.result.get('DashboardEntries')
                has_alarms = alarms_check and isinstance(alarms_check.result, dict) and (alarms_check.result.get('MetricAlarms') or alarms_check.result.get('CompositeAlarms'))
                has_anomaly = anomaly_check and isinstance(anomaly_check.result, dict) and anomaly_check.result.get('total_bands', 0) > 0
                has_devops_agent = devops_agent_check and isinstance(devops_agent_check.result, dict) and devops_agent_check.result.get('total_spaces', 0) > 0

                evidence_refs = f"(Checks #{', #'.join(str(id) for id in check.evidence_check_ids)})"
                capabilities = []
                if has_dashboards: capabilities.append(f"{len(dashboards_check.result['DashboardEntries'])} dashboards")
                if has_alarms:
                    alarm_count = len(alarms_check.result.get('MetricAlarms', [])) + len(alarms_check.result.get('CompositeAlarms', []))
                    capabilities.append(f"{alarm_count} alarms")
                if has_anomaly: capabilities.append(f"{anomaly_check.result.get('total_bands', 0)} anomaly detectors")
                if has_devops_agent: capabilities.append("DevOps Agent")

                # L4: AI/ML capabilities (anomaly detection + DevOps Agent)
                if has_anomaly and has_devops_agent:
                    check.current_level = 4
                    check.explanation = f"AI/ML-driven metrics usage with {', '.join(capabilities)}. Proactive issue identification via anomaly detection and AI-assisted troubleshooting {evidence_refs}."
                # L3: Automation and anomaly detection
                elif has_anomaly and has_alarms:
                    check.current_level = 3
                    check.explanation = f"Automated metrics usage with {', '.join(capabilities)}. Anomaly detection drives corrective action with high signal-to-noise ratio {evidence_refs}."
                # L2: Dashboards + alarms for operational visibility
                elif has_dashboards and has_alarms:
                    check.current_level = 2
                    check.explanation = f"Operational visibility with {', '.join(capabilities)}. Dashboards and alarms enable manual reaction to issues {evidence_refs}."
                # L1: Manual exploration
                else:
                    check.current_level = 1
                    check.explanation = f"Manual metrics exploration. {'Found ' + ', '.join(capabilities) + ' but' if capabilities else 'No dashboards or alarms detected —'} limited systematic usage {evidence_refs}."
            
            elif check.question_id == 7:  # How do you access metrics?
                # Discovery checks for metrics access
                streams_check = next((c for c in self.results.discovery_checks if c.name == "Have you configured metric streams for real-time export to third-party tools or data lakes?"), None)
                oam_check = next((c for c in self.results.discovery_checks if c.name == "Are you using CloudWatch cross-account observability?"), None)
                dashboards_check = next((c for c in self.results.discovery_checks if c.name == "Do you have CloudWatch dashboards for visualizing metrics and logs?" and "Metrics" in c.category), None)
                anomaly_check = next((c for c in self.results.discovery_checks if c.name == "Do you use anomaly detection models for adaptive alarming?"), None)
                devops_agent_check = next((c for c in self.results.discovery_checks if c.name == "Do you use AWS DevOps Agent for AI-assisted troubleshooting?"), None)

                check.evidence_check_ids = [c.id for c in [streams_check, oam_check, dashboards_check, anomaly_check, devops_agent_check] if c]

                has_streams = streams_check and isinstance(streams_check.result, dict) and streams_check.result.get('Entries')
                has_oam = oam_check and isinstance(oam_check.result, dict) and (oam_check.result.get('links_count', 0) > 0 or oam_check.result.get('sinks_count', 0) > 0)
                has_dashboards = dashboards_check and isinstance(dashboards_check.result, dict) and dashboards_check.result.get('DashboardEntries')
                has_anomaly = anomaly_check and isinstance(anomaly_check.result, dict) and anomaly_check.result.get('total_bands', 0) > 0
                has_devops_agent = devops_agent_check and isinstance(devops_agent_check.result, dict) and devops_agent_check.result.get('total_spaces', 0) > 0
                has_enterprise_access = has_streams or has_oam

                evidence_refs = f"(Checks #{', #'.join(str(id) for id in check.evidence_check_ids)})"
                capabilities = []
                if has_dashboards: capabilities.append(f"{len(dashboards_check.result['DashboardEntries'])} dashboards")
                if has_streams: capabilities.append(f"{len(streams_check.result['Entries'])} metric streams")
                if has_oam: capabilities.append("cross-account observability (OAM)")
                if has_anomaly: capabilities.append("anomaly detection")
                if has_devops_agent: capabilities.append("DevOps Agent")

                # L4: Automated insights with proactive root cause
                if has_enterprise_access and has_anomaly and has_devops_agent:
                    check.current_level = 4
                    check.explanation = f"Centralized metrics with automated insights via {', '.join(capabilities)}. Proactive root cause identification with AI-assisted resolution {evidence_refs}."
                # L3: Correlation and anomaly detection
                elif has_enterprise_access and has_anomaly:
                    check.current_level = 3
                    check.explanation = f"Centralized metrics with correlation via {', '.join(capabilities)}. Anomaly detection enables immediate root cause determination {evidence_refs}."
                # L2: Enterprise-wide visibility
                elif has_dashboards and has_enterprise_access:
                    check.current_level = 2
                    check.explanation = f"Enterprise-wide metrics visibility with {', '.join(capabilities)}. Teams can analyze and troubleshoot across data sources {evidence_refs}."
                # L1: Basic centralized collection
                elif has_dashboards:
                    check.current_level = 1
                    check.explanation = f"Basic centralized metrics access with {', '.join(capabilities)}. Lacks cross-account streaming or unified enterprise access {evidence_refs}."
                else:
                    check.current_level = 1
                    check.explanation = f"Basic metrics access without centralized management or unified visibility {evidence_refs}."

    def assess_traces_maturity(self):
        """Assess traces maturity based on discovery checks"""
        traces_checks = [c for c in self.results.assessment_checks if c.category == "Traces"]
        
        for check in traces_checks:
            if check.question_id == 8:  # How do you collect traces?
                xray_check = next((c for c in self.results.discovery_checks if c.name == "Do you use X-Ray service maps to visualize application architecture?"), None)
                lambda_tracing_check = next((c for c in self.results.discovery_checks if c.name == "Do your Lambda functions have X-Ray tracing enabled?"), None)
                sampling_check = next((c for c in self.results.discovery_checks if c.name == "Do you have custom X-Ray sampling rules configured?"), None)
                groups_check = next((c for c in self.results.discovery_checks if c.name == "Do you have X-Ray groups configured for focused trace analysis?"), None)
                transaction_search_check = next((c for c in self.results.discovery_checks if c.name == "Do you have transaction search enabled?"), None)
                
                check.evidence_check_ids = [c.id for c in [xray_check, lambda_tracing_check, sampling_check, groups_check, transaction_search_check] if c]
                
                has_service_map = xray_check and xray_check.result and xray_check.result.get('Services')
                has_sampling = sampling_check and sampling_check.result and sampling_check.result.get('SamplingRuleRecords')
                has_groups = groups_check and groups_check.result and groups_check.result.get('Groups')
                has_lambda_tracing = lambda_tracing_check and lambda_tracing_check.result and isinstance(lambda_tracing_check.result, list) and len(lambda_tracing_check.result) > 0
                has_transaction_search = transaction_search_check and transaction_search_check.result and transaction_search_check.result.get('logGroups')
                
                if has_transaction_search and has_service_map and has_sampling and has_groups:
                    service_count = len(xray_check.result.get('Services', []))
                    rule_count = len(sampling_check.result.get('SamplingRuleRecords', []))
                    group_count = len(groups_check.result.get('Groups', []))
                    check.current_level = 4
                    check.explanation = f"Advanced tracing with Transaction Search enabled (Check #{transaction_search_check.id}), X-Ray service map showing {service_count} services (Check #{xray_check.id}), {rule_count} sampling rules (Check #{sampling_check.id}), and {group_count} X-Ray groups for focused analysis (Check #{groups_check.id}). This provides automatic injection with proactive alerts, complete span visibility, optimized trace collection, and targeted trace filtering across distributed services."
                elif has_service_map and has_sampling and (has_groups or has_transaction_search):
                    service_count = len(xray_check.result.get('Services', []))
                    rule_count = len(sampling_check.result.get('SamplingRuleRecords', []))
                    check.current_level = 3
                    if has_groups:
                        group_count = len(groups_check.result.get('Groups', []))
                        check.explanation = f"Comprehensive tracing infrastructure with X-Ray service map showing {service_count} services (Check #{xray_check.id}), {rule_count} sampling rules (Check #{sampling_check.id}), and {group_count} X-Ray groups (Check #{groups_check.id}). This provides end-to-end visibility with optimized trace collection, focused trace analysis, and correlation capabilities across distributed services."
                    else:
                        check.explanation = f"Comprehensive tracing infrastructure with Transaction Search enabled (Check #{transaction_search_check.id}), X-Ray service map showing {service_count} services (Check #{xray_check.id}), and {rule_count} sampling rules (Check #{sampling_check.id}). This provides end-to-end visibility with complete span visibility and optimized trace collection across distributed services."
                elif has_service_map or has_lambda_tracing:
                    if has_service_map:
                        service_count = len(xray_check.result.get('Services', []))
                        check.current_level = 2
                        check.explanation = f"Active tracing implementation with X-Ray service map tracking {service_count} services (Check #{xray_check.id}). This indicates both auto-instrumentation and manual instrumentation are in use for distributed tracing."
                    else:
                        traced_functions = len(lambda_tracing_check.result) if isinstance(lambda_tracing_check.result, list) else 0
                        check.current_level = 2
                        check.explanation = f"Tracing enabled for {traced_functions} Lambda functions (Check #{lambda_tracing_check.id}), indicating selective instrumentation for serverless workloads."
                else:
                    check.current_level = 1
                    check.explanation = "Limited or no distributed tracing detected. Basic auto-instrumented SDKs may be present but without comprehensive trace collection."
            
            elif check.question_id == 9:  # How do you use traces?
                xray_check = next((c for c in self.results.discovery_checks if c.name == "Do you use X-Ray service maps to visualize application architecture?"), None)
                insights_check = next((c for c in self.results.discovery_checks if c.name == "Do you have X-Ray Insights configured for anomaly detection?"), None)
                app_signals_check = next((c for c in self.results.discovery_checks if c.name == "Do you use AWS Application Signals to monitor application services?"), None)
                groups_check = next((c for c in self.results.discovery_checks if c.name == "Do you have X-Ray groups configured for focused trace analysis?"), None)
                transaction_search_check = next((c for c in self.results.discovery_checks if c.name == "Do you have transaction search enabled?"), None)
                
                check.evidence_check_ids = [c.id for c in [xray_check, insights_check, app_signals_check, groups_check, transaction_search_check] if c]
                
                has_app_signals = app_signals_check and app_signals_check.result and app_signals_check.result.get('Services')
                has_insights = insights_check and insights_check.result
                has_service_map = xray_check and xray_check.result and xray_check.result.get('Services')
                has_groups = groups_check and groups_check.result and groups_check.result.get('Groups')
                has_transaction_search = transaction_search_check and transaction_search_check.result and transaction_search_check.result.get('logGroups')
                
                if has_app_signals and has_transaction_search:
                    service_count = len(app_signals_check.result.get('Services', []))
                    check.current_level = 4
                    check.explanation = f"Advanced trace analysis with Application Signals monitoring {service_count} services (Check #{app_signals_check.id}) and Transaction Search enabled (Check #{transaction_search_check.id}), providing cross-boundary insights with complete span visibility and proactive root cause identification. This enables comprehensive correlation across application boundaries with automated issue detection."
                elif has_app_signals or (has_transaction_search and has_service_map) or (has_groups and has_service_map):
                    if has_app_signals:
                        service_count = len(app_signals_check.result.get('Services', []))
                        check.current_level = 3
                        check.explanation = f"Advanced trace analysis with Application Signals monitoring {service_count} services (Check #{app_signals_check.id}), providing cross-boundary insights. Consider enabling Transaction Search for complete span visibility."
                    elif has_groups:
                        service_count = len(xray_check.result.get('Services', []))
                        group_count = len(groups_check.result.get('Groups', []))
                        check.current_level = 3
                        check.explanation = f"Sophisticated trace usage with {group_count} X-Ray groups (Check #{groups_check.id}) for focused trace analysis and X-Ray service map tracking {service_count} services (Check #{xray_check.id}). This provides targeted trace filtering with custom metrics and CloudWatch integration for correlation and detailed transaction analysis."
                    else:
                        service_count = len(xray_check.result.get('Services', []))
                        check.current_level = 3
                        check.explanation = f"Sophisticated trace usage with Transaction Search enabled (Check #{transaction_search_check.id}) and X-Ray service map tracking {service_count} services (Check #{xray_check.id}). This provides 360-degree view with complete span visibility for correlation and detailed transaction analysis."
                elif has_insights and has_service_map:
                    service_count = len(xray_check.result.get('Services', []))
                    check.current_level = 3
                    check.explanation = f"Sophisticated trace usage with X-Ray Insights (Check #{insights_check.id}) analyzing service map data from {service_count} services (Check #{xray_check.id}). This provides 360-degree view combining traces, logs, and metrics for correlation and anomaly detection."
                elif has_service_map:
                    service_count = len(xray_check.result.get('Services', []))
                    check.current_level = 2
                    check.explanation = f"Active trace analysis using X-Ray service map with {service_count} services (Check #{xray_check.id}), enabling troubleshooting and performance analysis based on captured trace information and service dependencies."
                else:
                    check.current_level = 1
                    check.explanation = "Basic trace collection without advanced analysis capabilities. Traces may be collected but not actively used for systematic troubleshooting or performance optimization."

    def assess_dashboards_alarms_maturity(self):
        """Assess dashboards and alarms maturity based on discovery checks"""
        dashboard_checks = [c for c in self.results.assessment_checks if c.category == "Dashboards & Alerting"]
        
        for check in dashboard_checks:
            if check.question_id == 10:  # How do you use alarms?
                alarms_check = next((c for c in self.results.discovery_checks if c.name == "Do you have CloudWatch alarms configured for your resources?"), None)
                composite_check = next((c for c in self.results.discovery_checks if c.name == "Do you use composite alarms to reduce alarm noise?"), None)
                sns_check = next((c for c in self.results.discovery_checks if c.name == "Do your alarms send notifications to SNS topics?"), None)
                anomaly_check = next((c for c in self.results.discovery_checks if c.name == "Do you use anomaly detection models for adaptive alarming?"), None)
                investigations_check = next((c for c in self.results.discovery_checks if c.name == "Have you configured CloudWatch Investigations action for any alarms?"), None)
                
                check.evidence_check_ids = [c.id for c in [alarms_check, composite_check, sns_check, anomaly_check, investigations_check] if c]
                
                has_composite = composite_check and isinstance(composite_check.result, dict) and composite_check.result.get('CompositeAlarms')
                has_anomaly = anomaly_check and isinstance(anomaly_check.result, dict) and anomaly_check.result.get('total_bands', 0) > 0
                has_basic_alarms = alarms_check and isinstance(alarms_check.result, dict) and alarms_check.result.get('MetricAlarms')
                has_sns = sns_check and isinstance(sns_check.result, dict) and sns_check.result.get('alarms_with_sns', 0) > 0
                
                if has_composite:
                    composite_count = len(composite_check.result.get('CompositeAlarms', []))
                    metric_count = len(alarms_check.result.get('MetricAlarms', [])) if alarms_check and alarms_check.result else 0
                    check.current_level = 4
                    check.explanation = f"Advanced alarm strategy with {composite_count} composite alarms (Check #{composite_check.id}) aggregating {metric_count} metric alarms (Check #{alarms_check.id if alarms_check else 'N/A'}). This creates summarized health indicators reducing alarm noise and enabling actions at an aggregated application level."
                elif has_anomaly and has_basic_alarms:
                    anomaly_count = anomaly_check.result.get('total_bands', 0)
                    alarm_count = len(alarms_check.result.get('MetricAlarms', []))
                    check.current_level = 3
                    check.explanation = f"Sophisticated alerting with {anomaly_count} anomaly detectors (Check #{anomaly_check.id}) complementing {alarm_count} traditional alarms (Check #{alarms_check.id}). This provides actionable alerts based on ML-driven anomaly detection that accounts for patterns and seasonality."
                elif has_basic_alarms:
                    alarm_count = len(alarms_check.result.get('MetricAlarms', []))
                    check.current_level = 2
                    check.explanation = f"Structured alerting with {alarm_count} alarms (Check #{alarms_check.id}) providing notifications when metrics meet alarm triggers. This enables understanding of urgency and customer impact for operational issues."
                else:
                    check.current_level = 1
                    check.explanation = "Basic or no alerting infrastructure detected. Limited ability to proactively notify operators when metrics meet alarm triggers."
            
            elif check.question_id == 11:  # How do you use dashboards?
                dashboards_check = next((c for c in self.results.discovery_checks if c.name == "Do you have CloudWatch dashboards for visualizing metrics and logs?" and "Dashboards" in c.category), None)
                variables_check = next((c for c in self.results.discovery_checks if c.name == "Do you have dashboards configured with variables?"), None)
                app_signals_check = next((c for c in self.results.discovery_checks if c.name == "Do you use AWS Application Signals to monitor application services?"), None)
                
                check.evidence_check_ids = [c.id for c in [dashboards_check, variables_check, app_signals_check] if c]
                
                has_dashboards = dashboards_check and dashboards_check.result and dashboards_check.result.get('DashboardEntries')
                has_variables = variables_check and variables_check.result and variables_check.result.get('dashboards_with_variables', 0) > 0
                has_app_signals = app_signals_check and app_signals_check.result and app_signals_check.result.get('Services')
                
                if has_dashboards:
                    dashboard_count = len(dashboards_check.result.get('DashboardEntries', []))
                    dashboards_with_vars = variables_check.result.get('dashboards_with_variables', 0) if variables_check and variables_check.result else 0
                    
                    # Level 4: Automatic dynamic visualizations
                    if has_app_signals:
                        service_count = len(app_signals_check.result.get('Services', []))
                        check.current_level = 4
                        check.explanation = f"Automatically created dynamic visualizations with Application Signals monitoring {service_count} services (Check #{app_signals_check.id}), which auto-generates service dashboards relevant to application health and performance. Additionally, {dashboard_count} custom dashboards provide operational visibility (Check #{dashboards_check.id}). This saves time and cost by automatically creating visualizations that contain only information relevant to issues."
                    
                    # Level 3: Flexible dashboards with variables
                    elif has_variables:
                        check.current_level = 3
                        check.explanation = f"Flexible dashboards with dynamic content: {dashboards_with_vars} out of {dashboard_count} dashboards are configured with dynamic variables/input fields (Checks #{dashboards_check.id}, #{variables_check.id}). These dashboards can quickly display different content in multiple widgets depending on input field values (e.g., selecting different resources, time ranges, or grouping dimensions), enabling easier correlation and anomaly detection across services and contexts."
                    
                    # Level 2: Single pane of glass
                    elif dashboard_count >= 3:
                        check.current_level = 2
                        check.explanation = f"Single pane of glass with {dashboard_count} CloudWatch dashboards (Check #{dashboards_check.id}) providing visibility into various data sources. Multiple dashboards enable faster communication flow during operational events with well-defined visualization criteria. To reach Level 3, consider adding dynamic variables to dashboards for flexible, context-aware visualizations."
                    
                    # Level 1: Basic monitoring
                    else:
                        check.current_level = 1
                        check.explanation = f"Basic resource monitoring with {dashboard_count} dashboard(s) (Check #{dashboards_check.id}). Limited dashboard count suggests primarily basic resource monitoring. To improve, create additional dashboards covering different services and operational aspects, and consider adding dynamic variables for flexible visualizations."
                else:
                    check.current_level = 1
                    check.explanation = "No dashboards detected. Limited or no dashboard usage for operational visibility. Create CloudWatch dashboards to visualize metrics, logs, and alarms for better operational awareness."
            
            elif check.question_id == 12:  # How adaptive are your alarm thresholds?
                anomaly_check = next((c for c in self.results.discovery_checks if c.name == "Do you use anomaly detection models for adaptive alarming?"), None)
                alarms_check = next((c for c in self.results.discovery_checks if c.name == "Do you have CloudWatch alarms configured for your resources?"), None)
                
                check.evidence_check_ids = [c.id for c in [anomaly_check, alarms_check] if c]
                
                has_anomaly = anomaly_check and anomaly_check.result and anomaly_check.result.get('total_bands', 0) > 0
                has_alarms = alarms_check and alarms_check.result and alarms_check.result.get('MetricAlarms')
                
                if has_anomaly:
                    anomaly_count = anomaly_check.result.get('total_bands', 0)
                    check.current_level = 4
                    check.explanation = f"Fully adaptive thresholds with {anomaly_count} ML-based anomaly detectors (Check #{anomaly_check.id}) that continuously analyze metrics, determine normal baselines, and surface anomalies with minimal user intervention. The system accounts for seasonality and trend changes automatically."
                elif has_alarms:
                    # Check if alarms have evaluation periods > 1
                    alarms = alarms_check.result.get('MetricAlarms', [])
                    time_based_alarms = [a for a in alarms if a.get('EvaluationPeriods', 1) > 1 or a.get('DatapointsToAlarm', 1) > 1]
                    
                    if time_based_alarms:
                        check.current_level = 2
                        check.explanation = f"Time-based alarm thresholds with {len(time_based_alarms)} out of {len(alarms)} alarms configured for sustained threshold breaches (Check #{alarms_check.id}). This reduces false positives by requiring metrics to exceed thresholds for a period of time before triggering."
                    else:
                        check.current_level = 1
                        check.explanation = f"Static alarm thresholds with {len(alarms)} alarms triggering immediately when metrics exceed fixed values (Check #{alarms_check.id}). This may result in false positives during normal operational variations."
                else:
                    check.current_level = 1
                    check.explanation = "No adaptive threshold mechanisms detected. Reliance on manual threshold setting without automated baseline determination or anomaly detection."

    def assess_organization_maturity(self):
        """Assess organization maturity based on discovery checks"""
        org_checks = [c for c in self.results.assessment_checks if c.category == "Organization"]
        
        for check in org_checks:
            if check.question_id == 13:  # Do you have an enterprise observability strategy?
                tags_check = next((c for c in self.results.discovery_checks if c.name == "Do you use resource tags for organizing and managing AWS resources?"), None)
                
                check.evidence_check_ids = [tags_check.id] if tags_check else []
                
                if tags_check and tags_check.result and tags_check.result.get('ResourceTagMappingList'):
                    tagged_resources = len(tags_check.result.get('ResourceTagMappingList', []))
                    check.current_level = 2
                    check.explanation = f"Enterprise strategy elements visible through {tagged_resources} tagged resources (Check #{tags_check.id}), indicating unified tools and technologies with standardized resource management practices across the organization."
                else:
                    check.current_level = 1
                    check.explanation = "Limited evidence of enterprise observability strategy. Appears to focus primarily on data collection without comprehensive organizational alignment or standardization."
            
            elif check.question_id == 14:  # How do you use SLOs?
                app_signals_slo_check = next((c for c in self.results.discovery_checks if c.name == "Have you defined Service Level Objectives (SLOs) for critical application services?"), None)
                
                check.evidence_check_ids = [app_signals_slo_check.id] if app_signals_slo_check else []
                
                if app_signals_slo_check and app_signals_slo_check.result and app_signals_slo_check.result.get('SloSummaries'):
                    slo_count = len(app_signals_slo_check.result.get('SloSummaries', []))
                    check.current_level = 4
                    check.explanation = f"Mature SLO implementation with {slo_count} Service Level Objectives configured through Application Signals (Check #{app_signals_slo_check.id}). This indicates integrated platforms with error budgets and business-aligned reliability targets."
                else:
                    check.current_level = 1
                    check.explanation = "No formal SLO implementation detected. May have team-level experimentation but lacks enterprise adoption for systematic reliability management."
            
            elif check.question_id == 15:  # Are you getting ROI from your observability tools?
                dashboards_check = next((c for c in self.results.discovery_checks if c.name == "Do you have CloudWatch dashboards for visualizing metrics and logs?" and "Dashboards" in c.category), None)
                alarms_check = next((c for c in self.results.discovery_checks if c.name == "Do you have CloudWatch alarms configured for your resources?"), None)
                
                check.evidence_check_ids = [c.id for c in [dashboards_check, alarms_check] if c]
                
                has_consolidated_tools = dashboards_check and alarms_check and dashboards_check.result and alarms_check.result
                
                if has_consolidated_tools:
                    dashboard_count = len(dashboards_check.result.get('DashboardEntries', []))
                    alarm_count = len(alarms_check.result.get('MetricAlarms', []))
                    check.current_level = 2
                    check.explanation = f"Evidence of tool consolidation with {dashboard_count} dashboards and {alarm_count} alarms centralized in CloudWatch (Checks #{dashboards_check.id}, #{alarms_check.id}). This suggests vendor consolidation efforts to optimize costs and reduce tool sprawl."
                else:
                    check.current_level = 1
                    check.explanation = "Limited evidence of ROI optimization. Observability tools may be present but without clear consolidation or cost optimization strategies."
            
            elif check.question_id == 16:  # Do you use any AI/ML capability today?
                anomaly_check = next((c for c in self.results.discovery_checks if c.name == "Do you use anomaly detection models for adaptive alarming?"), None)
                devops_agent_check = next((c for c in self.results.discovery_checks if c.name == "Do you use AWS DevOps Agent for AI-assisted troubleshooting?"), None)
                investigations_check = next((c for c in self.results.discovery_checks if c.name == "Have you configured CloudWatch Investigations action for any alarms?"), None)
                log_anomaly_check = next((c for c in self.results.discovery_checks if c.name == "Have you enabled anomaly detection?"), None)

                check.evidence_check_ids = [c.id for c in [anomaly_check, devops_agent_check, investigations_check, log_anomaly_check] if c]

                has_metric_anomaly = anomaly_check and isinstance(anomaly_check.result, dict) and anomaly_check.result.get('total_bands', 0) > 0
                has_log_anomaly = log_anomaly_check and log_anomaly_check.status == 'success'
                has_devops_agent = devops_agent_check and isinstance(devops_agent_check.result, dict) and devops_agent_check.result.get('total_spaces', 0) > 0
                has_investigations = investigations_check and isinstance(investigations_check.result, dict) and investigations_check.result.get('alarms_with_investigations', 0) > 0
                has_anomaly = has_metric_anomaly or has_log_anomaly

                evidence_refs = f"(Checks #{', #'.join(str(id) for id in check.evidence_check_ids)})"
                capabilities = []
                if has_metric_anomaly: capabilities.append(f"{anomaly_check.result.get('total_bands', 0)} metric anomaly detectors")
                if has_log_anomaly: capabilities.append("log anomaly detection")
                if has_devops_agent: capabilities.append("DevOps Agent (NL query)")
                if has_investigations: capabilities.append("CloudWatch Investigations")

                # L4: Comprehensive AI/ML with real-time
                if has_anomaly and has_devops_agent and has_investigations:
                    check.current_level = 4
                    check.explanation = f"Comprehensive AI/ML with {', '.join(capabilities)}. Real-time anomaly detection combined with AI-assisted troubleshooting and automated investigations {evidence_refs}."
                # L3: Automatic correlation and patterns
                elif has_anomaly and (has_devops_agent or has_investigations):
                    check.current_level = 3
                    check.explanation = f"Automatic correlation and patterns with {', '.join(capabilities)} {evidence_refs}."
                # L2: Natural language query capability
                elif has_devops_agent:
                    check.current_level = 2
                    check.explanation = f"Natural language query capability via {', '.join(capabilities)} {evidence_refs}."
                # L1: No AI/ML features
                elif has_anomaly:
                    check.current_level = 2
                    check.explanation = f"Basic AI/ML with {', '.join(capabilities)} but no natural language or automated investigation capabilities {evidence_refs}."
                else:
                    check.current_level = 1
                    check.explanation = f"No AI/ML features detected in the observability stack {evidence_refs}."
            
            elif check.question_id == 17:  # Do you have real end-user monitoring?
                rum_check = next((c for c in self.results.discovery_checks if c.name == "Do you use CloudWatch RUM to monitor real user experiences?"), None)
                synthetics_check = next((c for c in self.results.discovery_checks if c.name == "Do you use CloudWatch Synthetics to monitor application endpoints?"), None)
                
                check.evidence_check_ids = [c.id for c in [rum_check, synthetics_check] if c]
                
                has_rum = rum_check and rum_check.result and rum_check.result.get('AppMonitors')
                has_synthetics = synthetics_check and synthetics_check.result and synthetics_check.result.get('Canaries')
                
                if has_rum:
                    rum_count = len(rum_check.result.get('AppMonitors', []))
                    check.current_level = 4
                    check.explanation = f"Advanced end-user monitoring with {rum_count} Real User Monitoring applications (Check #{rum_check.id}), providing actual user experience data with proactive anomaly detection and performance insights from real user interactions."
                elif has_synthetics:
                    canary_count = len(synthetics_check.result.get('Canaries', []))
                    check.current_level = 2
                    check.explanation = f"Synthetic monitoring implemented with {canary_count} CloudWatch Synthetics canaries (Check #{synthetics_check.id}), providing scheduled validation of application functionality and user workflows from simulated user perspectives."
                else:
                    check.current_level = 1
                    check.explanation = "No end-user monitoring detected. Reliance on test users or manual validation without systematic monitoring of actual user experience or synthetic user journey testing."

    def generate_html_report(self):
        """Generate comprehensive HTML report with discovery section and assessment tabs"""
        
        # Calculate overall score
        total_score = sum(check.current_level for check in self.results.assessment_checks)
        max_score = len(self.results.assessment_checks) * 4
        self.results.overall_score = (total_score / max_score) * 4 if max_score > 0 else 0
        
        # Determine maturity level
        if self.results.overall_score >= 3.5:
            self.results.maturity_level = "Optimized"
        elif self.results.overall_score >= 2.5:
            self.results.maturity_level = "Defined"
        elif self.results.overall_score >= 1.5:
            self.results.maturity_level = "Developing"
        else:
            self.results.maturity_level = "Initial"
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AWS Observability Assessment Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 2rem; border-radius: 10px; margin-bottom: 2rem; text-align: center; }}
        .header h1 {{ font-size: 2.5rem; margin-bottom: 0.5rem; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }}
        .summary-card {{ background: white; padding: 1.5rem; border-radius: 10px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); text-align: center; }}
        .tabs {{ background: white; border-radius: 10px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); margin-bottom: 2rem; }}
        .tab-buttons {{ display: flex; background: #f8fafc; border-bottom: 1px solid #e5e7eb; }}
        .tab-button {{ flex: 1; padding: 1rem; background: none; border: none; cursor: pointer; font-size: 1rem; font-weight: 500; color: #6b7280; }}
        .tab-button.active {{ background: white; color: #667eea; border-bottom: 3px solid #667eea; }}
        .tab-content {{ display: none; padding: 2rem; }}
        .tab-content.active {{ display: block; }}
        .discovery-table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
        .discovery-table th, .discovery-table td {{ padding: 0.75rem; text-align: left; border-bottom: 1px solid #e5e7eb; }}
        .discovery-table th {{ background-color: #f8fafc; font-weight: 600; }}
        .status-success {{ color: #10b981; font-weight: bold; }}
        .status-failed {{ color: #ef4444; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 AWS Observability Assessment</h1>
            <p>Account: {self.results.account_id} | Generated: {datetime.now().strftime('%B %d, %Y at %I:%M %p')}</p>
        </div>
        
        <div class="summary-grid">
            <div class="summary-card">
                <h3>Overall Score</h3>
                <div class="number total">{self.results.overall_score:.1f}/4.0</div>
                <p>Maturity Level: {self.results.maturity_level}</p>
            </div>
            <div class="summary-card">
                <h3>Discovery Checks</h3>
                <div class="number complete">{len([c for c in self.results.discovery_checks if c.status == 'success'])}</div>
                <p>of {len(self.results.discovery_checks)} successful</p>
            </div>
            <div class="summary-card">
                <h3>Assessment Questions</h3>
                <div class="number total">{len(self.results.assessment_checks)}</div>
                <p>Evaluated</p>
            </div>
        </div>
        
        <div class="tabs">
            <div class="tab-buttons">
                <button class="tab-button active" onclick="showTab('discovery')">Discovery</button>
                <button class="tab-button" onclick="showTab('logs')">Logs</button>
                <button class="tab-button" onclick="showTab('metrics')">Metrics</button>
                <button class="tab-button" onclick="showTab('traces')">Traces</button>
                <button class="tab-button" onclick="showTab('dashboards')">Dashboards & Alarms</button>
                <button class="tab-button" onclick="showTab('organization')">Organization</button>
            </div>
            
            <div id="discovery" class="tab-content active">
                <h2>🔍 Discovery Section</h2>
                <p>Comprehensive list of all AWS service checks performed across all assessment categories.</p>
                <table class="discovery-table">
                    <thead>
                        <tr>
                            <th>Check #</th>
                            <th>Name</th>
                            <th>Category</th>
                            <th>Command</th>
                            <th>Evidence</th>
                        </tr>
                    </thead>
                    <tbody>"""
        
        # Add discovery checks to table
        for check in self.results.discovery_checks:
            html_content += f"""
                        <tr>
                            <td>{check.id}</td>
                            <td>{check.name}</td>
                            <td>{check.category}</td>
                            <td style="font-family: monospace; font-size: 0.8em; max-width: 300px; word-wrap: break-word;">{check.command}</td>
                            <td style="font-size: 0.85em; max-width: 600px; word-wrap: break-word;">{check.evidence}</td>
                        </tr>"""
        html_content += """
                    </tbody>
                </table>
            </div>
            
            <div id="logs" class="tab-content">
                <h2>📝 Logs Assessment</h2>
                <p>Assessment of log collection, usage, access, and retention practices.</p>"""
        
        # Add logs assessment content
        logs_checks = [c for c in self.results.assessment_checks if c.category == "Logs"]
        for check in logs_checks:
            evidence_refs = ", ".join([f"#{id}" for id in check.evidence_check_ids]) if check.evidence_check_ids else "No evidence"
            html_content += f"""
                <div style="margin: 2rem 0; padding: 1.5rem; border: 1px solid #e5e7eb; border-radius: 8px;">
                    <h3>Q{check.question_id}: {check.question}</h3>
                    <div style="margin: 1rem 0;">
                        <strong>Maturity Levels:</strong>
                        <ul style="margin: 0.5rem 0; padding-left: 2rem;">"""
            
            for level, description in check.maturity_descriptions.items():
                selected = "✅ " if level == check.current_level else ""
                style = "font-weight: bold; color: #10b981;" if level == check.current_level else ""
                html_content += f'<li style="{style}">Level {level}: {selected}{description}</li>'
            
            html_content += f"""
                        </ul>
                    </div>
                    <div style="background: #f8fafc; padding: 1rem; border-radius: 4px; margin: 1rem 0;">
                        <strong>Selected Answer:</strong> Level {check.current_level}<br>
                        <strong>Evidence:</strong> {check.explanation}<br>
                        <strong>Discovery Checks:</strong> {evidence_refs}
                    </div>
                </div>"""
        
        html_content += """
            </div>
            
            <div id="metrics" class="tab-content">
                <h2>📊 Metrics Assessment</h2>
                <p>Assessment of metric collection, usage, and access patterns.</p>"""
        
        # Add metrics assessment content
        metrics_checks = [c for c in self.results.assessment_checks if c.category == "Metrics"]
        for check in metrics_checks:
            evidence_refs = ", ".join([f"#{id}" for id in check.evidence_check_ids]) if check.evidence_check_ids else "No evidence"
            html_content += f"""
                <div style="margin: 2rem 0; padding: 1.5rem; border: 1px solid #e5e7eb; border-radius: 8px;">
                    <h3>Q{check.question_id}: {check.question}</h3>
                    <div style="margin: 1rem 0;">
                        <strong>Maturity Levels:</strong>
                        <ul style="margin: 0.5rem 0; padding-left: 2rem;">"""
            
            for level, description in check.maturity_descriptions.items():
                selected = "✅ " if level == check.current_level else ""
                style = "font-weight: bold; color: #10b981;" if level == check.current_level else ""
                html_content += f'<li style="{style}">Level {level}: {selected}{description}</li>'
            
            html_content += f"""
                        </ul>
                    </div>
                    <div style="background: #f8fafc; padding: 1rem; border-radius: 4px; margin: 1rem 0;">
                        <strong>Selected Answer:</strong> Level {check.current_level}<br>
                        <strong>Evidence:</strong> {check.explanation}<br>
                        <strong>Discovery Checks:</strong> {evidence_refs}
                    </div>
                </div>"""
        
        html_content += """
            </div>
            
            <div id="traces" class="tab-content">
                <h2>🔍 Traces Assessment</h2>
                <p>Assessment of trace collection and usage practices.</p>"""
        
        # Add traces assessment content
        traces_checks = [c for c in self.results.assessment_checks if c.category == "Traces"]
        for check in traces_checks:
            evidence_refs = ", ".join([f"#{id}" for id in check.evidence_check_ids]) if check.evidence_check_ids else "No evidence"
            html_content += f"""
                <div style="margin: 2rem 0; padding: 1.5rem; border: 1px solid #e5e7eb; border-radius: 8px;">
                    <h3>Q{check.question_id}: {check.question}</h3>
                    <div style="margin: 1rem 0;">
                        <strong>Maturity Levels:</strong>
                        <ul style="margin: 0.5rem 0; padding-left: 2rem;">"""
            
            for level, description in check.maturity_descriptions.items():
                selected = "✅ " if level == check.current_level else ""
                style = "font-weight: bold; color: #10b981;" if level == check.current_level else ""
                html_content += f'<li style="{style}">Level {level}: {selected}{description}</li>'
            
            html_content += f"""
                        </ul>
                    </div>
                    <div style="background: #f8fafc; padding: 1rem; border-radius: 4px; margin: 1rem 0;">
                        <strong>Selected Answer:</strong> Level {check.current_level}<br>
                        <strong>Evidence:</strong> {check.explanation}<br>
                        <strong>Discovery Checks:</strong> {evidence_refs}
                    </div>
                </div>"""
        
        html_content += """
            </div>
            
            <div id="dashboards" class="tab-content">
                <h2>📈 Dashboards & Alarms Assessment</h2>
                <p>Assessment of dashboard and alerting practices.</p>"""
        
        # Add dashboards assessment content
        dashboard_checks = [c for c in self.results.assessment_checks if c.category == "Dashboards & Alerting"]
        for check in dashboard_checks:
            evidence_refs = ", ".join([f"#{id}" for id in check.evidence_check_ids]) if check.evidence_check_ids else "No evidence"
            html_content += f"""
                <div style="margin: 2rem 0; padding: 1.5rem; border: 1px solid #e5e7eb; border-radius: 8px;">
                    <h3>Q{check.question_id}: {check.question}</h3>
                    <div style="margin: 1rem 0;">
                        <strong>Maturity Levels:</strong>
                        <ul style="margin: 0.5rem 0; padding-left: 2rem;">"""
            
            for level, description in check.maturity_descriptions.items():
                selected = "✅ " if level == check.current_level else ""
                style = "font-weight: bold; color: #10b981;" if level == check.current_level else ""
                html_content += f'<li style="{style}">Level {level}: {selected}{description}</li>'
            
            html_content += f"""
                        </ul>
                    </div>
                    <div style="background: #f8fafc; padding: 1rem; border-radius: 4px; margin: 1rem 0;">
                        <strong>Selected Answer:</strong> Level {check.current_level}<br>
                        <strong>Evidence:</strong> {check.explanation}<br>
                        <strong>Discovery Checks:</strong> {evidence_refs}
                    </div>
                </div>"""
        
        html_content += """
            </div>
            
            <div id="organization" class="tab-content">
                <h2>🏢 Organization Assessment</h2>
                <p>Assessment of enterprise observability strategy and practices.</p>"""
        
        # Add organization assessment content
        org_checks = [c for c in self.results.assessment_checks if c.category == "Organization"]
        for check in org_checks:
            evidence_refs = ", ".join([f"#{id}" for id in check.evidence_check_ids]) if check.evidence_check_ids else "No evidence"
            html_content += f"""
                <div style="margin: 2rem 0; padding: 1.5rem; border: 1px solid #e5e7eb; border-radius: 8px;">
                    <h3>Q{check.question_id}: {check.question}</h3>
                    <div style="margin: 1rem 0;">
                        <strong>Maturity Levels:</strong>
                        <ul style="margin: 0.5rem 0; padding-left: 2rem;">"""
            
            for level, description in check.maturity_descriptions.items():
                selected = "✅ " if level == check.current_level else ""
                style = "font-weight: bold; color: #10b981;" if level == check.current_level else ""
                html_content += f'<li style="{style}">Level {level}: {selected}{description}</li>'
            
            html_content += f"""
                        </ul>
                    </div>
                    <div style="background: #f8fafc; padding: 1rem; border-radius: 4px; margin: 1rem 0;">
                        <strong>Selected Answer:</strong> Level {check.current_level}<br>
                        <strong>Evidence:</strong> {check.explanation}<br>
                        <strong>Discovery Checks:</strong> {evidence_refs}
                    </div>
                </div>"""
        
        html_content += """
            </div>
        </div>
        
        <script>
            function showTab(tabName) {
                // Hide all tab contents
                const contents = document.querySelectorAll('.tab-content');
                contents.forEach(content => content.classList.remove('active'));
                
                // Remove active class from all buttons
                const buttons = document.querySelectorAll('.tab-button');
                buttons.forEach(button => button.classList.remove('active'));
                
                // Show selected tab and activate button
                document.getElementById(tabName).classList.add('active');
                event.target.classList.add('active');
            }
        </script>
    </div>
</body>
</html>"""
        
        # Ensure sample-result directory exists
        import os
        os.makedirs("sample-result", exist_ok=True)
        
        with open(self.html_file, 'w') as f:
            f.write(html_content)
        
        print(f"📊 HTML report saved to: {self.html_file}")

    def get_discovery_checks_for_question(self, question_id: int) -> list:
        """Return discovery check names needed for a given assessment question."""
        mapping = {
            1: [  # How do you collect logs?
                "What percentage of your log groups are categorized by source type (AWS Service Vended Logs, Custom Logs)",
                "What percentage of EC2 instances have CloudWatch Agent installed with both system metrics AND application logs configured?",
                "What percentage of Lambda functions use JSON structured logging?",
                "What percentage of ECS tasks use structured logging (JSON)?",
                "Are all five EKS control plane log types enabled (api, audit, authenticator, controllerManager, scheduler)?",
                "Is the EKS CloudWatch Observability add-on deployed with Container Insights and Application Signals enabled?",
                "What percentage of application logs use structured JSON format for easier parsing and analysis?",
                "Have you implemented Cross-Account and Cross-Region Log Centralization?",
                "Are you using CloudWatch cross-account observability?",
                "Have you enabled anomaly detection?",
            ],
            2: [  # How do you use logs?
                "Do you have standardized Log Insights queries for common troubleshooting scenarios (errors, latency, security events)?",
                "Have you created metric filters to extract KPIs from logs?",
                "Have you enabled anomaly detection?",
                "What percentage of application logs use structured JSON format for easier parsing and analysis?",
                "What percentage of Lambda functions use JSON structured logging?",
                "What percentage of ECS tasks use structured logging (JSON)?",
                "Do you have field index policies configured for faster log queries?",
                "Do you use AWS DevOps Agent for AI-assisted troubleshooting?",
            ],
            3: [  # How do you access logs?
                "What percentage of your log groups are categorized by source type (AWS Service Vended Logs, Custom Logs)",
                "Do you have CloudWatch dashboards for visualizing metrics and logs?",
                "What percentage of log groups have subscription filters for real-time processing?",
                "Have you implemented Cross-Account and Cross-Region Log Centralization?",
                "Are you using CloudWatch cross-account observability?",
                "Have you enabled anomaly detection?",
                "Do you use AWS DevOps Agent for AI-assisted troubleshooting?",
                "Have you configured CloudWatch Investigations action for any alarms?",
            ],
            4: [  # What is your log retention policy?
                "What percentage of log groups have retention policies aligned with your compliance requirements (security: 90+ days, operational: 30 days, debug: 7 days)?",
                "Do you have log export tasks configured for archival?",
                "What percentage of log groups have subscription filters for real-time processing?",
                "Have you implemented Cross-Account and Cross-Region Log Centralization?",
                "Do your log groups have resource tags for retention governance and metadata-based search?",
            ],
            5: [  # What type of metrics do you collect?
                "Are you publishing custom business and application metrics to CloudWatch?",
                "What percentage of production EC2 instances have detailed monitoring (1-minute metrics) enabled?",
                "What percentage of ECS Clusters have monitoring enabled?",
                "Do you have ECS clusters with Container Insights enabled?",
                "Do you have EKS clusters with CloudWatch Observability add-on enabled?",
                "What percentage of Lambda functions have Lambda Insights enabled for enhanced metrics?",
                "Are CloudWatch Agents configured to collect system-level metrics?",
                "Do you use AWS Application Signals to monitor application services?",
            ],
            6: [  # How do you use metrics?
                "Do you have CloudWatch dashboards for visualizing metrics and logs?",
                "Do you have CloudWatch alarms configured for your resources?",
                "Do you use anomaly detection models for adaptive alarming?",
                "Do you use AWS DevOps Agent for AI-assisted troubleshooting?",
            ],
            7: [  # How do you access metrics?
                "Have you configured metric streams for real-time export to third-party tools or data lakes?",
                "Are you using CloudWatch cross-account observability?",
                "Do you have CloudWatch dashboards for visualizing metrics and logs?",
                "Do you use anomaly detection models for adaptive alarming?",
                "Do you use AWS DevOps Agent for AI-assisted troubleshooting?",
            ],
            8: [  # How do you collect traces?
                "Do you use X-Ray service maps to visualize application architecture?",
                "Do your Lambda functions have X-Ray tracing enabled?",
                "Do you have custom X-Ray sampling rules configured?",
                "Do you have X-Ray groups configured for focused trace analysis?",
                "Do you have transaction search enabled?",
            ],
            9: [  # How do you use traces?
                "Do you use X-Ray service maps to visualize application architecture?",
                "Do you have X-Ray Insights configured for anomaly detection?",
                "Do you use AWS Application Signals to monitor application services?",
                "Do you have X-Ray groups configured for focused trace analysis?",
                "Do you have transaction search enabled?",
            ],
            10: [  # How do you use alarms?
                "Do you have CloudWatch alarms configured for your resources?",
                "Do you use composite alarms to reduce alarm noise?",
                "Do your alarms send notifications to SNS topics?",
                "Do you use anomaly detection models for adaptive alarming?",
                "Have you configured CloudWatch Investigations action for any alarms?",
            ],
            11: [  # How do you use dashboards?
                "Do you have CloudWatch dashboards for visualizing metrics and logs?",
                "Do you have dashboards configured with variables?",
                "Do you use AWS Application Signals to monitor application services?",
            ],
            12: [  # How adaptive are your alarm thresholds?
                "Do you use anomaly detection models for adaptive alarming?",
                "Do you have CloudWatch alarms configured for your resources?",
            ],
            13: [  # Do you have an enterprise observability strategy?
                "Do you use resource tags for organizing and managing AWS resources?",
            ],
            14: [  # How do you use SLOs?
                "Have you defined Service Level Objectives (SLOs) for critical application services?",
            ],
            15: [  # Are you getting ROI from your observability tools?
                "Do you have CloudWatch dashboards for visualizing metrics and logs?",
                "Do you have CloudWatch alarms configured for your resources?",
            ],
            16: [  # Do you use any AI/ML capability today?
                "Do you use anomaly detection models for adaptive alarming?",
                "Do you use AWS DevOps Agent for AI-assisted troubleshooting?",
                "Have you configured CloudWatch Investigations action for any alarms?",
                "Have you enabled anomaly detection?",
            ],
            17: [  # Do you have real end-user monitoring?
                "Do you use CloudWatch RUM to monitor real user experiences?",
                "Do you use CloudWatch Synthetics to monitor application endpoints?",
            ],
        }
        return mapping.get(question_id, [])

    def run_single_question(self, question_id: int):
        """Run only the discovery checks relevant to a specific assessment question and score it."""
        print(f"🔍 Running Assessment Question #{question_id}")
        print("=" * 60)

        self.setup_discovery_checks()

        identity = self.run_aws_command("aws sts get-caller-identity --output json")
        if not identity:
            print("❌ Error: Could not get AWS identity")
            return
        self.results.account_id = identity.get('Account', 'Unknown')
        self.results.user_arn = identity.get('Arn', 'Unknown')

        # Run only relevant discovery checks
        needed_names = self.get_discovery_checks_for_question(question_id)
        if not needed_names:
            print(f"❌ No discovery check mapping defined for question {question_id}")
            return

        relevant_checks = [c for c in self.results.discovery_checks if c.name in needed_names]
        print(f"📋 Running {len(relevant_checks)} discovery checks for question {question_id}:\n")
        for c in relevant_checks:
            print(f"  🚀 #{c.id}: {c.name[:80]}...")
            self.execute_discovery_check(c.id)
            print(f"     Status: {'✅' if c.status == 'success' else '❌'}")

        # Setup and run maturity assessment
        self.setup_assessment_questions()
        category_map = {1: 'Logs', 2: 'Logs', 3: 'Logs', 4: 'Logs',
                        5: 'Metrics', 6: 'Metrics', 7: 'Metrics',
                        8: 'Traces', 9: 'Traces',
                        10: 'Dashboards & Alerting', 11: 'Dashboards & Alerting', 12: 'Dashboards & Alerting',
                        13: 'Organization', 14: 'Organization', 15: 'Organization', 16: 'Organization', 17: 'Organization'}
        cat = category_map.get(question_id)
        if cat == 'Logs':
            self.assess_logs_maturity()
        elif cat == 'Metrics':
            self.assess_metrics_maturity()
        elif cat == 'Traces':
            self.assess_traces_maturity()
        elif cat == 'Dashboards & Alerting':
            self.assess_dashboards_alarms_maturity()
        elif cat == 'Organization':
            self.assess_organization_maturity()

        q = next((c for c in self.results.assessment_checks if c.question_id == question_id), None)
        if q:
            print(f"\n{'=' * 60}")
            print(f"📊 Question {question_id}: {q.question}")
            print(f"   Level: {q.current_level}/4 — {q.maturity_descriptions.get(q.current_level, '')}")
            print(f"   Explanation: {q.explanation}")
        print("\n✅ Single question assessment complete!")

    def run_single_check(self, check_id: int):
        """Run a single discovery check and output to console"""
        print(f"🔍 Running Single Discovery Check #{check_id}")
        print("=" * 60)
        
        # Setup discovery checks to get the check definition
        self.setup_discovery_checks()
        
        # Find the requested check
        target_check = next((c for c in self.results.discovery_checks if c.id == check_id), None)
        if not target_check:
            print(f"❌ Error: Check #{check_id} not found")
            print(f"Available checks: 1-{len(self.results.discovery_checks)}")
            return
        
        # Get AWS identity
        identity = self.run_aws_command("aws sts get-caller-identity --output json")
        if not identity:
            print("❌ Error: Could not get AWS identity")
            return
        
        self.results.account_id = identity.get('Account', 'Unknown')
        self.results.user_arn = identity.get('Arn', 'Unknown')
        
        print(f"📋 Check Details:")
        print(f"   ID: {target_check.id}")
        print(f"   Name: {target_check.name}")
        print(f"   Category: {target_check.category}")
        print(f"   Command: {target_check.command}")
        print()
        
        # Execute the specific check
        print(f"🚀 Executing check...")
        self.execute_discovery_check(check_id)
        
        # Display results
        print(f"📊 Results:")
        print(f"   Status: {'✅ SUCCESS' if target_check.status == 'success' else '❌ FAILED'}")
        print(f"   Evidence: {target_check.evidence}")
        print()
        
        print("✅ Single check complete!")

    def run_assessment(self):
        """Run the full comprehensive assessment"""
        return self.run_full_assessment()
    
    def run_full_assessment(self):
        """Run the complete assessment"""
        print("🚀 Starting Comprehensive Observability Assessment")
        print("=" * 80)
        
        # Get AWS identity
        identity = self.run_aws_command("aws sts get-caller-identity --output json")
        if identity:
            self.results.account_id = identity.get('Account', 'Unknown')
            self.results.user_arn = identity.get('Arn', 'Unknown')
            # Set html_file with account_id
            self.html_file = f"sample-result/observability_assessment_{self.timestamp}_{self.results.account_id}.html"
        
        # Setup and execute discovery
        self.setup_discovery_checks()
        self.execute_all_discovery_checks()
        
        # Setup assessment questions
        self.setup_assessment_questions()
        
        # Perform assessments
        self.assess_all_categories()
        
        # Generate report
        self.generate_html_report()
        
        print(f"✅ Assessment complete! Overall Score: {self.results.overall_score:.1f}/4.0")
        print(f"📊 Maturity Level: {self.results.maturity_level}")

    def execute_eks_addons_check(self):
        """Custom check for EKS observability add-ons across all EKS clusters"""
        try:
            # First get all EKS clusters
            clusters_result = self.run_aws_command("aws eks list-clusters --output json")
            if not clusters_result or 'clusters' not in clusters_result:
                return {'total_clusters': 0, 'observability_clusters': 0}
            
            cluster_names = clusters_result['clusters']
            observability_clusters = []
            
            # Check for observability add-on in each cluster
            for cluster_name in cluster_names:
                try:
                    addons_result = self.run_aws_command(f'aws eks list-addons --cluster-name "{cluster_name}" --output json')
                    if addons_result and 'addons' in addons_result:
                        cluster_addons = addons_result['addons']
                        if 'amazon-cloudwatch-observability' in cluster_addons:
                            observability_clusters.append(cluster_name)
                except:
                    continue  # Skip clusters that fail
            
            return {
                'total_clusters': len(cluster_names),
                'observability_clusters': len(observability_clusters),
                'clusters_with_observability': observability_clusters
            }
            
        except Exception as e:
            return {'total_clusters': 0, 'observability_clusters': 0}

    def execute_lambda_insights_check(self):
        """Custom check for Lambda functions with Lambda Insights enabled"""
        try:
            # Get all Lambda functions
            functions_result = self.run_aws_command("aws lambda list-functions --output json")
            if not functions_result or 'Functions' not in functions_result:
                return {'total_functions': 0, 'insights_functions': 0}
            
            functions = functions_result['Functions']
            insights_functions = []
            
            # Check each function for Lambda Insights layer
            for func in functions:
                func_name = func.get('FunctionName', '')
                layers = func.get('Layers', [])
                
                # Check if any layer contains LambdaInsightsExtension
                for layer in layers:
                    layer_arn = layer.get('Arn', '')
                    if 'LambdaInsightsExtension' in layer_arn:
                        insights_functions.append(func_name)
                        break
            
            return {
                'total_functions': len(functions),
                'insights_functions': len(insights_functions),
                'functions_with_insights': insights_functions
            }
            
        except Exception as e:
            return {'total_functions': 0, 'insights_functions': 0}

    def execute_custom_metrics_namespaces_check(self):
        """Custom check for truly custom application metrics (excluding AWS-generated and CWAgent system metrics)"""
        try:
            # Get all metrics and filter for custom namespaces
            metrics_result = self.run_aws_command("aws cloudwatch list-metrics --output json")
            if not metrics_result or 'Metrics' not in metrics_result:
                return {'custom_namespaces': [], 'total_custom_metrics': 0}
            
            all_metrics = metrics_result['Metrics']
            custom_metrics = []
            custom_namespaces = set()
            
            # AWS-generated namespaces to exclude (not truly custom)
            aws_generated_namespaces = {
                # Observability services
                'CloudWatchSynthetics',
                'LambdaInsights', 
                'ContainerInsights',
                'ECS/ContainerInsights',
                'ApplicationSignals',
                'AWS/ApplicationELB/TargetResponseTime',
                'AWS/X-Ray',
                
                # Container/Kubernetes
                'kubernetes.io',
                'ContainerInsights/Prometheus',
                'EKS/ContainerInsights',
                
                # Application monitoring
                'AWS/ApplicationInsights',
                'AWS/Usage',
                
                # Custom patterns that are AWS-generated
                'AWS/Events',
                'AWS/Logs/LogDelivery',
                'System/Linux',
                'System/Windows',
                
                # Third-party integrations managed by AWS
                'Prometheus',
                'Grafana',
                'Datadog',
                'NewRelic'
            }
            
            # CWAgent system metric names (not custom application metrics)
            cwagent_system_metrics = {
                'cpu_usage_idle', 'cpu_usage_iowait', 'cpu_usage_system', 'cpu_usage_user', 'cpu_usage_nice', 'cpu_usage_steal', 'cpu_usage_guest',
                'disk_used_percent', 'disk_inodes_free', 'disk_inodes_used', 'disk_free', 'disk_used', 'disk_total',
                'diskio_reads', 'diskio_writes', 'diskio_read_bytes', 'diskio_write_bytes', 'diskio_read_time', 'diskio_write_time',
                'mem_used_percent', 'mem_available_percent', 'mem_cached', 'mem_buffers', 'mem_free', 'mem_used', 'mem_total', 'mem_available',
                'netstat_tcp_established', 'netstat_tcp_time_wait', 'netstat_tcp_close', 'netstat_tcp_close_wait', 'netstat_tcp_closing',
                'net_bytes_sent', 'net_bytes_recv', 'net_packets_sent', 'net_packets_recv', 'net_err_in', 'net_err_out', 'net_drop_in', 'net_drop_out',
                'processes_running', 'processes_sleeping', 'processes_stopped', 'processes_zombies', 'processes_blocked', 'processes_paging', 'processes_total',
                'swap_used_percent', 'swap_free', 'swap_used', 'swap_total'
            }
            
            # Filter for truly custom namespaces and metrics
            for metric in all_metrics:
                namespace = metric.get('Namespace', '')
                metric_name = metric.get('MetricName', '')
                
                # Skip AWS namespaces and AWS-generated namespaces
                if namespace.startswith('AWS/') or namespace in aws_generated_namespaces:
                    continue
                
                # For CWAgent namespace, only include non-system metrics (custom application metrics)
                if namespace == 'CWAgent' and metric_name in cwagent_system_metrics:
                    continue
                
                # This is a truly custom metric
                custom_metrics.append(metric)
                custom_namespaces.add(namespace)
            
            return {
                'custom_namespaces': list(custom_namespaces),
                'total_custom_metrics': len(custom_metrics),
                'sample_metrics': custom_metrics[:5]  # First 5 for examples
            }
            
        except Exception as e:
            return {'custom_namespaces': [], 'total_custom_metrics': 0}

    def execute_cloudwatch_alarms_check(self):
        """Custom check for CloudWatch alarms including both metric and composite alarms"""
        try:
            # Get both metric and composite alarms
            metric_alarms_result = self.run_aws_command("aws cloudwatch describe-alarms --alarm-types MetricAlarm --output json")
            composite_alarms_result = self.run_aws_command("aws cloudwatch describe-alarms --alarm-types CompositeAlarm --output json")
            
            metric_alarms = metric_alarms_result.get('MetricAlarms', []) if metric_alarms_result else []
            composite_alarms = composite_alarms_result.get('CompositeAlarms', []) if composite_alarms_result else []
            
            return {
                'MetricAlarms': metric_alarms,
                'CompositeAlarms': composite_alarms
            }
            
        except Exception as e:
            return {'MetricAlarms': [], 'CompositeAlarms': []}

    def execute_alarm_sns_configuration_check(self):
        """Check first 50 alarms for SNS topic configurations"""
        try:
            # Get all alarms (both metric and composite)
            metric_alarms_result = self.run_aws_command("aws cloudwatch describe-alarms --alarm-types MetricAlarm --output json")
            composite_alarms_result = self.run_aws_command("aws cloudwatch describe-alarms --alarm-types CompositeAlarm --output json")
            
            metric_alarms = metric_alarms_result.get('MetricAlarms', []) if metric_alarms_result else []
            composite_alarms = composite_alarms_result.get('CompositeAlarms', []) if composite_alarms_result else []
            
            # Combine and limit to first 50 alarms
            all_alarms = metric_alarms + composite_alarms
            first_50_alarms = all_alarms[:50]
            
            alarms_with_sns = []
            alarms_without_sns = []
            
            for alarm in first_50_alarms:
                alarm_name = alarm.get('AlarmName', 'Unknown')
                alarm_actions = alarm.get('AlarmActions', [])
                ok_actions = alarm.get('OKActions', [])
                insufficient_data_actions = alarm.get('InsufficientDataActions', [])
                
                # Check if any action is an SNS topic (ARN contains :sns:)
                all_actions = alarm_actions + ok_actions + insufficient_data_actions
                sns_topics = [action for action in all_actions if ':sns:' in action]
                
                if sns_topics:
                    alarms_with_sns.append({
                        'AlarmName': alarm_name,
                        'SNSTopics': sns_topics,
                        'AlarmActions': alarm_actions,
                        'OKActions': ok_actions,
                        'InsufficientDataActions': insufficient_data_actions
                    })
                else:
                    alarms_without_sns.append({
                        'AlarmName': alarm_name,
                        'AlarmActions': alarm_actions,
                        'OKActions': ok_actions,
                        'InsufficientDataActions': insufficient_data_actions
                    })
            
            return {
                'total_alarms_checked': len(first_50_alarms),
                'alarms_with_sns': len(alarms_with_sns),
                'alarms_without_sns': len(alarms_without_sns),
                'alarms_with_sns_details': alarms_with_sns,
                'alarms_without_sns_details': alarms_without_sns
            }
            
        except Exception as e:
            return {
                'total_alarms_checked': 0,
                'alarms_with_sns': 0,
                'alarms_without_sns': 0,
                'alarms_with_sns_details': [],
                'alarms_without_sns_details': []
            }

    def execute_anomaly_detection_bands_check(self):
        """Check for anomaly detection bands configured for metrics"""
        try:
            # Get anomaly detectors
            anomaly_detectors_result = self.run_aws_command("aws cloudwatch describe-anomaly-detectors --output json")
            anomaly_detectors = anomaly_detectors_result.get('AnomalyDetectors', []) if anomaly_detectors_result else []
            
            bands_configured = []
            
            for detector in anomaly_detectors:
                namespace = detector.get('Namespace', 'Unknown')
                metric_name = detector.get('MetricName', 'Unknown')
                dimensions = detector.get('Dimensions', [])
                state = detector.get('StateValue', 'Unknown')
                
                # Format dimensions for display
                dim_str = ', '.join([f"{d.get('Name', 'Unknown')}={d.get('Value', 'Unknown')}" for d in dimensions])
                
                bands_configured.append({
                    'Namespace': namespace,
                    'MetricName': metric_name,
                    'Dimensions': dim_str,
                    'State': state,
                    'DimensionCount': len(dimensions)
                })
            
            return {
                'total_bands': len(bands_configured),
                'bands_details': bands_configured
            }
            
        except Exception as e:
            return {
                'total_bands': 0,
                'bands_details': []
            }

    def execute_alarm_opsitem_actions_check(self):
        """Check first 50 alarms for OpsItem creation actions"""
        try:
            # Get all alarms (both metric and composite)
            metric_alarms_result = self.run_aws_command("aws cloudwatch describe-alarms --alarm-types MetricAlarm --output json")
            composite_alarms_result = self.run_aws_command("aws cloudwatch describe-alarms --alarm-types CompositeAlarm --output json")
            
            metric_alarms = metric_alarms_result.get('MetricAlarms', []) if metric_alarms_result else []
            composite_alarms = composite_alarms_result.get('CompositeAlarms', []) if composite_alarms_result else []
            
            # Combine and limit to first 50 alarms
            all_alarms = metric_alarms + composite_alarms
            first_50_alarms = all_alarms[:50]
            
            alarms_with_opsitem = []
            alarms_without_opsitem = []
            
            for alarm in first_50_alarms:
                alarm_name = alarm.get('AlarmName', 'Unknown')
                alarm_actions = alarm.get('AlarmActions', [])
                ok_actions = alarm.get('OKActions', [])
                insufficient_data_actions = alarm.get('InsufficientDataActions', [])
                
                # Check if any action is an OpsItem action (ARN contains :opsitem:)
                all_actions = alarm_actions + ok_actions + insufficient_data_actions
                opsitem_actions = [action for action in all_actions if ':opsitem:' in action]
                
                if opsitem_actions:
                    alarms_with_opsitem.append({
                        'AlarmName': alarm_name,
                        'OpsItemActions': opsitem_actions,
                        'AlarmActions': alarm_actions,
                        'OKActions': ok_actions,
                        'InsufficientDataActions': insufficient_data_actions
                    })
                else:
                    alarms_without_opsitem.append({
                        'AlarmName': alarm_name,
                        'AlarmActions': alarm_actions,
                        'OKActions': ok_actions,
                        'InsufficientDataActions': insufficient_data_actions
                    })
            
            return {
                'total_alarms_checked': len(first_50_alarms),
                'alarms_with_opsitem': len(alarms_with_opsitem),
                'alarms_without_opsitem': len(alarms_without_opsitem),
                'alarms_with_opsitem_details': alarms_with_opsitem,
                'alarms_without_opsitem_details': alarms_without_opsitem
            }
            
        except Exception as e:
            return {
                'total_alarms_checked': 0,
                'alarms_with_opsitem': 0,
                'alarms_without_opsitem': 0,
                'alarms_with_opsitem_details': [],
                'alarms_without_opsitem_details': []
            }

    def execute_devops_agent_spaces_check(self):
        """Check for DevOps Agent Spaces in current region and us-east-1"""
        try:
            all_spaces = []
            regions_checked = []
            
            # Always check us-east-1
            regions_to_check = ['us-east-1']
            
            # Add current region if it's not us-east-1
            if self.region != 'us-east-1':
                regions_to_check.append(self.region)
            
            for region in regions_to_check:
                try:
                    # Build region-specific endpoint URL
                    endpoint_url = f"https://api.prod.cp.aidevops.{region}.api.aws"
                    
                    # Execute the DevOps Agent command with custom endpoint
                    command = f"aws devopsagent list-agent-spaces --endpoint-url \"{endpoint_url}\" --region {region} --output json"
                    result = self.run_aws_command(command)
                    
                    agent_spaces = result.get('agentSpaces', []) if result else []
                    
                    for space in agent_spaces:
                        all_spaces.append({
                            'name': space.get('name', 'Unknown'),
                            'agentSpaceId': space.get('agentSpaceId', 'Unknown'),
                            'createdAt': space.get('createdAt', 'Unknown'),
                            'updatedAt': space.get('updatedAt', 'Unknown'),
                            'region': region
                        })
                    
                    regions_checked.append(region)
                    
                except Exception as e:
                    # Continue checking other regions if one fails
                    continue
            
            return {
                'total_spaces': len(all_spaces),
                'spaces_details': all_spaces,
                'regions_checked': regions_checked
            }
            
        except Exception as e:
            return {
                'total_spaces': 0,
                'spaces_details': [],
                'regions_checked': []
            }

    def execute_xray_service_graph_check(self):
        """Check X-Ray service graph with time range"""
        try:
            import time
            end_time = int(time.time())
            start_time = end_time - (6 * 60 * 60)  # 6 hours ago (X-Ray limit)
            
            result = self.run_aws_command(f"aws xray get-service-graph --start-time {start_time} --end-time {end_time} --output json")
            return result
            
        except Exception as e:
            return None

    def execute_xray_sampling_rules_check(self):
        """Check X-Ray sampling rules, excluding default rule"""
        try:
            result = self.run_aws_command("aws xray get-sampling-rules --output json")
            if result and 'SamplingRuleRecords' in result:
                # Filter out the default rule
                custom_rules = [rule for rule in result['SamplingRuleRecords'] 
                               if rule.get('SamplingRule', {}).get('RuleName') != 'Default']
                
                if custom_rules:
                    # Return only custom rules
                    return {'SamplingRuleRecords': custom_rules}
                else:
                    # Return None to indicate no custom rules (check will fail)
                    return None
            return None
            
        except Exception as e:
            return None

    def execute_log_group_tags_check(self):
        """Check how many log groups have resource tags for retention governance"""
        try:
            result = self.run_aws_command(
                "aws resourcegroupstaggingapi get-resources --resource-type-filters logs:log-group --output json"
            )
            if not result or 'ResourceTagMappingList' not in result:
                return {'total_tagged_log_groups': 0, 'tagged_log_groups': []}

            resources = result['ResourceTagMappingList']
            tagged = []
            for r in resources:
                arn = r.get('ResourceARN', '')
                name = arn.split(':log-group:')[-1].rstrip(':*') if ':log-group:' in arn else arn
                tags = {t['Key']: t['Value'] for t in r.get('Tags', [])}
                tagged.append({'name': name, 'tags': tags})

            return {
                'total_tagged_log_groups': len(tagged),
                'tagged_log_groups': tagged
            }
        except Exception:
            return {'total_tagged_log_groups': 0, 'tagged_log_groups': []}

    def execute_app_signals_list_services_check(self):
        """List Application Signals services with required time window"""
        try:
            from datetime import datetime, timedelta, timezone
            end = datetime.now(timezone.utc)
            start = end - timedelta(hours=1)
            cmd = f"aws application-signals list-services --start-time {start.strftime('%Y-%m-%dT%H:%M:%SZ')} --end-time {end.strftime('%Y-%m-%dT%H:%M:%SZ')} --output json"
            result = self.run_aws_command(cmd)
            if result and 'ServiceSummaries' in result:
                return {'Services': result['ServiceSummaries']}
            return {'Services': []}
        except Exception:
            return {'Services': []}

    def execute_log_groups_categorization_check(self):
        """Categorize log groups by source type: Vended/AWS Service Logs vs Custom Logs"""
        try:
            result = self.run_aws_command("aws logs describe-log-groups --output json")
            if not result or 'logGroups' not in result:
                return None
            
            log_groups = result['logGroups']
            vended_logs = []
            custom_logs = []
            
            # AWS vended log prefixes
            aws_prefixes = ['/aws/', '/aws-']
            
            for lg in log_groups:
                name = lg.get('logGroupName', '')
                if any(name.startswith(prefix) for prefix in aws_prefixes):
                    vended_logs.append(name)
                else:
                    custom_logs.append(name)
            
            result_data = {
                'total_log_groups': len(log_groups),
                'vended_logs': vended_logs,
                'custom_logs': custom_logs,
                'vended_count': len(vended_logs),
                'custom_count': len(custom_logs)
            }
            
            # Export to CSV
            self.export_check_to_csv(
                check_name="Log Groups Categorization",
                found_count=len(vended_logs) + len(custom_logs),
                total_count=len(log_groups),
                details={
                    'Vended Logs': len(vended_logs),
                    'Custom Logs': len(custom_logs)
                }
            )
            
            return result_data
            
        except Exception as e:
            return None
            
        except Exception as e:
            return {
                'total_spaces': 0,
                'spaces_details': [],
                'regions_checked': []
            }

    def execute_alarm_lambda_actions_check(self):
        """Check first 50 alarms for Lambda function invocation actions"""
        try:
            # Get all alarms (both metric and composite)
            metric_alarms_result = self.run_aws_command("aws cloudwatch describe-alarms --alarm-types MetricAlarm --output json")
            composite_alarms_result = self.run_aws_command("aws cloudwatch describe-alarms --alarm-types CompositeAlarm --output json")
            
            metric_alarms = metric_alarms_result.get('MetricAlarms', []) if metric_alarms_result else []
            composite_alarms = composite_alarms_result.get('CompositeAlarms', []) if composite_alarms_result else []
            
            # Combine and limit to first 50 alarms
            all_alarms = metric_alarms + composite_alarms
            first_50_alarms = all_alarms[:50]
            
            alarms_with_lambda = []
            alarms_without_lambda = []
            
            for alarm in first_50_alarms:
                alarm_name = alarm.get('AlarmName', 'Unknown')
                alarm_actions = alarm.get('AlarmActions', [])
                ok_actions = alarm.get('OKActions', [])
                insufficient_data_actions = alarm.get('InsufficientDataActions', [])
                
                # Check if any action is a Lambda function (ARN contains :lambda:)
                all_actions = alarm_actions + ok_actions + insufficient_data_actions
                lambda_actions = [action for action in all_actions if ':lambda:' in action]
                
                if lambda_actions:
                    alarms_with_lambda.append({
                        'AlarmName': alarm_name,
                        'LambdaActions': lambda_actions,
                        'AlarmActions': alarm_actions,
                        'OKActions': ok_actions,
                        'InsufficientDataActions': insufficient_data_actions
                    })
                else:
                    alarms_without_lambda.append({
                        'AlarmName': alarm_name,
                        'AlarmActions': alarm_actions,
                        'OKActions': ok_actions,
                        'InsufficientDataActions': insufficient_data_actions
                    })
            
            return {
                'total_alarms_checked': len(first_50_alarms),
                'alarms_with_lambda': len(alarms_with_lambda),
                'alarms_without_lambda': len(alarms_without_lambda),
                'alarms_with_lambda_details': alarms_with_lambda,
                'alarms_without_lambda_details': alarms_without_lambda
            }
            
        except Exception as e:
            return {
                'total_alarms_checked': 0,
                'alarms_with_lambda': 0,
                'alarms_without_lambda': 0,
                'alarms_with_lambda_details': [],
                'alarms_without_lambda_details': []
            }

    def execute_alarm_investigations_actions_check(self):
        """Check first 50 alarms for CloudWatch Investigations actions"""
        try:
            # Get all alarms (both metric and composite)
            metric_alarms_result = self.run_aws_command("aws cloudwatch describe-alarms --alarm-types MetricAlarm --output json")
            composite_alarms_result = self.run_aws_command("aws cloudwatch describe-alarms --alarm-types CompositeAlarm --output json")
            
            metric_alarms = metric_alarms_result.get('MetricAlarms', []) if metric_alarms_result else []
            composite_alarms = composite_alarms_result.get('CompositeAlarms', []) if composite_alarms_result else []
            
            # Combine and limit to first 50 alarms
            all_alarms = metric_alarms + composite_alarms
            first_50_alarms = all_alarms[:50]
            
            alarms_with_investigations = []
            alarms_without_investigations = []
            
            for alarm in first_50_alarms:
                alarm_name = alarm.get('AlarmName', 'Unknown')
                alarm_actions = alarm.get('AlarmActions', [])
                ok_actions = alarm.get('OKActions', [])
                insufficient_data_actions = alarm.get('InsufficientDataActions', [])
                
                # Check if any action is a CloudWatch Investigations action (ARN contains :aiops:)
                all_actions = alarm_actions + ok_actions + insufficient_data_actions
                investigations_actions = [action for action in all_actions if ':aiops:' in action]
                
                if investigations_actions:
                    alarms_with_investigations.append({
                        'AlarmName': alarm_name,
                        'InvestigationsActions': investigations_actions,
                        'AlarmActions': alarm_actions,
                        'OKActions': ok_actions,
                        'InsufficientDataActions': insufficient_data_actions
                    })
                else:
                    alarms_without_investigations.append({
                        'AlarmName': alarm_name,
                        'AlarmActions': alarm_actions,
                        'OKActions': ok_actions,
                        'InsufficientDataActions': insufficient_data_actions
                    })
            
            return {
                'total_alarms_checked': len(first_50_alarms),
                'alarms_with_investigations': len(alarms_with_investigations),
                'alarms_without_investigations': len(alarms_without_investigations),
                'alarms_with_investigations_details': alarms_with_investigations,
                'alarms_without_investigations_details': alarms_without_investigations
            }
            
        except Exception as e:
            return {
                'total_alarms_checked': 0,
                'alarms_with_investigations': 0,
                'alarms_without_investigations': 0,
                'alarms_with_investigations_details': [],
                'alarms_without_investigations_details': []
            }

    def execute_alarm_ec2_actions_check(self):
        """Check first 50 alarms for EC2 actions"""
        try:
            # Get all alarms (both metric and composite)
            metric_alarms_result = self.run_aws_command("aws cloudwatch describe-alarms --alarm-types MetricAlarm --output json")
            composite_alarms_result = self.run_aws_command("aws cloudwatch describe-alarms --alarm-types CompositeAlarm --output json")
            
            metric_alarms = metric_alarms_result.get('MetricAlarms', []) if metric_alarms_result else []
            composite_alarms = composite_alarms_result.get('CompositeAlarms', []) if composite_alarms_result else []
            
            # Combine and limit to first 50 alarms
            all_alarms = metric_alarms + composite_alarms
            first_50_alarms = all_alarms[:50]
            
            alarms_with_ec2 = []
            alarms_without_ec2 = []
            
            for alarm in first_50_alarms:
                alarm_name = alarm.get('AlarmName', 'Unknown')
                alarm_actions = alarm.get('AlarmActions', [])
                ok_actions = alarm.get('OKActions', [])
                insufficient_data_actions = alarm.get('InsufficientDataActions', [])
                
                # Check if any action is an EC2 action (ARN contains :ec2:)
                all_actions = alarm_actions + ok_actions + insufficient_data_actions
                ec2_actions = [action for action in all_actions if ':ec2:' in action]
                
                if ec2_actions:
                    alarms_with_ec2.append({
                        'AlarmName': alarm_name,
                        'EC2Actions': ec2_actions,
                        'AlarmActions': alarm_actions,
                        'OKActions': ok_actions,
                        'InsufficientDataActions': insufficient_data_actions
                    })
                else:
                    alarms_without_ec2.append({
                        'AlarmName': alarm_name,
                        'AlarmActions': alarm_actions,
                        'OKActions': ok_actions,
                        'InsufficientDataActions': insufficient_data_actions
                    })
            
            return {
                'total_alarms_checked': len(first_50_alarms),
                'alarms_with_ec2': len(alarms_with_ec2),
                'alarms_without_ec2': len(alarms_without_ec2),
                'alarms_with_ec2_details': alarms_with_ec2,
                'alarms_without_ec2_details': alarms_without_ec2
            }
            
        except Exception as e:
            return {
                'total_alarms_checked': 0,
                'alarms_with_ec2': 0,
                'alarms_without_ec2': 0,
                'alarms_with_ec2_details': [],
                'alarms_without_ec2_details': []
            }

    def execute_dashboard_variables_check(self):
        """Check dashboards for dynamic variables and templating"""
        try:
            # Get list of dashboards
            dashboards_result = self.run_aws_command("aws cloudwatch list-dashboards --output json")
            dashboards = dashboards_result.get('DashboardEntries', []) if dashboards_result else []
            
            dashboards_with_variables = []
            dashboards_without_variables = []
            
            for dashboard in dashboards:
                dashboard_name = dashboard.get('DashboardName', 'Unknown')
                
                try:
                    # Get dashboard body
                    dashboard_body_result = self.run_aws_command(f"aws cloudwatch get-dashboard --dashboard-name \"{dashboard_name}\" --output json")
                    dashboard_body = dashboard_body_result.get('DashboardBody', '') if dashboard_body_result else ''
                    
                    # Check for dashboard variables indicators
                    has_variables = False
                    variable_indicators = []
                    
                    # Look for common variable patterns in CloudWatch dashboards
                    if '"variables"' in dashboard_body:
                        has_variables = True
                        variable_indicators.append("variables section")
                    
                    if '"templateFields"' in dashboard_body:
                        has_variables = True
                        variable_indicators.append("template fields")
                    
                    if '${' in dashboard_body:
                        has_variables = True
                        variable_indicators.append("variable substitution")
                    
                    if '"inputs"' in dashboard_body:
                        has_variables = True
                        variable_indicators.append("input fields")
                    
                    if has_variables:
                        dashboards_with_variables.append({
                            'DashboardName': dashboard_name,
                            'VariableIndicators': variable_indicators,
                            'Size': dashboard.get('Size', 0)
                        })
                    else:
                        dashboards_without_variables.append({
                            'DashboardName': dashboard_name,
                            'Size': dashboard.get('Size', 0)
                        })
                        
                except Exception as e:
                    # If we can't get dashboard body, assume no variables
                    dashboards_without_variables.append({
                        'DashboardName': dashboard_name,
                        'Size': dashboard.get('Size', 0)
                    })
            
            return {
                'total_dashboards': len(dashboards),
                'dashboards_with_variables': len(dashboards_with_variables),
                'dashboards_without_variables': len(dashboards_without_variables),
                'dashboards_with_variables_details': dashboards_with_variables,
                'dashboards_without_variables_details': dashboards_without_variables
            }
            
        except Exception as e:
            return {
                'total_dashboards': 0,
                'dashboards_with_variables': 0,
                'dashboards_without_variables': 0,
                'dashboards_with_variables_details': [],
                'dashboards_without_variables_details': []
            }

def main():
    parser = argparse.ArgumentParser(description='AWS Comprehensive Observability Assessment')
    parser.add_argument('--profile', help='AWS profile to use')
    parser.add_argument('--region', default='us-west-2', help='AWS region')
    parser.add_argument('--single-check', type=int, help='Run only a specific check by ID (outputs to console)')
    parser.add_argument('--single-question', type=int, help='Run only discovery checks for a specific question (1-17) and score it')
    
    args = parser.parse_args()
    
    assessment = ComprehensiveObservabilityAssessment(profile=args.profile, region=args.region)
    
    if args.single_check:
        assessment.run_single_check(args.single_check)
    elif args.single_question:
        assessment.run_single_question(args.single_question)
    else:
        assessment.run_assessment()

if __name__ == "__main__":
    main()
