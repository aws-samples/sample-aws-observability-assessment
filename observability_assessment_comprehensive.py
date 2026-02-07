#!/usr/bin/env python3

import json
import subprocess
import sys
import time
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
        self.html_file = f"sample-result/comprehensive_observability_assessment_{self.timestamp}.html"
        self.discovery_check_counter = 0
        self.largest_log_groups = None  # Will be populated during setup
        
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
        
        try:
            if check.command == "custom_ec2_cloudwatch_agent_check":
                check.result = self.execute_ec2_cloudwatch_agent_check()
            elif check.command == "custom_ecs_task_log_check":
                check.result = self.execute_ecs_task_log_check()
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
            else:
                check.result = self.run_aws_command(check.command)
            
            if check.result is not None:
                check.status = "success"
                # Generate detailed evidence based on check type
                try:
                    check.evidence = self.generate_detailed_evidence(check)
                except Exception as e:
                    print(f"DEBUG: Exception in evidence generation for {check.name}: {e}")
                    check.evidence = f"Account: {self.results.account_id}, Region: {self.region} - Evidence generation failed: {str(e)}"
            else:
                check.status = "failed"
                check.evidence = f"Account: {self.results.account_id}, Region: {self.region} - No resources found"
        except Exception as e:
            check.status = "failed"
            check.evidence = f"Account: {self.results.account_id}, Region: {self.region} - No resources found"

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
        
        elif check.name == "Composite Alarms":
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
                summary = f"Command: Multi-step EC2 CloudWatch agent analysis | Total: {total_instances} instances | SSM: {ssm_count}/{total_instances} | CW Agent: {cw_agent_count}/{ssm_count if ssm_count > 0 else 0} | Logging: {logging_count}/{total_instances}"
                
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
            return f"Command: Multi-step EC2 CloudWatch agent analysis | No EC2 instances found"
        
        elif check.name == "Are all Lambda functions logging to CloudWatch?":
            log_groups = check.result.get('logGroups', [])
            if log_groups:
                summary = f"Found {len(log_groups)} Lambda log groups"
                details = "<br>".join([lg.get('logGroupName', 'Unknown') for lg in log_groups[:15]])
                if len(log_groups) > 15:
                    details += f"<br>... and {len(log_groups) - 15} more log groups"
                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return f"No Lambda log groups found"
        
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
        
        elif check.name == "Are all five EKS control plane log types enabled (api, audit, authenticator, controllerManager, scheduler)?":
            log_groups = check.result.get('logGroups', [])
            if log_groups:
                summary = f"Found {len(log_groups)} EKS control plane log groups"
                details = "<br>".join([lg.get('logGroupName', 'Unknown') for lg in log_groups[:10]])
                if len(log_groups) > 10:
                    details += f"<br>... and {len(log_groups) - 10} more log groups"
                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return f"No EKS control plane log groups found"
        
        elif check.name == "Is the EKS CloudWatch Observability add-on deployed with Container Insights and Application Signals enabled?":
            if check.result and 'addon' in check.result:
                addon = check.result['addon']
                addon_name = addon.get('addonName', 'Unknown')
                addon_version = addon.get('addonVersion', 'Unknown')
                status = addon.get('status', 'Unknown')
                created_at = addon.get('createdAt', 'Unknown')
                modified_at = addon.get('modifiedAt', 'Unknown')
                cluster_name = addon.get('clusterName', 'Unknown')
                
                summary = f"Found EKS addon: {addon_name} (version: {addon_version}, status: {status})"
                
                # Create detailed breakdown
                details = f"<strong>Add-on Details:</strong><br>"
                details += f"Name: {addon_name}<br>"
                details += f"Version: {addon_version}<br>"
                details += f"Status: {status}<br>"
                details += f"Cluster: {cluster_name}<br>"
                details += f"Created: {created_at}<br>"
                details += f"Modified: {modified_at}<br>"
                
                # Add configuration details if available
                if 'configurationValues' in addon:
                    config_values = addon.get('configurationValues', '')
                    if config_values:
                        details += f"<br><strong>Configuration:</strong><br>{config_values}<br>"
                
                # Add service account details if available
                if 'serviceAccountRoleArn' in addon:
                    service_account_role = addon.get('serviceAccountRoleArn', '')
                    if service_account_role:
                        details += f"<br><strong>Service Account Role:</strong><br>{service_account_role}<br>"
                
                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return f"EKS CloudWatch Observability add-on not found"
        
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
        
        elif check.name == "Log Export Tasks Per Log Group":
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
        
        elif check.name == "Field Index Policies Per Log Group":
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
        
        elif check.name == "List of ECS clusters with Container Insights enabled?":
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
        
        elif check.name == "EKS Clusters":
            clusters = check.result.get('clusters', [])
            if clusters:
                summary = f"Found {len(clusters)} EKS clusters"
                details = "<br>".join(clusters[:10])
                if len(clusters) > 10:
                    details += f"<br>... and {len(clusters) - 10} more clusters"
                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return f"No EKS clusters found"
        
        elif check.name == "List of EKS clusters enabled with CloudWatch Observability EKS add-on?":
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
        elif check.name == "What percentage of your log groups are categorized by source type (Vended Logs, AWS Service Logs, Custom Logs)":
            log_groups = check.result.get('logGroups', [])
            if log_groups:
                summary = f"Found {len(log_groups)} log groups"
                details = "<br>".join([lg.get('logGroupName', 'Unknown') for lg in log_groups[:20]])
                if len(log_groups) > 20:
                    details += f"<br>... and {len(log_groups) - 20} more"
                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return f"No log groups found"
        
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
        
        elif check.name == "CloudWatch Alarms":
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
        
        elif check.name == "CloudWatch Dashboards":
            dashboards = check.result.get('DashboardEntries', [])
            if dashboards:
                summary = f"Found {len(dashboards)} dashboards"
                details = "<br>".join([dash.get('DashboardName', 'Unknown') for dash in dashboards[:15]])
                if len(dashboards) > 15:
                    details += f"<br>... and {len(dashboards) - 15} more dashboards"
                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return f"No dashboards found"
        
        elif check.name == "Alarm SNS Configuration":
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
        
        elif check.name == "Anomaly Detection Bands":
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
        
        elif check.name == "Resource Tags":
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
        
        elif check.name == "CloudWatch Synthetics Canaries":
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
        
        elif check.name == "RUM Applications":
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
        
        elif check.name == "Alarm OpsItem Actions":
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
        
        elif check.name == "Application Signals Services":
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
        
        elif check.name == "DevOps Agent Spaces":
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
        
        elif check.name == "Alarm Lambda Actions":
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
        
        elif check.name == "Alarm Investigations Actions":
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
        
        elif check.name == "Alarm EC2 Actions":
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
        
        elif check.name == "Lambda Functions":
            functions = check.result.get('Functions', [])
            if functions:
                summary = f"Found {len(functions)} Lambda functions"
                details = "<br>".join([func.get('FunctionName', 'Unknown') for func in functions[:20]])
                if len(functions) > 20:
                    details += f"<br>... and {len(functions) - 20} more functions"
                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return f"No Lambda functions found"
        
        elif check.name == "EC2 Instances":
            instances = []
            for reservation in check.result.get('Reservations', []):
                instances.extend(reservation.get('Instances', []))
            if instances:
                summary = f"Found {len(instances)} EC2 instances"
                details = ""
                for instance in instances[:15]:
                    instance_id = instance.get('InstanceId', 'Unknown')
                    instance_type = instance.get('InstanceType', 'Unknown')
                    state = instance.get('State', {}).get('Name', 'Unknown')
                    details += f"{instance_id} ({instance_type}) - {state}<br>"
                if len(instances) > 15:
                    details += f"... and {len(instances) - 15} more instances"
                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return f"No EC2 instances found"
        
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
        
        elif check.name == "X-Ray Sampling Rules":
            sampling_rules = check.result.get('SamplingRuleRecords', []) if check.result else []
            custom_rules = [rule for rule in sampling_rules if rule.get('SamplingRule', {}).get('RuleName') != 'Default']
            
            if custom_rules:
                summary = f"{base_info} | Found {len(custom_rules)} custom sampling rules"
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
                return f"{base_info} | No custom sampling rules configured (only {default_count} default rule exists)"
        
        # Default handler for other checks
        else:
            # Provide specific context for known checks that might return empty results
            if check.name == "Is the EKS CloudWatch Observability add-on deployed with Container Insights and Application Signals enabled?":
                return f"{base_info} | {command_info} | CloudWatch Observability add-on not found - EKS cluster may not have Amazon CloudWatch Observability add-on installed"
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
        
        elif check.name == "Log Insights Query History":
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
        
        
        
        elif check.name == "EC2 Instances":
            instances = []
            for reservation in check.result.get('Reservations', []):
                instances.extend(reservation.get('Instances', []))
            if instances:
                sample_ids = [inst.get('InstanceId', 'Unknown') for inst in instances[:3]]
                return f"Found {len(instances)} EC2 instances (e.g., {', '.join(sample_ids)})"
            return f"No EC2 instances found"
        
        elif check.name == "EKS Clusters":
            clusters = check.result.get('clusters', [])
            if clusters:
                sample_names = clusters[:3]
                return f"Found {len(clusters)} EKS clusters (e.g., {', '.join(sample_names)})"
            return f"No EKS clusters found"
        
        elif check.name == "Lambda Functions":
            functions = check.result.get('Functions', [])
            if functions:
                sample_names = [func.get('FunctionName', 'Unknown') for func in functions[:3]]
                return f"Found {len(functions)} Lambda functions (e.g., {', '.join(sample_names)})"
            return f"No Lambda functions found"
        
        elif check.name == "CloudWatch Alarms":
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
        
        elif check.name == "CloudWatch Dashboards":
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
        
        elif check.name == "Are all Lambda functions logging to CloudWatch?":
            log_groups = check.result.get('logGroups', [])
            if log_groups:
                # Get Lambda function count for comparison
                lambda_functions_result = self.run_aws_command("aws lambda list-functions --output json")
                lambda_count = 0
                if lambda_functions_result and 'Functions' in lambda_functions_result:
                    lambda_count = len(lambda_functions_result['Functions'])
                
                # Filter out non-function log groups (like lambda-insights)
                function_log_groups = [lg for lg in log_groups if not lg.get('logGroupName', '').endswith('-insights')]
                function_log_count = len(function_log_groups)
                
                if lambda_count > 0:
                    # Calculate coverage (cap at 100% since there can be old log groups)
                    coverage_count = min(function_log_count, lambda_count)
                    percentage = int((coverage_count / lambda_count) * 100)
                    return f"{command_info} | {coverage_count}/{lambda_count} Lambda functions ({percentage}%) have log groups configured | Total log groups: {len(log_groups)}"
                else:
                    return f"{command_info} | Found {len(log_groups)} Lambda log groups but no Lambda functions detected"
            else:
                # Check if there are Lambda functions without log groups
                lambda_functions_result = self.run_aws_command("aws lambda list-functions --output json")
                lambda_count = 0
                if lambda_functions_result and 'Functions' in lambda_functions_result:
                    lambda_count = len(lambda_functions_result['Functions'])
                
                if lambda_count > 0:
                    return f"{command_info} | No Lambda log groups found but {lambda_count} Lambda functions exist (functions may not have been invoked yet to create log groups)"
                else:
                    return f"{command_info} | No Lambda log groups found and no Lambda functions deployed"
        
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
        
        elif check.name == "Are all five EKS control plane log types enabled (api, audit, authenticator, controllerManager, scheduler)?":
            log_groups = check.result.get('logGroups', [])
            if log_groups:
                sample_names = [lg.get('logGroupName', 'Unknown') for lg in log_groups[:3]]
                return f"Found {len(log_groups)} EKS control plane log groups (e.g., {', '.join(sample_names)})"
            return f"No EKS control plane log groups found"
        
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
        
        elif check.name == "Log Export Tasks Per Log Group":
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
                pure_json = check.result.get('pure_json_groups', 0)
                embedded_json = check.result.get('embedded_json_groups', 0)
                sample_groups = check.result.get('sample_groups', [])
                
                total_structured = pure_json + embedded_json
                if total_structured > 0:
                    structure_details = []
                    if pure_json > 0:
                        structure_details.append(f"{pure_json} pure JSON")
                    if embedded_json > 0:
                        structure_details.append(f"{embedded_json} embedded JSON")
                    
                    sample_info = f"Examples: {', '.join(sample_groups[:3])}" if sample_groups else ""
                    return f"Analyzed {total_checked} largest log groups | {total_structured}/{total_checked} have structured logs ({', '.join(structure_details)}) | {sample_info}"
                return f"Analyzed {total_checked} largest log groups | {total_structured}/{total_checked} have structured logs"
            return f"No JSON structured log analysis performed"
        

        elif check.name == "Field Index Policies Per Log Group":
            if check.result:
                total_groups = check.result.get('total_log_groups', 0)
                indexed_groups = check.result.get('indexed_log_groups', 0)
                sample_groups = check.result.get('sample_indexed_groups', [])
                
                if indexed_groups > 0:
                    sample_info = f"Examples: {', '.join(sample_groups[:3])}" if sample_groups else ""
                    return f"Checked {total_groups} largest log groups by size - {indexed_groups}/{total_groups} have field index policies | {sample_info}"
                return f"Checked {total_groups} largest log groups by size - {indexed_groups}/{total_groups} have field index policies"
            return f"No largest log groups checked for field indexes"

        elif check.name == "List of EKS clusters enabled with CloudWatch Observability EKS add-on?":
            if check.result:
                total_clusters = check.result.get('total_clusters', 0)
                observability_clusters = check.result.get('observability_clusters', 0)
                clusters_with_obs = check.result.get('clusters_with_observability', [])
                
                if observability_clusters > 0:
                    examples = f"Examples: {', '.join(clusters_with_obs[:3])}" if clusters_with_obs else ""
                    return f"{observability_clusters}/{total_clusters} EKS clusters have amazon-cloudwatch-observability add-on | {examples}"
                return f"{observability_clusters}/{total_clusters} EKS clusters have amazon-cloudwatch-observability add-on"
            return f"{base_info} | No EKS clusters found"

        elif check.name == "X-Ray Service Map":
            services = check.result.get('Services', [])
            if services:
                sample_names = [svc.get('Name', 'Unknown') for svc in services[:3]]
                return f"{base_info} | Found {len(services)} X-Ray services (e.g., {', '.join(sample_names)})"
            return f"{base_info} | No X-Ray services found"
        
        elif check.name == "Dashboard Variables":
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
        self.add_discovery_check("What percentage of your log groups are categorized by source type (Vended Logs, AWS Service Logs, Custom Logs)", "Logs", "aws logs describe-log-groups --output json")
        self.add_discovery_check("What percentage of log groups have retention policies aligned with your compliance requirements (security: 90+ days, operational: 30 days, debug: 7 days)?", "Logs", "custom_top_log_groups_retention_check")
        self.add_discovery_check("Do you have standardized Log Insights queries for common troubleshooting scenarios (errors, latency, security events)?", "Logs", "aws logs describe-query-definitions --output json")
        self.add_discovery_check("Log Insights Query History", "Logs", "aws logs describe-queries --output json")
        self.add_discovery_check("Have you created metric filters to extract KPIs from logs?", "Logs", "aws logs describe-metric-filters --output json")
        self.add_discovery_check("What percentage of log groups have subscription filters for real-time processing?", "Logs", "custom_subscription_filters_coverage_check")
        
        # Service-Specific Log Collection
        self.add_discovery_check("What percentage of EC2 instances have CloudWatch Agent installed with both system metrics AND application logs configured?", "Logs", "custom_ec2_cloudwatch_agent_check")
        self.add_discovery_check("Are all Lambda functions logging to CloudWatch?", "Logs", "aws logs describe-log-groups --log-group-name-prefix /aws/lambda --output json")
        self.add_discovery_check("What percentage of ECS tasks use structured logging (JSON)?", "Logs", "custom_ecs_task_log_check")
        self.add_discovery_check("Are all five EKS control plane log types enabled (api, audit, authenticator, controllerManager, scheduler)?", "Logs", "aws logs describe-log-groups --log-group-name-prefix /aws/eks --output json")
        self.add_discovery_check("Is the EKS CloudWatch Observability add-on deployed with Container Insights and Application Signals enabled?", "Logs", "aws eks describe-addon --cluster-name PetsiteEKS-cluster --addon-name amazon-cloudwatch-observability --output json")
        
        # Advanced Log Analysis
        self.add_discovery_check("Have you enabled anomaly detection?", "Logs", "aws logs list-log-anomaly-detectors --output json")
        self.add_discovery_check("Log Export Tasks Per Log Group", "Logs", "custom_log_export_tasks_per_log_group_check")
        self.add_discovery_check("Have you implemented Cross-Account and Cross-Region Log Centralization?", "Logs", "custom_log_centralization_analysis_check")
        self.add_discovery_check("Are you using CloudWatch cross-account observability?", "Logs", "custom_oam_links_and_sinks_check")
        self.add_discovery_check("What percentage of application logs use structured JSON format for easier parsing and analysis?", "Logs", "custom_json_structured_logs_check")
        self.add_discovery_check("Field Index Policies Per Log Group", "Logs", "custom_field_indexes_per_log_group_check")
        
        # Metrics Discovery Checks (Detailed)
        self.add_discovery_check("EC2 Instances", "Metrics", "aws ec2 describe-instances --output json")
        self.add_discovery_check("What percentage of production EC2 instances have detailed monitoring (1-minute metrics) enabled?", "Metrics", "aws ec2 describe-instances --query 'Reservations[].Instances[?Monitoring.State==`enabled`]' --output json")
        self.add_discovery_check("What percentage of ECS Clusters have monitoring enabled?", "Metrics", "aws ecs list-clusters --output json")
        self.add_discovery_check("List of ECS clusters with Container Insights enabled?", "Metrics", "aws ecs describe-clusters --clusters PetsiteECS-cluster --include SETTINGS --output json")
        self.add_discovery_check("EKS Clusters", "Metrics", "aws eks list-clusters --output json")
        self.add_discovery_check("List of EKS clusters enabled with CloudWatch Observability EKS add-on?", "Metrics", "custom_eks_addons_check")
        self.add_discovery_check("Lambda Functions", "Metrics", "aws lambda list-functions --output json")
        self.add_discovery_check("What percentage of Lambda functions have Lambda Insights enabled for enhanced metrics?", "Metrics", "custom_lambda_insights_check")

        self.add_discovery_check("Are you publishing custom business and application metrics to CloudWatch?", "Metrics", "custom_metrics_namespaces_check")
        self.add_discovery_check("Are CloudWatch Agents configured to collect system-level metrics?", "Metrics", "aws cloudwatch list-metrics --namespace CWAgent --output json")
        self.add_discovery_check("Have you configured metric streams for real-time export to third-party tools or data lakes?", "Metrics", "aws cloudwatch list-metric-streams --output json")
        
        # Traces Discovery Checks (Detailed)
        self.add_discovery_check("X-Ray Service Map", "Traces", "custom_xray_service_graph_check")
        self.add_discovery_check("X-Ray Sampling Rules", "Traces", "custom_xray_sampling_rules_check")
        self.add_discovery_check("X-Ray Encryption Config", "Traces", "aws xray get-encryption-config --output json")
        self.add_discovery_check("Lambda Tracing Config", "Traces", "aws lambda list-functions --query 'Functions[?TracingConfig.Mode==`Active`]' --output json")
        self.add_discovery_check("X-Ray Insights", "Traces", "aws xray get-insight-summaries --output json")
        
        # Dashboards & Alarms Discovery Checks (Detailed)
        self.add_discovery_check("CloudWatch Dashboards", "Dashboards", "aws cloudwatch list-dashboards --output json")
        self.add_discovery_check("CloudWatch Alarms", "Alarms", "custom_cloudwatch_alarms_check")
        self.add_discovery_check("Metric Alarms", "Alarms", "aws cloudwatch describe-alarms --alarm-types MetricAlarm --output json")
        self.add_discovery_check("Composite Alarms", "Alarms", "aws cloudwatch describe-alarms --alarm-types CompositeAlarm --output json")
        self.add_discovery_check("Anomaly Detector Alarms", "Alarms", "aws cloudwatch describe-alarms --query 'MetricAlarms[?contains(MetricName, `ANOMALY_DETECTION_FUNCTION`)]' --output json")
        self.add_discovery_check("Alarm SNS Configuration", "Alarms", "custom_alarm_sns_configuration_check")
        self.add_discovery_check("Anomaly Detection Bands", "Alarms", "custom_anomaly_detection_bands_check")
        
        # Organization Discovery Checks (Detailed)
        self.add_discovery_check("Resource Tags", "Organization", "aws resourcegroupstaggingapi get-resources --output json")
        self.add_discovery_check("CloudWatch Synthetics Canaries", "Organization", "aws synthetics describe-canaries --output json")
        self.add_discovery_check("RUM Applications", "Organization", "aws rum list-app-monitors --output json")
        self.add_discovery_check("Alarm OpsItem Actions", "Organization", "custom_alarm_opsitem_actions_check")
        self.add_discovery_check("DevOps Agent Spaces", "Organization", "custom_devops_agent_spaces_check")
        self.add_discovery_check("Alarm Lambda Actions", "Alarms", "custom_alarm_lambda_actions_check")
        self.add_discovery_check("Alarm Investigations Actions", "Alarms", "custom_alarm_investigations_actions_check")
        self.add_discovery_check("Alarm EC2 Actions", "Alarms", "custom_alarm_ec2_actions_check")
        self.add_discovery_check("Dashboard Variables", "Dashboards", "custom_dashboard_variables_check")
        
        # Cross-Category Checks (checks that apply to multiple categories)
        # Application Signals - applies to Metrics, Traces, and Organization
        self.add_discovery_check("Application Signals Services", "Metrics", "aws application-signals list-services --output json")
        self.add_discovery_check("Application Signals Services", "Traces", "aws application-signals list-services --output json")
        self.add_discovery_check("Have you defined Service Level Objectives (SLOs) for critical application services?", "Metrics", "aws application-signals list-service-level-objectives --output json")
        self.add_discovery_check("Have you defined Service Level Objectives (SLOs) for critical application services?", "Organization", "aws application-signals list-service-level-objectives --output json")
        
        # CloudWatch Dashboards - applies to Logs, Metrics, Traces access
        self.add_discovery_check("CloudWatch Dashboards", "Logs", "aws cloudwatch list-dashboards --output json")
        self.add_discovery_check("CloudWatch Dashboards", "Metrics", "aws cloudwatch list-dashboards --output json")
        
        # Lambda Functions - applies to Logs, Metrics, and Traces
        self.add_discovery_check("Lambda Functions", "Logs", "aws lambda list-functions --output json")
        self.add_discovery_check("Lambda Functions", "Traces", "aws lambda list-functions --output json")
        
        # Resource Tags - applies to Logs retention and Organization strategy
        self.add_discovery_check("Resource Tags", "Logs", "aws resourcegroupstaggingapi get-resources --output json")

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
                'logging_configured_instances': logging_configured_instances
            }
            
        except Exception as e:
            return {'instances': [], 'ssm_instances': [], 'cw_agent_instances': [], 'logging_configured_instances': []}

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
                'logging_configs': logging_configs
            }
            
        except Exception as e:
            return {'clusters': [], 'running_tasks': [], 'tasks_with_logging': [], 'logging_configs': []}

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
            
            return {
                'top_log_groups': top_groups_info,
                'groups_with_retention': groups_with_retention,
                'total_size_gb': total_size_gb
            }
            
        except Exception as e:
            return {'top_log_groups': [], 'groups_with_retention': 0, 'total_size_gb': 0}

    def execute_subscription_filters_coverage_check(self):
        """Custom check for subscription filter coverage across ALL log groups"""
        try:
            # Step 1: Get all log groups
            log_groups_result = self.run_aws_command("aws logs describe-log-groups --output json")
            if not log_groups_result or 'logGroups' not in log_groups_result:
                return {'total_log_groups': 0, 'groups_with_subscription_filters': 0, 'sample_filtered_groups': []}
            
            log_groups = log_groups_result['logGroups']
            total_groups = len(log_groups)
            filtered_groups = []
            
            # Step 2: Check ALL log groups for subscription filters (with rate limiting)
            for i, log_group in enumerate(log_groups):
                log_group_name = log_group.get('logGroupName', '')
                try:
                    # Check for subscription filters on this log group
                    # Use shlex.quote to properly escape log group names
                    import shlex
                    escaped_name = shlex.quote(log_group_name)
                    filters_result = self.run_aws_command(f'aws logs describe-subscription-filters --log-group-name {escaped_name} --output json')
                    if filters_result and filters_result.get('subscriptionFilters'):
                        filtered_groups.append(log_group_name)
                    
                    # Rate limiting: small delay every 10 requests to avoid throttling
                    if (i + 1) % 10 == 0:
                        time.sleep(0.5)
                        
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
        """Check for JSON structured logs in the 40 largest log groups by compute type"""
        try:
            if not self.largest_log_groups:
                return {'total_groups_checked': 0, 'pure_json_groups': 0, 'embedded_json_groups': 0, 'sample_groups': []}
            
            # Combine all largest log groups
            all_target_groups = []
            for compute_type, groups in self.largest_log_groups.items():
                all_target_groups.extend(groups)
            
            if not all_target_groups:
                return {'total_groups_checked': 0, 'pure_json_groups': 0, 'embedded_json_groups': 0, 'sample_groups': []}
            
            pure_json_groups = []
            embedded_json_groups = []
            
            # Check each log group for JSON structured logs
            for group_name in all_target_groups[:40]:  # Limit to 40 groups
                try:
                    # Use a recent time window (last 24 hours)
                    import time
                    end_time = int(time.time())
                    start_time = end_time - 86400  # 24 hours ago
                    
                    # Query 1: Check for pure JSON messages (start and end with {})
                    pure_json_query = f'aws logs start-query --log-group-name "{group_name}" --start-time {start_time} --end-time {end_time} --query-string "fields @timestamp, @message | filter @message like /^\\{{.*\\}}$/ | limit 1" --output json'
                    pure_json_result = self.run_aws_command(pure_json_query)
                    
                    # Query 2: Check for embedded JSON (contains JSON structure)
                    embedded_json_query = f'aws logs start-query --log-group-name "{group_name}" --start-time {start_time} --end-time {end_time} --query-string "fields @timestamp, @message | filter @message like /\\{{/ | limit 1" --output json'
                    embedded_json_result = self.run_aws_command(embedded_json_query)
                    
                    has_pure_json = False
                    has_embedded_json = False
                    
                    # Check pure JSON results
                    if pure_json_result and pure_json_result.get('queryId'):
                        time.sleep(2)
                        results_command = f'aws logs get-query-results --query-id {pure_json_result["queryId"]} --output json'
                        results = self.run_aws_command(results_command)
                        if results and results.get('status') == 'Complete' and results.get('results'):
                            has_pure_json = True
                            pure_json_groups.append(group_name)
                    
                    # Check embedded JSON results (only if not already pure JSON)
                    if not has_pure_json and embedded_json_result and embedded_json_result.get('queryId'):
                        time.sleep(2)
                        results_command = f'aws logs get-query-results --query-id {embedded_json_result["queryId"]} --output json'
                        results = self.run_aws_command(results_command)
                        if results and results.get('status') == 'Complete' and results.get('results'):
                            has_embedded_json = True
                            embedded_json_groups.append(group_name)
                            
                except Exception:
                    continue  # Skip groups that fail
            
            return {
                'total_groups_checked': len(all_target_groups),
                'pure_json_groups': len(pure_json_groups),
                'embedded_json_groups': len(embedded_json_groups),
                'sample_groups': (pure_json_groups + embedded_json_groups)[:5]  # Show first 5 as examples
            }
            
        except Exception as e:
            return {'total_groups_checked': 0, 'pure_json_groups': 0, 'embedded_json_groups': 0, 'sample_groups': []}
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
            print(f"  [{i}/{len(self.results.discovery_checks)}] {check.name}...")
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
                # Map to discovery checks for log collection
                log_groups_check = next((c for c in self.results.discovery_checks if c.name == "What percentage of your log groups are categorized by source type (Vended Logs, AWS Service Logs, Custom Logs)"), None)
                vpc_flow_check = next((c for c in self.results.discovery_checks if c.name == "VPC Flow Logs"), None)
                cloudtrail_check = next((c for c in self.results.discovery_checks if c.name == "CloudTrail Trails"), None)
                config_recorders_check = next((c for c in self.results.discovery_checks if c.name == "Config Recorders"), None)
                ec2_agent_check = next((c for c in self.results.discovery_checks if c.name == "EC2 CloudWatch Agent IAM"), None)
                lambda_logs_check = next((c for c in self.results.discovery_checks if c.name == "Are all Lambda functions logging to CloudWatch?"), None)
                ecs_logs_check = next((c for c in self.results.discovery_checks if c.name == "What percentage of ECS tasks use structured logging (JSON)?"), None)
                eks_logs_check = next((c for c in self.results.discovery_checks if c.name == "Are all five EKS control plane log types enabled (api, audit, authenticator, controllerManager, scheduler)?"), None)
                
                check.evidence_check_ids = [c.id for c in [log_groups_check, vpc_flow_check, cloudtrail_check, config_recorders_check, ec2_agent_check, lambda_logs_check, ecs_logs_check, eks_logs_check] if c]
                
                # Count successful log collection mechanisms
                collection_mechanisms = []
                if log_groups_check and log_groups_check.result and log_groups_check.result.get('logGroups'):
                    log_count = len(log_groups_check.result.get('logGroups', []))
                    collection_mechanisms.append(f"{log_count} CloudWatch log groups")
                
                if vpc_flow_check and vpc_flow_check.result and vpc_flow_check.result.get('FlowLogs'):
                    flow_count = len(vpc_flow_check.result.get('FlowLogs', []))
                    collection_mechanisms.append(f"{flow_count} VPC flow logs")
                
                if cloudtrail_check and cloudtrail_check.result and cloudtrail_check.result.get('trailList'):
                    trail_count = len(cloudtrail_check.result.get('trailList', []))
                    collection_mechanisms.append(f"{trail_count} CloudTrail trails")
                
                if config_recorders_check and config_recorders_check.result and config_recorders_check.result.get('ConfigurationRecorders'):
                    config_count = len(config_recorders_check.result.get('ConfigurationRecorders', []))
                    collection_mechanisms.append(f"{config_count} Config recorders")
                
                if ec2_agent_check and ec2_agent_check.status == 'success':
                    collection_mechanisms.append("EC2 CloudWatch Agent configured")
                
                if lambda_logs_check and lambda_logs_check.status == 'success':
                    collection_mechanisms.append("Lambda log groups configured")
                
                if ecs_logs_check and ecs_logs_check.status == 'success':
                    collection_mechanisms.append("ECS task logging configured")
                
                if eks_logs_check and eks_logs_check.status == 'success':
                    collection_mechanisms.append("EKS control plane logs enabled")
                
                if len(collection_mechanisms) >= 4:
                    check.current_level = 3
                    check.explanation = f"Comprehensive centralized log collection with {', '.join(collection_mechanisms)} (Checks #{', #'.join(str(id) for id in check.evidence_check_ids)}). This demonstrates advanced structured logging practices across multiple AWS services including application logs, network flows, API calls, configuration changes, and service-specific logging for compute services."
                elif len(collection_mechanisms) >= 2:
                    check.current_level = 2
                    check.explanation = f"Centralized log collection established with {', '.join(collection_mechanisms)} (Checks #{', #'.join(str(id) for id in check.evidence_check_ids)}). Good foundation for observability with multiple log sources configured across AWS services."
                elif len(collection_mechanisms) >= 1:
                    check.current_level = 1
                    check.explanation = f"Basic log collection with {', '.join(collection_mechanisms)} (Checks #{', #'.join(str(id) for id in check.evidence_check_ids)}). Limited logging infrastructure needs expansion for comprehensive observability."
                else:
                    check.current_level = 1
                    check.explanation = "Minimal log collection detected. Basic logging may be present but lacks centralized collection mechanisms across AWS services."
            
            elif check.question_id == 2:  # How do you use logs?
                # Map to discovery checks for log usage
                metric_filters_check = next((c for c in self.results.discovery_checks if c.name == "Have you created metric filters to extract KPIs from logs?"), None)
                subscription_filters_check = next((c for c in self.results.discovery_checks if c.name == "What percentage of log groups have subscription filters for real-time processing?"), None)
                anomaly_detection_check = next((c for c in self.results.discovery_checks if c.name == "Have you enabled anomaly detection?"), None)
                
                check.evidence_check_ids = [c.id for c in [metric_filters_check, subscription_filters_check, anomaly_detection_check] if c]
                
                usage_capabilities = []
                if metric_filters_check and metric_filters_check.result and metric_filters_check.result.get('metricFilters'):
                    filter_count = len(metric_filters_check.result.get('metricFilters', []))
                    usage_capabilities.append(f"{filter_count} metric filters for automated monitoring")
                
                if subscription_filters_check and subscription_filters_check.result:
                    groups_with_filters = subscription_filters_check.result.get('groups_with_subscription_filters', 0)
                    if groups_with_filters > 0:
                        usage_capabilities.append(f"{groups_with_filters} log groups with subscription filters for real-time processing")
                
                if anomaly_detection_check and anomaly_detection_check.status == 'success':
                    usage_capabilities.append("log anomaly detection configured")
                
                if len(usage_capabilities) >= 3:
                    check.current_level = 3
                    check.explanation = f"Advanced log usage with {', '.join(usage_capabilities)} (Checks #{', #'.join(str(id) for id in check.evidence_check_ids)}). This enables automated correlation and anomaly detection, moving beyond structured queries to proactive log analysis with automated insights and correlation patterns."
                elif len(usage_capabilities) >= 2:
                    check.current_level = 2
                    check.explanation = f"Structured log usage with {', '.join(usage_capabilities)} (Checks #{', #'.join(str(id) for id in check.evidence_check_ids)}). This enables structured queries with faster analysis, moving beyond basic manual log searches to automated monitoring and alerting based on log patterns."
                elif len(usage_capabilities) >= 1:
                    check.current_level = 2
                    check.explanation = f"Basic structured log usage with {', '.join(usage_capabilities)} (Checks #{', #'.join(str(id) for id in check.evidence_check_ids)}). Foundation for log analysis and monitoring."
                else:
                    check.current_level = 1
                    check.explanation = "Log usage appears limited to basic manual searches and troubleshooting. No evidence of structured log analysis, automated monitoring patterns, or real-time log processing."
            
            elif check.question_id == 3:  # How do you access logs?
                # Map to discovery checks for log access
                log_groups_check = next((c for c in self.results.discovery_checks if c.name == "What percentage of your log groups are categorized by source type (Vended Logs, AWS Service Logs, Custom Logs)"), None)
                dashboards_check = next((c for c in self.results.discovery_checks if c.name == "CloudWatch Dashboards"), None)
                subscription_filters_check = next((c for c in self.results.discovery_checks if c.name == "What percentage of log groups have subscription filters for real-time processing?"), None)
                centralization_check = next((c for c in self.results.discovery_checks if c.name == "Have you implemented Cross-Account and Cross-Region Log Centralization?"), None)
                
                check.evidence_check_ids = [c.id for c in [log_groups_check, dashboards_check, subscription_filters_check, centralization_check] if c]
                
                access_mechanisms = []
                if log_groups_check and log_groups_check.result and log_groups_check.result.get('logGroups'):
                    log_count = len(log_groups_check.result.get('logGroups', []))
                    access_mechanisms.append(f"centralized access to {log_count} log groups")
                
                if dashboards_check and dashboards_check.result and dashboards_check.result.get('DashboardEntries'):
                    dashboard_count = len(dashboards_check.result.get('DashboardEntries', []))
                    access_mechanisms.append(f"{dashboard_count} dashboards for visualization")
                
                if subscription_filters_check and subscription_filters_check.result:
                    access_mechanisms.append("subscription filters for cross-service access")
                
                if centralization_check and centralization_check.status == 'success':
                    access_mechanisms.append("centralized logging infrastructure")
                
                if len(access_mechanisms) >= 3:
                    check.current_level = 3
                    check.explanation = f"Advanced log access with {', '.join(access_mechanisms)} (Checks #{', #'.join(str(id) for id in check.evidence_check_ids)}). This provides single pane correlation and anomaly detection capabilities with comprehensive enterprise-wide visibility and unified access patterns."
                elif len(access_mechanisms) >= 2:
                    check.current_level = 2
                    check.explanation = f"Enterprise-wide log access established through {', '.join(access_mechanisms)} (Checks #{', #'.join(str(id) for id in check.evidence_check_ids)}). This provides comprehensive visibility into application and infrastructure logs with appropriate access controls and visualization capabilities."
                elif len(access_mechanisms) >= 1:
                    check.current_level = 1
                    check.explanation = f"Basic centralized log access through {', '.join(access_mechanisms)} (Checks #{', #'.join(str(id) for id in check.evidence_check_ids)}). Foundation for enterprise visibility."
                else:
                    check.current_level = 1
                    check.explanation = "Log access appears fragmented across different systems without centralized management, unified access patterns, or comprehensive visualization capabilities."
            
            elif check.question_id == 4:  # What is your log retention policy?
                # Map to discovery checks for log retention
                log_groups_check = next((c for c in self.results.discovery_checks if c.name == "What percentage of your log groups are categorized by source type (Vended Logs, AWS Service Logs, Custom Logs)"), None)
                top_groups_retention_check = next((c for c in self.results.discovery_checks if c.name == "What percentage of log groups have retention policies aligned with your compliance requirements (security: 90+ days, operational: 30 days, debug: 7 days)?"), None)
                export_tasks_check = next((c for c in self.results.discovery_checks if c.name == "Log Export Tasks Per Log Group"), None)
                tags_check = next((c for c in self.results.discovery_checks if c.name == "Resource Tags"), None)
                
                check.evidence_check_ids = [c.id for c in [log_groups_check, top_groups_retention_check, export_tasks_check, tags_check] if c]
                
                retention_mechanisms = []
                
                # Check top 10 largest log groups retention policies
                if top_groups_retention_check and top_groups_retention_check.result:
                    groups_with_retention = top_groups_retention_check.result.get('groups_with_retention', 0)
                    total_size_gb = top_groups_retention_check.result.get('total_size_gb', 0)
                    if groups_with_retention > 0:
                        retention_mechanisms.append(f"retention policies on {groups_with_retention}/10 largest log groups ({total_size_gb:.1f} GB)")
                
                if log_groups_check and log_groups_check.result and log_groups_check.result.get('logGroups'):
                    # Check if log groups have retention policies
                    groups_with_retention = [lg for lg in log_groups_check.result.get('logGroups', []) if lg.get('retentionInDays')]
                    if groups_with_retention:
                        retention_mechanisms.append(f"retention policies on {len(groups_with_retention)} total log groups")
                
                if export_tasks_check and export_tasks_check.status == 'success':
                    retention_mechanisms.append("log export tasks for archival")
                
                if tags_check and tags_check.result and tags_check.result.get('ResourceTagMappingList'):
                    retention_mechanisms.append("resource tagging for governance")
                
                if len(retention_mechanisms) >= 2:
                    check.current_level = 2
                    check.explanation = f"Structured log retention approach with {', '.join(retention_mechanisms)} (Checks #{', #'.join(str(id) for id in check.evidence_check_ids)}). This indicates enterprise-wide compliance-based policies for log lifecycle management and cost optimization through automated archival strategies."
                elif len(retention_mechanisms) >= 1:
                    check.current_level = 2
                    check.explanation = f"Basic retention management with {', '.join(retention_mechanisms)} (Checks #{', #'.join(str(id) for id in check.evidence_check_ids)}). Foundation for compliance and cost control."
                else:
                    check.current_level = 1
                    check.explanation = "Log retention appears to use default settings without enterprise-wide policy coordination, compliance-driven retention strategies, or systematic cost optimization approaches."
                dashboards_check = next((c for c in self.results.discovery_checks if c.name == "CloudWatch Dashboards"), None)
                subscription_filters_check = next((c for c in self.results.discovery_checks if c.name == "What percentage of log groups have subscription filters for real-time processing?"), None)
                
                check.evidence_check_ids = [c.id for c in [log_groups_check, dashboards_check, subscription_filters_check] if c]
                
                access_mechanisms = []
                if log_groups_check and log_groups_check.result and log_groups_check.result.get('logGroups'):
                    log_count = len(log_groups_check.result.get('logGroups', []))
                    access_mechanisms.append(f"centralized access to {log_count} log groups")
                
                if dashboards_check and dashboards_check.result and dashboards_check.result.get('DashboardEntries'):
                    dashboard_count = len(dashboards_check.result.get('DashboardEntries', []))
                    access_mechanisms.append(f"{dashboard_count} dashboards for visualization")
                
                if subscription_filters_check and subscription_filters_check.result:
                    access_mechanisms.append("subscription filters for cross-service access")
                
                if len(access_mechanisms) >= 2:
                    check.current_level = 2
                    check.explanation = f"Enterprise-wide log access established through {', '.join(access_mechanisms)} (Checks #{', #'.join(str(id) for id in check.evidence_check_ids)}). This provides comprehensive visibility into application and infrastructure logs with appropriate access controls and visualization capabilities."
                elif len(access_mechanisms) >= 1:
                    check.current_level = 2
                    check.explanation = f"Centralized log access through {', '.join(access_mechanisms)} (Checks #{', #'.join(str(id) for id in check.evidence_check_ids)}). Good foundation for enterprise visibility."
                else:
                    check.current_level = 1
                    check.explanation = "Log access appears fragmented across different systems without centralized management, unified access patterns, or comprehensive visualization capabilities."
            
            elif check.question_id == 4:  # What is your log retention policy?
                # Required checks: CloudWatch retention settings, S3 lifecycle policies, Compliance tagging, Cost optimization
                log_groups_check = next((c for c in self.results.discovery_checks if c.name == "What percentage of your log groups are categorized by source type (Vended Logs, AWS Service Logs, Custom Logs)"), None)
                tags_check = next((c for c in self.results.discovery_checks if c.name == "Resource Tags"), None)
                
                check.evidence_check_ids = [c.id for c in [log_groups_check, tags_check] if c]
                
                retention_mechanisms = []
                
                if log_groups_check and log_groups_check.result and log_groups_check.result.get('logGroups'):
                    # Check if log groups have retention policies
                    groups_with_retention = [lg for lg in log_groups_check.result.get('logGroups', []) if lg.get('retentionInDays')]
                    if groups_with_retention:
                        retention_mechanisms.append(f"retention policies on {len(groups_with_retention)} log groups")
                
                if tags_check and tags_check.result and tags_check.result.get('ResourceTagMappingList'):
                    retention_mechanisms.append("resource tagging for governance")
                
                if len(retention_mechanisms) >= 2:
                    check.current_level = 2
                    check.explanation = f"Structured log retention approach with {', '.join(retention_mechanisms)} (Checks #{', #'.join(str(id) for id in check.evidence_check_ids)}). This indicates enterprise-wide compliance-based policies for log lifecycle management and cost optimization."
                elif len(retention_mechanisms) >= 1:
                    check.current_level = 2
                    check.explanation = f"Basic retention management with {', '.join(retention_mechanisms)} (Checks #{', #'.join(str(id) for id in check.evidence_check_ids)}). Foundation for compliance and cost control."
                else:
                    check.current_level = 1
                    check.explanation = "Log retention appears to use default settings without enterprise-wide policy coordination, compliance-driven retention strategies, or systematic cost optimization approaches."

    def assess_metrics_maturity(self):
        """Assess metrics maturity based on discovery checks"""
        metrics_checks = [c for c in self.results.assessment_checks if c.category == "Metrics"]
        
        for check in metrics_checks:
            if check.question_id == 5:  # What type of metrics do you collect?
                ec2_check = next((c for c in self.results.discovery_checks if c.name == "EC2 Instances"), None)
                custom_metrics_check = next((c for c in self.results.discovery_checks if c.name == "Are you publishing custom business and application metrics to CloudWatch?"), None)
                eks_check = next((c for c in self.results.discovery_checks if c.name == "EKS Clusters"), None)
                lambda_check = next((c for c in self.results.discovery_checks if c.name == "Lambda Functions"), None)
                
                check.evidence_check_ids = [c.id for c in [ec2_check, custom_metrics_check, eks_check, lambda_check] if c]
                
                has_infrastructure = any([
                    ec2_check and ec2_check.result and ec2_check.result.get('Reservations'),
                    eks_check and eks_check.result and eks_check.result.get('clusters'),
                    lambda_check and lambda_check.result and lambda_check.result.get('Functions')
                ])
                
                has_custom = custom_metrics_check and custom_metrics_check.result and isinstance(custom_metrics_check.result, dict) and any(
                    not m.get('Namespace', '').startswith('AWS/') 
                    for m in custom_metrics_check.result.get('Metrics', [])
                )
                
                if has_custom:
                    custom_count = len([m for m in custom_metrics_check.result.get('Metrics', []) 
                                      if not m.get('Namespace', '').startswith('AWS/')])
                    check.current_level = 3
                    check.explanation = f"Comprehensive metrics collection is implemented with infrastructure metrics from EC2, EKS, and Lambda services (Checks #{ec2_check.id if ec2_check else 'N/A'}, #{eks_check.id if eks_check else 'N/A'}, #{lambda_check.id if lambda_check else 'N/A'}), plus {custom_count} custom metrics (Check #{custom_metrics_check.id}). This indicates mature monitoring covering infrastructure, applications, and business-specific metrics."
                elif has_infrastructure:
                    check.current_level = 2
                    check.explanation = f"Infrastructure and application metrics are collected from multiple AWS services including EC2, EKS, and Lambda (Checks #{ec2_check.id if ec2_check else 'N/A'}, #{eks_check.id if eks_check else 'N/A'}, #{lambda_check.id if lambda_check else 'N/A'}). This provides good coverage of system performance and application health metrics."
                else:
                    check.current_level = 1
                    check.explanation = "Limited metrics collection detected, primarily basic infrastructure monitoring without comprehensive application or custom business metrics."
            
            elif check.question_id == 6:  # How do you use metrics?
                dashboards_check = next((c for c in self.results.discovery_checks if c.name == "CloudWatch Dashboards"), None)
                alarms_check = next((c for c in self.results.discovery_checks if c.name == "CloudWatch Alarms"), None)
                anomaly_check = next((c for c in self.results.discovery_checks if c.name == "Anomaly Detectors"), None)
                
                check.evidence_check_ids = [c.id for c in [dashboards_check, alarms_check, anomaly_check] if c]
                
                has_anomaly = anomaly_check and anomaly_check.result and anomaly_check.result.get('AnomalyDetectors')
                has_alarms = alarms_check and alarms_check.result and (alarms_check.result.get('MetricAlarms') or alarms_check.result.get('CompositeAlarms'))
                has_dashboards = dashboards_check and dashboards_check.result and dashboards_check.result.get('DashboardEntries')
                
                if has_anomaly:
                    anomaly_count = len(anomaly_check.result.get('AnomalyDetectors', []))
                    check.current_level = 4
                    check.explanation = f"Advanced metrics usage with AI/ML capabilities implemented through {anomaly_count} anomaly detectors (Check #{anomaly_check.id}), complemented by dashboards and alarms (Checks #{dashboards_check.id if dashboards_check else 'N/A'}, #{alarms_check.id if alarms_check else 'N/A'}). This enables proactive issue identification and automated anomaly detection."
                elif has_alarms and has_dashboards:
                    alarm_count = len(alarms_check.result.get('MetricAlarms', []) + alarms_check.result.get('CompositeAlarms', []))
                    dashboard_count = len(dashboards_check.result.get('DashboardEntries', []))
                    check.current_level = 2
                    check.explanation = f"Structured metrics usage with {dashboard_count} dashboards for operational visibility (Check #{dashboards_check.id}) and {alarm_count} alarms for reactive monitoring (Check #{alarms_check.id}). This provides good operational awareness and manual response capabilities."
                else:
                    check.current_level = 1
                    check.explanation = "Basic metrics usage limited to manual exploration and ad-hoc analysis without systematic dashboards or automated alerting."
            
            elif check.question_id == 7:  # How do you access metrics?
                metrics_check = None
                streams_check = next((c for c in self.results.discovery_checks if c.name == "Have you configured metric streams for real-time export to third-party tools or data lakes?"), None)
                
                check.evidence_check_ids = [c.id for c in [metrics_check, streams_check] if c]
                
                has_streams = streams_check and streams_check.result and streams_check.result.get('Entries')
                has_metrics = metrics_check and metrics_check.result and metrics_check.result.get('Metrics')
                
                if has_streams:
                    stream_count = len(streams_check.result.get('Entries', []))
                    check.current_level = 3
                    check.explanation = f"Advanced metrics access with {stream_count} metric streams configured (Check #{streams_check.id}), enabling real-time data export and correlation capabilities. This supports sophisticated analytics and cross-service correlation."
                elif has_metrics:
                    metric_count = len(metrics_check.result.get('Metrics', []))
                    check.current_level = 2
                    check.explanation = f"Centralized metrics access through CloudWatch with {metric_count} metrics available (Check #{metrics_check.id}), providing enterprise-wide visibility for analysis and troubleshooting across multiple services and applications."
                else:
                    check.current_level = 1
                    check.explanation = "Basic metrics access without centralized management or unified visibility across services."

    def assess_traces_maturity(self):
        """Assess traces maturity based on discovery checks"""
        traces_checks = [c for c in self.results.assessment_checks if c.category == "Traces"]
        
        for check in traces_checks:
            if check.question_id == 8:  # How do you collect traces?
                xray_check = next((c for c in self.results.discovery_checks if c.name == "X-Ray Service Map"), None)
                lambda_tracing_check = next((c for c in self.results.discovery_checks if c.name == "Lambda Tracing Config"), None)
                sampling_check = next((c for c in self.results.discovery_checks if c.name == "X-Ray Sampling Rules"), None)
                
                check.evidence_check_ids = [c.id for c in [xray_check, lambda_tracing_check, sampling_check] if c]
                
                has_service_map = xray_check and xray_check.result and xray_check.result.get('Services')
                has_sampling = sampling_check and sampling_check.result and sampling_check.result.get('SamplingRuleRecords')
                has_lambda_tracing = lambda_tracing_check and lambda_tracing_check.result and isinstance(lambda_tracing_check.result, dict) and any(
                    func.get('TracingConfig', {}).get('Mode') == 'Active' 
                    for func in lambda_tracing_check.result.get('Functions', [])
                )
                
                if has_service_map and has_sampling:
                    service_count = len(xray_check.result.get('Services', []))
                    rule_count = len(sampling_check.result.get('SamplingRuleRecords', []))
                    check.current_level = 3
                    check.explanation = f"Comprehensive tracing infrastructure with X-Ray service map showing {service_count} services (Check #{xray_check.id}) and {rule_count} sampling rules configured (Check #{sampling_check.id}). This provides end-to-end visibility with optimized trace collection and correlation capabilities across distributed services."
                elif has_service_map or has_lambda_tracing:
                    if has_service_map:
                        service_count = len(xray_check.result.get('Services', []))
                        check.current_level = 2
                        check.explanation = f"Active tracing implementation with X-Ray service map tracking {service_count} services (Check #{xray_check.id}). This indicates both auto-instrumentation and manual instrumentation are in use for distributed tracing."
                    else:
                        traced_functions = sum(1 for func in lambda_tracing_check.result.get('Functions', []) 
                                             if func.get('TracingConfig', {}).get('Mode') == 'Active') if isinstance(lambda_tracing_check.result, dict) else 0
                        check.current_level = 2
                        check.explanation = f"Tracing enabled for {traced_functions} Lambda functions (Check #{lambda_tracing_check.id}), indicating selective instrumentation for serverless workloads."
                else:
                    check.current_level = 1
                    check.explanation = "Limited or no distributed tracing detected. Basic auto-instrumented SDKs may be present but without comprehensive trace collection."
            
            elif check.question_id == 9:  # How do you use traces?
                xray_check = next((c for c in self.results.discovery_checks if c.name == "X-Ray Service Map"), None)
                insights_check = next((c for c in self.results.discovery_checks if c.name == "X-Ray Insights"), None)
                app_signals_check = next((c for c in self.results.discovery_checks if c.name == "Application Signals Services"), None)
                
                check.evidence_check_ids = [c.id for c in [xray_check, insights_check, app_signals_check] if c]
                
                has_app_signals = app_signals_check and app_signals_check.result and app_signals_check.result.get('Services')
                has_insights = insights_check and insights_check.result
                has_service_map = xray_check and xray_check.result and xray_check.result.get('Services')
                
                if has_app_signals:
                    service_count = len(app_signals_check.result.get('Services', []))
                    check.current_level = 4
                    check.explanation = f"Advanced trace analysis with Application Signals monitoring {service_count} services (Check #{app_signals_check.id}), providing cross-boundary insights and proactive root cause identification. This enables comprehensive correlation across application boundaries with automated issue detection."
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
                alarms_check = next((c for c in self.results.discovery_checks if c.name == "CloudWatch Alarms"), None)
                composite_check = next((c for c in self.results.discovery_checks if c.name == "Composite Alarms"), None)
                sns_check = next((c for c in self.results.discovery_checks if c.name == "SNS Topics"), None)
                anomaly_check = next((c for c in self.results.discovery_checks if c.name == "Anomaly Detectors"), None)
                
                check.evidence_check_ids = [c.id for c in [alarms_check, composite_check, anomaly_check] if c]
                
                has_composite = composite_check and composite_check.result and composite_check.result.get('CompositeAlarms')
                has_anomaly = anomaly_check and anomaly_check.result and anomaly_check.result.get('AnomalyDetectors')
                has_basic_alarms = alarms_check and alarms_check.result and alarms_check.result.get('MetricAlarms')
                
                if has_composite:
                    composite_count = len(composite_check.result.get('CompositeAlarms', []))
                    metric_count = len(alarms_check.result.get('MetricAlarms', [])) if alarms_check and alarms_check.result else 0
                    check.current_level = 4
                    check.explanation = f"Advanced alarm strategy with {composite_count} composite alarms (Check #{composite_check.id}) aggregating {metric_count} metric alarms (Check #{alarms_check.id if alarms_check else 'N/A'}). This creates summarized health indicators reducing alarm noise and enabling actions at an aggregated application level."
                elif has_anomaly and has_basic_alarms:
                    anomaly_count = len(anomaly_check.result.get('AnomalyDetectors', []))
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
                dashboards_check = next((c for c in self.results.discovery_checks if c.name == "CloudWatch Dashboards"), None)
                
                check.evidence_check_ids = [c.id for c in [dashboards_check] if c]
                
                has_dashboards = dashboards_check and dashboards_check.result and dashboards_check.result.get('DashboardEntries')
                
                if has_dashboards:
                    dashboard_count = len(dashboards_check.result.get('DashboardEntries', []))
                    if dashboard_count >= 5:
                        check.current_level = 3
                        check.explanation = f"Advanced dashboard usage with {dashboard_count} dashboards (Check #{dashboards_check.id}) providing comprehensive operational visibility. Multiple dashboards suggest systematic approach to visualization with potential for correlation and anomaly detection across different services and metrics."
                    else:
                        check.current_level = 2
                        check.explanation = f"Operational dashboards implemented with {dashboard_count} CloudWatch dashboards (Check #{dashboards_check.id}), providing single pane of glass visibility into various data sources. This enables faster communication flow during operational events with well-defined visualization criteria."
                else:
                    check.current_level = 1
                    check.explanation = "Limited dashboard usage, primarily basic resource monitoring without comprehensive operational visibility or systematic visualization strategies."
            
            elif check.question_id == 12:  # How adaptive are your alarm thresholds?
                anomaly_check = next((c for c in self.results.discovery_checks if c.name == "Anomaly Detectors"), None)
                alarms_check = next((c for c in self.results.discovery_checks if c.name == "CloudWatch Alarms"), None)
                
                check.evidence_check_ids = [c.id for c in [anomaly_check, alarms_check] if c]
                
                has_anomaly = anomaly_check and anomaly_check.result and anomaly_check.result.get('AnomalyDetectors')
                has_alarms = alarms_check and alarms_check.result and alarms_check.result.get('MetricAlarms')
                
                if has_anomaly:
                    anomaly_count = len(anomaly_check.result.get('AnomalyDetectors', []))
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
                tags_check = next((c for c in self.results.discovery_checks if c.name == "Resource Tags"), None)
                
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
                # This is typically assessed through tool consolidation and cost optimization evidence
                dashboards_check = next((c for c in self.results.discovery_checks if c.name == "CloudWatch Dashboards"), None)
                alarms_check = next((c for c in self.results.discovery_checks if c.name == "CloudWatch Alarms"), None)
                
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
                anomaly_check = next((c for c in self.results.discovery_checks if c.name == "Anomaly Detectors"), None)
                
                check.evidence_check_ids = [c.id for c in [anomaly_check] if c]
                
                has_anomaly = anomaly_check and anomaly_check.result and anomaly_check.result.get('AnomalyDetectors')
                
                if has_anomaly:
                    anomaly_count = len(anomaly_check.result.get('AnomalyDetectors', []))
                    check.current_level = 3
                    check.explanation = f"Active AI/ML capabilities with {anomaly_count} CloudWatch anomaly detectors (Check #{anomaly_check.id}), providing automatic correlation and pattern detection for proactive monitoring and alerting."
                else:
                    check.current_level = 1
                    check.explanation = "No AI/ML features detected in the observability stack. Reliance on traditional threshold-based monitoring without machine learning capabilities."
            
            elif check.question_id == 17:  # Do you have real end-user monitoring?
                rum_check = next((c for c in self.results.discovery_checks if c.name == "RUM Applications"), None)
                synthetics_check = next((c for c in self.results.discovery_checks if c.name == "CloudWatch Synthetics Canaries"), None)
                
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
    
    args = parser.parse_args()
    
    assessment = ComprehensiveObservabilityAssessment(profile=args.profile, region=args.region)
    
    if args.single_check:
        assessment.run_single_check(args.single_check)
    else:
        assessment.run_assessment()

if __name__ == "__main__":
    main()
