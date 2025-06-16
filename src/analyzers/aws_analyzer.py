"""
AWS Security Group Analyzer
Scans for risky security group rules and generates compliance reports
"""

import logging
from dataclasses import dataclass
from typing import List
import pandas as pd
import boto3

# Configure logging to show timestamps and severity levels
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

@dataclass
class SecurityFinding:
    """
    Data class representing a security vulnerability finding
    Args:
        resource_id: AWS resource ID (e.g., sg-123456)
        risk_level: HIGH/MEDIUM/LOW based on potential impact
        description: Vulnerability details
        recommendation: Suggested remediation steps
    """
    resource_id: str
    risk_level: str
    description: str
    recommendation: str = "Review and restrict permissions"

class AWSSecurityAnalyzer:
    """Main scanner class for AWS security groups and IAM policies"""
    
    def __init__(self, region='us-east-1'):
        """
        Initialize AWS clients
        Args:
            region: AWS region to scan (default: us-east-1)
        """
        self.ec2 = boto3.client('ec2', region_name=region)
        
    def find_over_permissive_rules(self) -> List[SecurityFinding]:
        """
        Finds security groups allowing open internet access (0.0.0.0/0)
        Returns:
            List of SecurityFinding objects for risky rules
        """
        findings = []
        
        try:
            sgs = self.ec2.describe_security_groups()
            for sg in sgs['SecurityGroups']:
                for perm in sg['IpPermissions']:
                    for ip_range in perm.get('IpRanges', []):
                        if ip_range['CidrIp'] == '0.0.0.0/0':
                            port_range = (
                                f"{perm['FromPort']}" 
                                if perm['FromPort'] == perm['ToPort'] 
                                else f"{perm['FromPort']}-{perm['ToPort']}"
                            )
                            
                            findings.append(
                                SecurityFinding(
                                    resource_id=sg['GroupId'],
                                    risk_level="HIGH",
                                    description=f"Open access on port {port_range} ({perm['IpProtocol']}) to internet",
                                    recommendation="Restrict to specific IP ranges"
                                )
                            )
            logging.info(f"Scanned {len(sgs['SecurityGroups'])} security groups")
            
        except Exception as e:
            logging.error(f"Permission scan failed: {str(e)}")
            
        return findings

    def find_unused_security_groups(self) -> List[SecurityFinding]:
        """
        Identifies security groups not attached to any EC2 instances
        Returns:
            List of SecurityFinding objects for unused groups
        """
        findings = []
        try:
            # Get all security groups
            all_sgs = {sg['GroupId'] for sg in self.ec2.describe_security_groups()['SecurityGroups']}
            
            # Get security groups in use
            used_sgs = set()
            reservations = self.ec2.describe_instances()['Reservations']
            for res in reservations:
                for instance in res['Instances']:
                    used_sgs.update(sg['GroupId'] for sg in instance.get('SecurityGroups', []))
            
            # Create findings for unused groups
            unused = all_sgs - used_sgs
            findings = [
                SecurityFinding(
                    resource_id=sg_id,
                    risk_level="LOW",
                    description="Security group not attached to any instances",
                    recommendation="Delete if no longer needed"
                ) for sg_id in unused
            ]
            logging.info(f"Found {len(unused)} unused security groups")
            
        except Exception as e:
            logging.error(f"Unused SG scan failed: {str(e)}")
            
        return findings

    def find_over_permissive_iam_policies(self) -> List[SecurityFinding]:
        """
        Finds IAM policies that allow full administrative access (*)
        Returns:
            List of SecurityFinding objects for risky IAM policies
        """
        iam = boto3.client('iam')
        findings = []

        try:
            paginator = iam.get_paginator('list_policies')
            for page in paginator.paginate(Scope='Local'):
                for policy in page['Policies']:
                    policy_arn = policy['Arn']
                    version = iam.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=policy['DefaultVersionId']
                    )
                    doc = version['PolicyVersion']['Document']

                    statements = doc.get('Statement', [])
                    if not isinstance(statements, list):
                        statements = [statements]

                    for statement in statements:
                        effect = statement.get('Effect')
                        action = statement.get('Action')
                        if effect == 'Allow':
                            if action == '*' or (isinstance(action, list) and '*' in action):
                                findings.append(
                                    SecurityFinding(
                                        resource_id=policy_arn,
                                        risk_level='HIGH',
                                        description='IAM Policy allows full administrative access (*)',
                                        recommendation='Restrict policy permissions to least privilege'
                                    )
                                )
        except Exception as e:
            logging.error(f"IAM policy analysis failed: {str(e)}")

        return findings

def generate_csv_report(findings: List[SecurityFinding], filename="aws_findings.csv"):
    """
    Generates CSV report from security findings
    Args:
        findings: List of SecurityFinding objects
        filename: Output CSV file path
    """
    if not findings:
        logging.info("No findings to report")
        return
    
    report_data = [ {
        'Resource ID': f.resource_id,
        'Risk Level': f.risk_level,
        'Description': f.description,
        'Recommendation': f.recommendation,
        'PCI Violation': 'YES' if f.risk_level == "HIGH" else 'NO'  # Compliance tagging
    } for f in findings]
    
    pd.DataFrame(report_data).to_csv(filename, index=False)
    logging.info(f"Report generated: {filename}")

def print_network_topology(findings: List[SecurityFinding]):
    """
    Generates ASCII visualization of network structure with risk indicators
    Args:
        findings: List of SecurityFinding objects to highlight risks
    """
    if not findings:
        return
    
    ec2 = boto3.client('ec2')
    try:
        vpcs = ec2.describe_vpcs()['Vpcs']
        subnets = ec2.describe_subnets()['Subnets']
        
        print("\n" + "="*50)
        print("LIVE NETWORK TOPOLOGY")
        print("="*50)
        
        # Build risk map for quick lookup
        risk_map = {f.resource_id: f for f in findings}
        
        for vpc in vpcs:
            vpc_name = next(
                (tag['Value'] for tag in vpc.get('Tags', []) if tag['Key'] == 'Name'),
                'unnamed'
            )
            print(f"\nVPC: {vpc_name} ({vpc['VpcId']})")
            
            # Categorize subnets
            public = [s for s in subnets if s['VpcId'] == vpc['VpcId'] and s.get('MapPublicIpOnLaunch')]
            private = [s for s in subnets if s['VpcId'] == vpc['VpcId'] and not s.get('MapPublicIpOnLaunch')]
            
            print("Internet")
            print("   │")
            print("   ├── [Public Subnets]")
            for subnet in public:
                print(f"   │   ├── {subnet['SubnetId']}")
                # Check for associated risky SGs
                if subnet.get('SubnetId') in risk_map:
                    finding = risk_map[subnet['SubnetId']]
                    print(f"   │   │   ⚠️ {finding.resource_id} ({finding.risk_level})")
            
            print("   │")
            print("   └── [Private Subnets]")
            for subnet in private:
                print(f"       ├── {subnet['SubnetId']}")
                
    except Exception as e:
        logging.error(f"Topology generation failed: {str(e)}")

def identify_risks():
    analyzer = AWSSecurityAnalyzer()
    findings = []
    findings.extend(analyzer.find_over_permissive_rules())
    findings.extend(analyzer.find_unused_security_groups())
    findings.extend(analyzer.find_over_permissive_iam_policies())
    return findings

def is_risky_rule(rule):
    """
    Determines if a given rule is risky (open to 0.0.0.0/0 on common ports).
    For testing purposes, expects a dict in the format of EC2 IpPermissions.
    """
    cidrs = [r.get("CidrIp") for r in rule.get("IpRanges", [])]
    open_to_world = "0.0.0.0/0" in cidrs

    risky_ports = [22, 3389, 80, 443]
    from_port = rule.get("FromPort")
    to_port = rule.get("ToPort")

    risky_port = any(
        from_port <= port <= to_port for port in risky_ports
    ) if from_port is not None and to_port is not None else False

    return open_to_world and risky_port

if __name__ == "__main__":
    """Main execution flow"""
    print("=== AWS Security Analyzer ===")
    analyzer = AWSSecurityAnalyzer()
    
    findings = []
    findings.extend(analyzer.find_over_permissive_rules())
    findings.extend(analyzer.find_unused_security_groups())
    findings.extend(analyzer.find_over_permissive_iam_policies())
    
    generate_csv_report(findings)
    
    if not findings:
        print("✅ No security issues found")
    else:
        print("\n🔴 Security Findings:")
        for finding in findings:
            print(f"[{finding.risk_level}] {finding.resource_id}")
            print(f"   - {finding.description}")
            print(f"   - Recommendation: {finding.recommendation}\n")
    
    print_network_topology(findings)
    
    print("=== Scan completed ===")
