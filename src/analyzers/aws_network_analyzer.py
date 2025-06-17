import boto3
from typing import List
from dataclasses import dataclass
from src.analyzers.aws_analyzer import SecurityFinding

# --- Analysis Functions ---

def analyze_vpc(vpc: dict) -> List[SecurityFinding]:
    findings = []
    vpc_id = vpc.get("VpcId", "unknown")
    cidr_block = vpc.get("CidrBlock", "")
    if cidr_block.startswith("10."):
        findings.append(SecurityFinding(
            resource_id=vpc_id,
            description=f"VPC CIDR block is large: {cidr_block}",
            risk_level="MEDIUM",
            recommendation="Consider narrowing CIDR range if possible"
        ))
    return findings

def analyze_subnet(subnet: dict) -> List[SecurityFinding]:
    findings = []
    subnet_id = subnet.get("SubnetId", "unknown")
    if subnet.get("MapPublicIpOnLaunch") is True:
        findings.append(SecurityFinding(
            resource_id=subnet_id,
            description="Subnet is public (MapPublicIpOnLaunch=True)",
            risk_level="HIGH",
            recommendation="Restrict public IP mapping unless necessary"
        ))
    return findings

def analyze_route_table(route_table: dict) -> List[SecurityFinding]:
    findings = []
    rt_id = route_table.get("RouteTableId", "unknown")
    routes = route_table.get("Routes", [])

    for route in routes:
        dest_cidr = route.get("DestinationCidrBlock", "")
        dest_cidr_ipv6 = route.get("DestinationIpv6CidrBlock", "")
        gateway_id = route.get("GatewayId", "")
        nat_gw_id = route.get("NatGatewayId", "")

        if dest_cidr == "0.0.0.0/0" or dest_cidr_ipv6 == "::/0":
            if gateway_id.startswith("igw-"):
                findings.append(SecurityFinding(
                    resource_id=rt_id,
                    description="Route table has default route to Internet Gateway (public subnet)",
                    risk_level="HIGH",
                    recommendation="Limit default route to trusted resources"
                ))
            elif nat_gw_id:
                findings.append(SecurityFinding(
                    resource_id=rt_id,
                    description="Route table has default route to NAT Gateway (private subnet with outbound internet)",
                    risk_level="MEDIUM",
                    recommendation="Ensure NAT routing is secured and monitored"
                ))
            else:
                findings.append(SecurityFinding(
                    resource_id=rt_id,
                    description="Route table has default route to unknown target",
                    risk_level="MEDIUM",
                    recommendation="Verify unknown routing targets"
                ))
    return findings

def analyze_internet_gateway(internet_gateway: dict) -> List[SecurityFinding]:
    findings = []
    igw_id = internet_gateway.get("InternetGatewayId", "unknown")
    attachments = internet_gateway.get("Attachments", [])

    if not attachments:
        findings.append(SecurityFinding(
            resource_id=igw_id,
            description="Internet Gateway is not attached to any VPC",
            risk_level="HIGH",
            recommendation="Delete unattached IGWs to reduce surface area"
        ))
    else:
        for attach in attachments:
            state = attach.get("State", "")
            vpc_id = attach.get("VpcId", "unknown")
            if state != "available":
                findings.append(SecurityFinding(
                    resource_id=igw_id,
                    description=f"Internet Gateway attached to VPC {vpc_id} is in state '{state}'",
                    risk_level="MEDIUM",
                    recommendation="Investigate IGWs not in 'available' state"
                ))
    return findings

def analyze_nat_gateway(nat_gateway: dict) -> List[SecurityFinding]:
    findings = []
    nat_id = nat_gateway.get("NatGatewayId", "unknown")
    state = nat_gateway.get("State", "")
    subnet_id = nat_gateway.get("SubnetId", "unknown")

    if state != "available":
        findings.append(SecurityFinding(
            resource_id=nat_id,
            description=f"NAT Gateway in subnet {subnet_id} is in state '{state}'",
            risk_level="MEDIUM",
            recommendation="Verify NAT Gateway deployment state"
        ))

    addresses = nat_gateway.get("NatGatewayAddresses", [])
    if not addresses:
        findings.append(SecurityFinding(
            resource_id=nat_id,
            description="NAT Gateway has no associated Elastic IP address",
            risk_level="HIGH",
            recommendation="Ensure NAT Gateway has valid public IPs"
        ))
    return findings

def analyze_network_acl(network_acl: dict) -> List[SecurityFinding]:
    findings = []
    acl_id = network_acl.get("NetworkAclId", "unknown")
    entries = network_acl.get("Entries", [])

    for entry in entries:
        rule_action = entry.get("RuleAction", "")
        cidr_block = entry.get("CidrBlock", "")
        egress = entry.get("Egress", False)

        if rule_action == "allow" and cidr_block == "0.0.0.0/0":
            direction = "egress" if egress else "ingress"
            findings.append(SecurityFinding(
                resource_id=acl_id,
                description=f"Network ACL allows all traffic ({direction})",
                risk_level="HIGH",
                recommendation="Restrict overly permissive ACL rules"
            ))
    return findings

def analyze_network(resources: dict) -> List[SecurityFinding]:
    findings = []
    for vpc in resources.get("Vpcs", []):
        findings.extend(analyze_vpc(vpc))
    for subnet in resources.get("Subnets", []):
        findings.extend(analyze_subnet(subnet))
    for rt in resources.get("RouteTables", []):
        findings.extend(analyze_route_table(rt))
    for igw in resources.get("InternetGateways", []):
        findings.extend(analyze_internet_gateway(igw))
    for nat in resources.get("NatGateways", []):
        findings.extend(analyze_nat_gateway(nat))
    for acl in resources.get("NetworkAcls", []):
        findings.extend(analyze_network_acl(acl))
    return findings
