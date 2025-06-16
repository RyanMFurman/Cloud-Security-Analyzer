from typing import List
from dataclasses import dataclass

@dataclass
class NetworkFinding:
    resource_id: str
    issue: str
    severity: str

def analyze_vpc(vpc: dict) -> List[NetworkFinding]:
    findings = []
    vpc_id = vpc.get("VpcId", "unknown")
    cidr_block = vpc.get("CidrBlock", "")
    if cidr_block.startswith("10."):
        findings.append(NetworkFinding(
            resource_id=vpc_id,
            issue=f"VPC CIDR block is large: {cidr_block}",
            severity="medium"
        ))
    return findings

def analyze_subnet(subnet: dict) -> List[NetworkFinding]:
    findings = []
    subnet_id = subnet.get("SubnetId", "unknown")
    if subnet.get("MapPublicIpOnLaunch") is True:
        findings.append(NetworkFinding(
            resource_id=subnet_id,
            issue="Subnet is public (MapPublicIpOnLaunch=True)",
            severity="high"
        ))
    return findings

def analyze_route_table(route_table: dict) -> List[NetworkFinding]:
    findings = []
    rt_id = route_table.get("RouteTableId", "unknown")
    routes = route_table.get("Routes", [])

    for route in routes:
        dest_cidr = route.get("DestinationCidrBlock", "")
        gateway_id = route.get("GatewayId", "")
        nat_gw_id = route.get("NatGatewayId", "")

        if dest_cidr == "0.0.0.0/0":
            if gateway_id.startswith("igw-"):
                findings.append(NetworkFinding(
                    resource_id=rt_id,
                    issue="Route table has default route to Internet Gateway (public subnet)",
                    severity="high"
                ))
            elif nat_gw_id:
                findings.append(NetworkFinding(
                    resource_id=rt_id,
                    issue="Route table has default route to NAT Gateway (private subnet with outbound internet)",
                    severity="medium"
                ))
            else:
                findings.append(NetworkFinding(
                    resource_id=rt_id,
                    issue="Route table has default route to unknown target",
                    severity="medium"
                ))

    return findings

def analyze_internet_gateway(internet_gateway: dict) -> List[NetworkFinding]:
    findings = []
    igw_id = internet_gateway.get("InternetGatewayId", "unknown")
    attachments = internet_gateway.get("Attachments", [])

    if not attachments:
        findings.append(NetworkFinding(
            resource_id=igw_id,
            issue="Internet Gateway is not attached to any VPC",
            severity="high"
        ))
    else:
        for attach in attachments:
            state = attach.get("State", "")
            vpc_id = attach.get("VpcId", "unknown")
            if state != "available":
                findings.append(NetworkFinding(
                    resource_id=igw_id,
                    issue=f"Internet Gateway attached to VPC {vpc_id} is in state '{state}'",
                    severity="medium"
                ))
    return findings

def analyze_nat_gateway(nat_gateway: dict) -> List[NetworkFinding]:
    findings = []
    nat_id = nat_gateway.get("NatGatewayId", "unknown")
    state = nat_gateway.get("State", "")
    subnet_id = nat_gateway.get("SubnetId", "unknown")

    if state != "available":
        findings.append(NetworkFinding(
            resource_id=nat_id,
            issue=f"NAT Gateway in subnet {subnet_id} is in state '{state}'",
            severity="medium"
        ))

    addresses = nat_gateway.get("NatGatewayAddresses", [])
    if not addresses:
        findings.append(NetworkFinding(
            resource_id=nat_id,
            issue="NAT Gateway has no associated Elastic IP address",
            severity="high"
        ))
    return findings

def analyze_network_acl(network_acl: dict) -> List[NetworkFinding]:
    findings = []
    acl_id = network_acl.get("NetworkAclId", "unknown")
    entries = network_acl.get("Entries", [])

    for entry in entries:
        rule_action = entry.get("RuleAction", "")
        cidr_block = entry.get("CidrBlock", "")
        egress = entry.get("Egress", False)

        if rule_action == "allow" and cidr_block == "0.0.0.0/0":
            direction = "egress" if egress else "ingress"
            findings.append(NetworkFinding(
                resource_id=acl_id,
                issue=f"Network ACL allows all traffic ({direction})",
                severity="high"
            ))
    return findings

def analyze_network(resources: dict) -> List[NetworkFinding]:
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
