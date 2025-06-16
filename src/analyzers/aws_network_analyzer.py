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

    # Example check: Is VPC CIDR block too large (like /8)?
    cidr_block = vpc.get("CidrBlock", "")
    if cidr_block.startswith("10."):
        # just an example condition; you can refine this
        findings.append(NetworkFinding(
            resource_id=vpc_id,
            issue=f"VPC CIDR block is large: {cidr_block}",
            severity="medium"
        ))

    return findings

def analyze_subnet(subnet: dict) -> List[NetworkFinding]:
    findings = []
    subnet_id = subnet.get("SubnetId", "unknown")
    # Example check: Public subnet without proper tagging or route table
    if subnet.get("MapPublicIpOnLaunch") is True:
        findings.append(NetworkFinding(
            resource_id=subnet_id,
            issue="Subnet is public (MapPublicIpOnLaunch=True)",
            severity="high"
        ))
    return findings

def analyze_network(resources: dict) -> List[NetworkFinding]:
    findings = []
    vpcs = resources.get("Vpcs", [])
    subnets = resources.get("Subnets", [])

    for vpc in vpcs:
        findings.extend(analyze_vpc(vpc))
    for subnet in subnets:
        findings.extend(analyze_subnet(subnet))

    return findings
