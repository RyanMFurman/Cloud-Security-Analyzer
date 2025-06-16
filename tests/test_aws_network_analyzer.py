import pytest
from src.analyzers.aws_network_analyzer import (
    analyze_vpc,
    analyze_subnet,
    analyze_network,
    analyze_route_table,
    analyze_internet_gateway,
    analyze_nat_gateway,
    analyze_network_acl,
    NetworkFinding
)

def test_analyze_vpc_detects_large_cidr():
    vpc = {
        "VpcId": "vpc-123",
        "CidrBlock": "10.0.0.0/8"
    }
    findings = analyze_vpc(vpc)
    assert any(f.issue.startswith("VPC CIDR block") for f in findings)
    assert all(isinstance(f, NetworkFinding) for f in findings)

def test_analyze_subnet_detects_public_subnet():
    subnet = {
        "SubnetId": "subnet-456",
        "MapPublicIpOnLaunch": True
    }
    findings = analyze_subnet(subnet)
    assert any("public" in f.issue.lower() for f in findings)
    assert all(isinstance(f, NetworkFinding) for f in findings)

def test_analyze_network_combines_findings():
    resources = {
        "Vpcs": [{"VpcId": "vpc-1", "CidrBlock": "10.0.0.0/8"}],
        "Subnets": [{"SubnetId": "subnet-1", "MapPublicIpOnLaunch": True}]
    }
    findings = analyze_network(resources)
    assert len(findings) >= 2
    assert all(isinstance(f, NetworkFinding) for f in findings)

def test_analyze_route_table_detects_public_route():
    route_table = {
        "RouteTableId": "rtb-123",
        "Routes": [
            {"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-456"},
            {"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local"}
        ]
    }
    findings = analyze_route_table(route_table)
    assert any("default route to internet gateway" in f.issue.lower() for f in findings)
    assert all(isinstance(f, NetworkFinding) for f in findings)

def test_analyze_internet_gateway_detects_detached():
    igw = {
        "InternetGatewayId": "igw-789",
        "Attachments": []
    }
    findings = analyze_internet_gateway(igw)
    assert any("not attached" in f.issue.lower() for f in findings)
    assert all(isinstance(f, NetworkFinding) for f in findings)

def test_analyze_nat_gateway_detects_non_available_state():
    nat_gw = {
        "NatGatewayId": "nat-123",
        "State": "pending",
        "SubnetId": "subnet-789",
        "NatGatewayAddresses": [{"AllocationId": "eipalloc-123"}]
    }
    findings = analyze_nat_gateway(nat_gw)
    assert any("state 'pending'" in f.issue.lower() for f in findings)
    assert all(isinstance(f, NetworkFinding) for f in findings)

def test_analyze_nat_gateway_detects_missing_eip():
    nat_gw = {
        "NatGatewayId": "nat-124",
        "State": "available",
        "SubnetId": "subnet-790",
        "NatGatewayAddresses": []
    }
    findings = analyze_nat_gateway(nat_gw)
    assert any("no associated elastic ip address" in f.issue.lower() for f in findings)
    assert all(isinstance(f, NetworkFinding) for f in findings)

def test_analyze_network_acl_detects_open_inbound():
    nacl = {
        "NetworkAclId": "acl-123",
        "Entries": [
            {
                "Egress": False,
                "CidrBlock": "0.0.0.0/0",
                "Protocol": "-1",
                "RuleAction": "allow"
            }
        ]
    }
    findings = analyze_network_acl(nacl)
    assert any("allows all traffic (ingress)" in f.issue.lower() for f in findings)
    assert all(isinstance(f, NetworkFinding) for f in findings)
