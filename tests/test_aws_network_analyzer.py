import pytest
from src.analyzers.aws_network_analyzer import analyze_vpc, analyze_subnet, analyze_network, NetworkFinding

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

def test_analyze_network_combines_findings():
    resources = {
        "Vpcs": [{"VpcId": "vpc-1", "CidrBlock": "10.0.0.0/8"}],
        "Subnets": [{"SubnetId": "subnet-1", "MapPublicIpOnLaunch": True}]
    }
    findings = analyze_network(resources)
    assert len(findings) >= 2
    assert all(isinstance(f, NetworkFinding) for f in findings)
