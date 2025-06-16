from src.analyzers.aws_analyzer import identify_risks, is_risky_rule, SecurityFinding

def test_identify_risks_returns_findings():
    findings = identify_risks()
    assert isinstance(findings, list)
    for f in findings:
        assert isinstance(f, SecurityFinding)

def test_is_risky_rule_detects_open_port_22():
    rule = {
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        "FromPort": 22,
        "ToPort": 22,
        "IpProtocol": "tcp"
    }
    assert is_risky_rule(rule) is True

def test_is_risky_rule_returns_false_for_safe_rule():
    rule = {
        "IpRanges": [{"CidrIp": "10.0.0.0/16"}],
        "FromPort": 22,
        "ToPort": 22,
        "IpProtocol": "tcp"
    }
    assert is_risky_rule(rule) is False

def test_is_risky_rule_detects_open_port_22_ipv6():
    rule = {
        "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
        "FromPort": 22,
        "ToPort": 22,
        "IpProtocol": "tcp"
    }
    assert is_risky_rule(rule) is True

def test_is_risky_rule_detects_open_udp_port_53():
    rule = {
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        "FromPort": 53,
        "ToPort": 53,
        "IpProtocol": "udp"
    }
    assert is_risky_rule(rule) is True

def test_is_risky_rule_detects_open_mysql_port():
    rule = {
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        "FromPort": 3306,
        "ToPort": 3306,
        "IpProtocol": "tcp"
    }
    assert is_risky_rule(rule) is True

def test_is_risky_rule_all_ports_for_protocol_open():
    rule = {
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        "FromPort": None,
        "ToPort": None,
        "IpProtocol": "tcp"
    }
    assert is_risky_rule(rule) is True

def test_is_risky_rule_open_all_protocols_and_ports():
    rule = {
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        "FromPort": None,
        "ToPort": None,
        "IpProtocol": "-1"
    }
    assert is_risky_rule(rule) is True
