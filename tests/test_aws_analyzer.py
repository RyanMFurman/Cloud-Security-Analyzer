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
