import boto3
from src.analyzers.aws_analyzer import AWSSecurityAnalyzer, generate_csv_report, print_network_topology
from src.analyzers.aws_network_analyzer import analyze_network as analyze_network_resources
from src.reporting.csv_reporter import generate_csv_report as generate_network_report

def main():
    print("=== AWS Security Analyzer ===")
    
    # 1. Run Security Group + IAM Findings (Class-based)
    analyzer = AWSSecurityAnalyzer()
    findings = []
    findings.extend(analyzer.find_over_permissive_rules())
    findings.extend(analyzer.find_unused_security_groups())
    findings.extend(analyzer.find_over_permissive_iam_policies())

    # 2. Run Network Resource Analysis (analyze_network_resources expects a resource dict)
    ec2 = boto3.client('ec2')
    network_resources = {
        "Vpcs": ec2.describe_vpcs()['Vpcs'],
        "Subnets": ec2.describe_subnets()['Subnets'],
        "RouteTables": ec2.describe_route_tables()['RouteTables'],
        "InternetGateways": ec2.describe_internet_gateways()['InternetGateways'],
        "NatGateways": ec2.describe_nat_gateways()['NatGateways'],
        "NetworkAcls": ec2.describe_network_acls()['NetworkAcls']
    }
    network_findings = analyze_network_resources(network_resources)

    # 3. Combine both
    all_findings = findings + network_findings

    # 4. Export report
    generate_csv_report(all_findings)

    # 5. Print findings
    if not all_findings:
        print("✅ No security issues found")
    else:
        print("\n🔴 Security Findings:")
        for f in all_findings:
            print(f"[{f.risk_level}] {f.resource_id}")
            print(f"   - {f.description}")
            print(f"   - Recommendation: {f.recommendation}\n")

    print_network_topology(all_findings)
    print("=== Scan completed ===")

if __name__ == "__main__":
    main()
