# src/reporting/csv_reporter.py
import pandas as pd
from typing import List
from ..analyzers.aws_analyzer import SecurityFinding

# Update generate_csv_report() in aws_analyzer.py
def generate_csv_report(findings: List[SecurityFinding], filename="aws_findings.csv"):
    if not findings:
        return
    
    report_data = []
    for f in findings:
        # Add compliance flags
        pci_violation = "YES" if "0.0.0.0/0" in f.description else "NO"
        soc2_violation = "YES" if f.risk_level == "HIGH" else "NO"
        
        report_data.append({
            'Resource ID': f.resource_id,
            'Risk Level': f.risk_level,
            'Description': f.description,
            'Recommendation': f.recommendation,
            'PCI-DSS Violation': pci_violation,  # New
            'SOC2 Violation': soc2_violation,     # New
            'Severity Score': 3 if f.risk_level == "HIGH" else 1  # New
        })
    
    pd.DataFrame(report_data).to_csv(filename, index=False)
    print(f"Enhanced report generated: {filename}")