# aws-iam-security-auditor
## 🛡️Project Overview

The AWS IAM Security Auditor is a Python-based Governance, Risk, and Compliance (GRC) tool designed to programmatically evaluate an AWS account's identity security posture. By leveraging the Boto3 SDK, the script identifies high-risk configurations that lead to Account Takeovers (ATO) and unauthorized privilege escalation.

## 🔑Key Features & Security Logic
1. MFA Compliance Audit
   Identifies IAM users lacking Multi-Factor Authentication (MFA). In a zero-trust environment, MFA is the primary defense against credential-stuffing attacks.
3. Credential Lifecycle Management
   Calculates the age of all active IAM Access Keys. The tool flags any key exceeding the 90-day rotation threshold, satisfying compliance requirements for frameworks like SOC2 and PCI-DSS.
```math
  | Formula: Age_{days} = \text{Current Time}_{UTC} - \text{Key Creation Date}_{UTC}
```
5. Deep-Inspection Privilege Audit
   Solves the "Visibility Gap" in standard auditing by inspecting both direct policy attachments and group-based inheritance. It specifically hunts for the AdministratorAccess managed policy to ensure the Principle of Least Privilege (PoLP) is maintained.

## 📊Sample JSON Output
The tool generates machine-readable reports suitable for ingestion into SIEM platforms or automated remediation pipelines.

```JSON
{
    "audit_metadata": {
        "timestamp": "2026-04-29T12:00:00Z",
        "account_id": "123456789012"
    },
    "findings": {
        "mfa_compliance": [
            { "user": "admin-user", "mfa_enabled": true, "status": "PASS" },
            { "user": "service-bot", "mfa_enabled": false, "status": "FAIL" }
        ]
    }
}
```

## 🛠️Setup & Usage
Clone the repository:
```Bash
git clone https://github.com/yourusername/aws-iam-auditor.git
```
Install dependencies:
```Bash
pip install -r requirements.txt
```
Configure AWS Credentials: Ensure your environment is configured via aws configure.
Run the Audit:
```Bash
python auditor.py
```
