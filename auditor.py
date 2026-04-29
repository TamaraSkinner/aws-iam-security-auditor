import boto3
import json
from datetime import datetime, timezone
from botocore.exceptions import ClientError

def audit_mfa(iam):
    findings = []
    users = iam.list_users()
    for user in users['Users']:
        username = user['UserName']
        mfa_devices = iam.list_mfa_devices(UserName=username)
        is_secured = len(mfa_devices['MFADevices']) > 0
        findings.append({
            "user": username,
            "mfa_enabled": is_secured,
            "status": "PASS" if is_secured else "FAIL"
        })
    return findings

def audit_access_keys(iam):
    findings = []
    users = iam.list_users()
    for user in users['Users']:
        username = user['UserName']
        keys = iam.list_access_keys(UserName=username)
        for key in keys['AccessKeyMetadata']:
            age_days = (datetime.now(timezone.utc) - key['CreateDate']).days
            status = "FAIL" if age_days > 90 else "PASS"
            findings.append({
                "user": username,
                "key_id": key['AccessKeyId'],
                "age_days": age_days,
                "status": status
            })
    return findings

def audit_admin_privileges(iam):
    findings = []
    ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
    users = iam.list_users()
    
    for user in users['Users']:
        username = user['UserName']
        is_admin = False
        
        # Check Direct & Group Policies
        direct = iam.list_attached_user_policies(UserName=username)
        groups = iam.list_groups_for_user(UserName=username)
        
        all_policy_arns = [p['PolicyArn'] for p in direct['AttachedPolicies']]
        for group in groups['Groups']:
            g_policies = iam.list_attached_group_policies(GroupName=group['GroupName'])
            all_policy_arns.extend([p['PolicyArn'] for p in g_policies['AttachedPolicies']])
        
        if ADMIN_POLICY_ARN in all_policy_arns:
            is_admin = True
            
        findings.append({
            "user": username,
            "has_admin_access": is_admin,
            "status": "FAIL" if is_admin else "PASS" # Admin in a lab is usually a finding!
        })
    return findings

def main():
    try:
        iam = boto3.client('iam')
        print("🚀 Starting Cloud Audit...")

        # Collect all data into a master report
        report = {
            "audit_timestamp": datetime.now(timezone.utc).isoformat(),
            "account_id": boto3.client('sts').get_caller_identity()['Account'],
            "findings": {
                "mfa_compliance": audit_mfa(iam),
                "access_key_hygiene": audit_access_keys(iam),
                "administrative_privileges": audit_admin_privileges(iam)
            }
        }

        # 1. Print to Terminal for immediate feedback
        print(json.dumps(report, indent=2))

        # 2. Export to JSON file
        filename = f"iam_report_{datetime.now().strftime('%Y%m%d_%H%M')}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=4)
    
        print(f"\n✅ Audit complete! Report saved to {filename}")
    except ClientError as e:
        print(f"❌ Critical Audit Failure: {e}")

if __name__ == "__main__":
    main()
