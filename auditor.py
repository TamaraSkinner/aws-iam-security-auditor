import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timezone

def audit_mfa():
    # Initialize the IAM client
    iam = boto3.client('iam')
    
    print("--- Starting IAM Security Audit: MFA Compliance ---")
    
    try:
        # 1. Fetch all users in the account
        users = iam.list_users()
        
        for user in users['Users']:
            username = user['UserName']
            
            # 2. Check for MFA devices
            mfa_devices = iam.list_mfa_devices(UserName=username)
            
            if not mfa_devices['MFADevices']:
                print(f"🚨 ALERT: User '{username}' does NOT have MFA enabled!")
            else:
                print(f"✅ User '{username}' is secured with MFA.")
                
    except ClientError as e:
        print(f"Couldn't audit users. Error: {e}")


def audit_access_keys():
    iam = boto3.client('iam')
    print("\n--- Starting IAM Security Audit: Access Key Hygiene ---")
    
    users = iam.list_users()
    for user in users['Users']:
        username = user['UserName']
        
        # Get the keys for the user
        keys = iam.list_access_keys(UserName=username)
        
        for key in keys['AccessKeyMetadata']:
            key_id = key['AccessKeyId']
            created_date = key['CreateDate']
            
            # Calculate the age of the key
            age_days = (datetime.now(timezone.utc) - created_date).days
            
            if age_days > 90:
                print(f"🚨 ALERT: User '{username}' has a STALE key ({key_id}). Age: {age_days} days.")
            else:
                print(f"✅ User '{username}' has a fresh key ({key_id}). Age: {age_days} days.")
def audit_admin_privileges():
    iam = boto3.client('iam')
    print("\n--- Starting IAM Security Audit: Administrative Privileges ---")
    
    # The ARN for the standard AWS AdministratorAccess policy
    ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
    
    users = iam.list_users()
    for user in users['Users']:
        username = user['UserName']
        
        # Check attached managed policies
        policies = iam.list_attached_user_policies(UserName=username)
        
        is_admin = False
        for policy in policies['AttachedPolicies']:
            if policy['PolicyArn'] == ADMIN_POLICY_ARN:
                is_admin = True
                break
        
        if is_admin:
            print(f"🚨 ALERT: User '{username}' has FULL AdministratorAccess! (Principle of Least Privilege violation)")
        else:
            print(f"✅ User '{username}' does not have the default Admin policy.")


if __name__ == "__main__":
    audit_mfa()
    audit_access_keys()
    audit_admin_privileges()
