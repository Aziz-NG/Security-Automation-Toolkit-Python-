
import json
import msal
import csv

# --- MFA Check ---

with open("config.json") as f:
    config = json.load(f)

authority = f"https://login.microsoftonline.com/{config['tenant_id']}"

app = msal.ConfidentialClientApplication(
    client_id=config["client_id"],
    client_credential=config["client_secret"],
    authority=authority
)

result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])

if "access_token" in result:
    print("Authentication succeeded!")
    print("Token starts with:", result["access_token"][:20], "...")
else:
    print("Authentication failed:", result.get("error_description"))

import requests

access_token = result["access_token"]

headers = {
    "Authorization": f"Bearer {access_token}"
}

response = requests.get(
    "https://graph.microsoft.com/v1.0/users?$select=displayName,userPrincipalName",
    headers=headers
)

users = response.json()

print("Status code:", response.status_code)
mfa_response = requests.get(
    "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails",
    headers=headers
)

mfa_data = mfa_response.json()
print("MFA endpoint status code:", mfa_response.status_code)
print("Raw response:", mfa_data)

users_without_mfa = []

for user in users["value"]:
    user_upn = user["userPrincipalName"]
    
    methods_response = requests.get(
        f"https://graph.microsoft.com/v1.0/users/{user_upn}/authentication/methods",
        headers=headers
    )
    
    methods_data = methods_response.json()
    method_count = len(methods_data.get("value", []))
    
    # Every user has at least 1 method (their password) - anything beyond
    # that (phone, authenticator app, etc.) counts as real MFA
    if method_count <= 1:
        users_without_mfa.append(user_upn)

print("Users without MFA registered:")
for upn in users_without_mfa:
    print("-", upn)

print("\nTotal flagged:", len(users_without_mfa))

# --- Standing Privileged Role Check ---

# Step 1: get all role definitions once, build a lookup dictionary (id -> name)
role_defs_response = requests.get(
    "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions",
    headers=headers
)
role_defs_data = role_defs_response.json()

role_names_by_id = {}
for role_def in role_defs_data.get("value", []):
    role_names_by_id[role_def["id"]] = role_def["displayName"]

# Step 2: get role assignments, expanding only "principal" this time
role_response = requests.get(
    "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$expand=principal",
    headers=headers
)
role_data = role_response.json()

privileged_assignments = []

for assignment in role_data.get("value", []):
    principal_name = assignment["principal"]["displayName"]
    role_id = assignment["roleDefinitionId"]
    role_name = role_names_by_id.get(role_id, "Unknown Role")
    privileged_assignments.append(f"{principal_name} - {role_name}")

print("\nPrivileged directory role assignments found:")
for entry in privileged_assignments:
    print("-", entry)

print("\nTotal flagged:", len(privileged_assignments))

with open("audit_report.csv", "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    
    writer.writerow(["Finding Type", "Account/Principal", "Detail"])
    
    for upn in users_without_mfa:
        writer.writerow(["No MFA Registered", upn, ""])
    
    for entry in privileged_assignments:
        writer.writerow(["Standing Privileged Role", entry, ""])

print("\nReport written to audit_report.csv")
