# mfa_stale_role_audit.py
#
# Purpose: audits an Entra ID tenant for two access-hygiene gaps:
#   1. Accounts with no MFA method registered beyond a password
#   2. Standing (permanent) privileged directory role assignments
#
# Note on scope: the original plan was to flag privileged roles unused for
# 90+ days via PIM activation history. That data requires Entra ID P2/
# Governance licensing, which this tenant doesn't have. Instead, this script
# flags standing/permanent role assignments - which is a legitimate finding
# on its own, since it's exactly the anti-pattern PIM's just-in-time
# activation model is meant to prevent.
#
# Authenticates as its own app (client credentials flow) via an Entra ID
# app registration - not as a signed-in user.

import json
import msal
import requests
import csv

# --- Load credentials from config.json (never committed - see .gitignore) ---
with open("config.json") as f:
    config = json.load(f)

# --- Authenticate to Entra ID and get an access token for Microsoft Graph ---
authority = f"https://login.microsoftonline.com/{config['tenant_id']}"

app = msal.ConfidentialClientApplication(
    client_id=config["client_id"],
    client_credential=config["client_secret"],
    authority=authority
)

result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])

if "access_token" in result:
    print("Authentication succeeded!")
else:
    print("Authentication failed:", result.get("error_description"))

access_token = result["access_token"]

headers = {
    "Authorization": f"Bearer {access_token}"
}

# --- Get the full list of users in the tenant ---
# We only request the two fields we actually need, rather than everything
# Graph would return by default.
users_response = requests.get(
    "https://graph.microsoft.com/v1.0/users?$select=displayName,userPrincipalName",
    headers=headers
)
users = users_response.json()

# =====================================================================
# CHECK 1: Accounts without MFA registered
# =====================================================================
# Note: Graph has a single-call reporting endpoint for this
# (reports/authenticationMethods/userRegistrationDetails), which would be
# faster than checking each user individually - but it requires Entra ID
# P1/P2 licensing this tenant doesn't have. Falling back to checking each
# user's registered methods directly, which works on any tier.

users_without_mfa = []

for user in users["value"]:
    user_upn = user["userPrincipalName"]

    methods_response = requests.get(
        f"https://graph.microsoft.com/v1.0/users/{user_upn}/authentication/methods",
        headers=headers
    )
    methods_data = methods_response.json()
    method_count = len(methods_data.get("value", []))

    # Every user always has at least 1 method (their password). Anything
    # beyond that (phone, authenticator app, etc.) counts as real MFA.
    if method_count <= 1:
        users_without_mfa.append(user_upn)

print("\nUsers without MFA registered:")
for upn in users_without_mfa:
    print("-", upn)
print("Total flagged:", len(users_without_mfa))

# =====================================================================
# CHECK 2: Standing (permanent) privileged role assignments
# =====================================================================

# Step 1: get all role definitions once, and build an id -> name lookup
# dictionary. The role assignments endpoint only gives us role IDs, not
# readable names, so we need this to translate between them.
role_defs_response = requests.get(
    "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions",
    headers=headers
)
role_defs_data = role_defs_response.json()

role_names_by_id = {}
for role_def in role_defs_data.get("value", []):
    role_names_by_id[role_def["id"]] = role_def["displayName"]

# Step 2: get all standing role assignments, expanding "principal" so we
# get readable account names instead of just GUIDs.
# (Note: this endpoint only allows expanding one property at a time, so
# role name lookups are done manually via the dictionary above instead.)
role_response = requests.get(
    "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$expand=principal",
    headers=headers
)
role_data = role_response.json()

privileged_assignments = []

for assignment in role_data.get("value", []):
    # Some principals (service principals, certain system assignments)
    # don't have a displayName - fall back gracefully instead of
    # showing "None" in the report.
    principal_name = assignment["principal"].get("displayName", "Unknown/Service Principal")
    role_id = assignment["roleDefinitionId"]
    role_name = role_names_by_id.get(role_id, "Unknown Role")
    privileged_assignments.append(f"{principal_name} - {role_name}")

print("\nPrivileged directory role assignments found:")
for entry in privileged_assignments:
    print("-", entry)
print("Total flagged:", len(privileged_assignments))

# =====================================================================
# Write both findings out to a CSV report
# =====================================================================
with open("audit_report.csv", "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["Finding Type", "Account/Principal", "Detail"])

    for upn in users_without_mfa:
        writer.writerow(["No MFA Registered", upn, ""])

    for entry in privileged_assignments:
        writer.writerow(["Standing Privileged Role", entry, ""])

print("\nReport written to audit_report.csv")
