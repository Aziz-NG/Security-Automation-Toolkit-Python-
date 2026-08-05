# ca_policy_export.py
#
# Purpose: exports all Microsoft Entra ID Conditional Access policies into a
# readable CSV report - name, enabled/disabled state, required grant
# controls (e.g. MFA, block), and included users - so policies can be
# reviewed in bulk instead of opening each one individually in the portal.
#
# Authenticates as its own app (client credentials flow) via the same
# Entra ID app registration used by mfa_stale_role_audit.py.
# Requires the Policy.Read.All application permission (admin consent granted).

import json
import msal
import requests
import csv


def get_graph_headers():
    """
    Authenticates to Entra ID using the app registration's credentials
    (from config.json) and returns the Authorization header needed for
    every subsequent Microsoft Graph API call.
    """
    with open("config.json") as f:
        config = json.load(f)

    authority = f"https://login.microsoftonline.com/{config['tenant_id']}"

    app = msal.ConfidentialClientApplication(
        client_id=config["client_id"],
        client_credential=config["client_secret"],
        authority=authority
    )

    result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])

    if "access_token" not in result:
        raise Exception("Authentication failed: " + result.get("error_description", "unknown error"))

    return {"Authorization": f"Bearer {result['access_token']}"}


headers = get_graph_headers()
print("Authenticated successfully.")

# --- Get all Conditional Access policies ---
ca_response = requests.get(
    "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies",
    headers=headers
)
ca_data = ca_response.json()

# --- Pull out the fields that matter for a governance report ---
# Each policy's real data is deeply nested (conditions > users > includeUsers,
# grantControls > builtInControls, etc.) - we flatten what we need into a
# simple list of dictionaries, one per policy, ready to write to CSV.
ca_policies = []

for policy in ca_data["value"]:
    name = policy["displayName"]
    state = policy["state"]

    # grantControls can be None for some policy types (e.g. session-only
    # policies), so check before reading into it.
    controls = policy["grantControls"]
    if controls is not None:
        required_controls = ", ".join(controls.get("builtInControls", []))
    else:
        required_controls = "None specified"

    # Note: some policies (e.g. "Require MFA for admins") target access
    # entirely through includeRoles rather than named users/groups. For
    # those, included_users below will legitimately be blank - that's
    # accurate scoping, not missing data.
    included_users = ", ".join(policy["conditions"]["users"].get("includeUsers", []))

    ca_policies.append({
        "name": name,
        "state": state,
        "required_controls": required_controls,
        "included_users": included_users
    })

print("\nConditional Access policies found:")
for p in ca_policies:
    print(f"- {p['name']} ({p['state']}) - requires: {p['required_controls']}")
print("\nTotal policies:", len(ca_policies))

# --- Write results to a CSV report ---
with open("ca_policy_report.csv", "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["Policy Name", "State", "Required Controls", "Included Users"])

    for p in ca_policies:
        writer.writerow([p["name"], p["state"], p["required_controls"], p["included_users"]])

print("\nReport written to ca_policy_report.csv")
