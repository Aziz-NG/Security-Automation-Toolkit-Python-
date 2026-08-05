import json
import msal
import requests
import csv

def get_graph_headers():
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

ca_response = requests.get(
    "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies",
    headers=headers
)

ca_data = ca_response.json()
print("CA endpoint status code:", ca_response.status_code)
print("Raw response:", ca_data)

ca_policies = []

for policy in ca_data["value"]:
    name = policy["displayName"]
    state = policy["state"]
    
    # grantControls holds what's required to gain access (e.g. "mfa", "block")
    # builtInControls is a list, so we join it into one readable string
    controls = policy["grantControls"]
    if controls is not None:
        required_controls = ", ".join(controls.get("builtInControls", []))
    else:
        required_controls = "None specified"
    
    # who this policy applies to
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

with open("ca_policy_report.csv", "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["Policy Name", "State", "Required Controls", "Included Users"])
    
    for p in ca_policies:
        writer.writerow([p["name"], p["state"], p["required_controls"], p["included_users"]])

print("\nReport written to ca_policy_report.csv")
