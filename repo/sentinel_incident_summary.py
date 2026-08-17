import json
import msal
import requests
import csv


def get_headers(scope, config):
    authority = f"https://login.microsoftonline.com/{config['tenant_id']}"

    app = msal.ConfidentialClientApplication(
        client_id=config["client_id"],
        client_credential=config["client_secret"],
        authority=authority
    )

    result = app.acquire_token_for_client(scopes=[scope])

    if "access_token" not in result:
        raise Exception("Authentication failed: " + result.get("error_description", "unknown error"))

    return {"Authorization": f"Bearer {result['access_token']}"}


with open("config.json") as f:
    config = json.load(f)

arm_headers = get_headers("https://management.azure.com/.default", config)
print("Authenticated to Azure Resource Manager.")

subscription_id = config["subscription_id"]
resource_group = config["resource_group"]
workspace_name = config["workspace_name"]

incidents_url = (
    f"https://management.azure.com/subscriptions/{subscription_id}"
    f"/resourceGroups/{resource_group}"
    f"/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}"
    f"/providers/Microsoft.SecurityInsights/incidents"
    f"?api-version=2024-03-01"
)

incidents_response = requests.get(incidents_url, headers=arm_headers)
incidents_data = incidents_response.json()

print("Incidents endpoint status code:", incidents_response.status_code)
print("Raw response:", incidents_data)

severity_counts = {}
brute_force_count = 0
impossible_travel_detection_count = 0

for incident in incidents_data["value"]:
    severity = incident["properties"]["severity"]
    title = incident["properties"]["title"]

    severity_counts[severity] = severity_counts.get(severity, 0) + 1

    if title == "Brute Force":
        brute_force_count += 1
    if title == "Impossible Travel Detection":
        impossible_travel_detection_count +=1

print("\nIncident counts by severity:")
for severity, count in severity_counts.items():
    print(f"- {severity}: {count}")

print("\nTotal incidents on this page:", len(incidents_data["value"]))
print("Brute Force incidents:", brute_force_count)
print("Impossible Travel Detection incidents:", impossible_travel_detection_count)

with open("sentinel_incident_summary.csv", "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["Metric", "Value"])

    for severity, count in severity_counts.items():
        writer.writerow([f"Incidents - {severity} severity", count])

    writer.writerow(["Total incidents (this page)", len(incidents_data["value"])])
    writer.writerow(["Brute Force incidents", brute_force_count])
    writer.writerow(["Impossible Travel Detection incidents", impossible_travel_detection_count])

print("\nReport written to sentinel_incident_summary.csv")