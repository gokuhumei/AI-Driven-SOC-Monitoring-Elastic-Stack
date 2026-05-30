import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from elasticsearch import Elasticsearch
from datetime import datetime, timedelta, UTC
now = datetime.now(UTC)
import statistics

# Connect to Elasticsearch
es = Elasticsearch(
    "https://localhost:9200",
    basic_auth=("elastic", "U2PcNcHBbi8g3i_niKkX"),
    verify_certs=False
)

now = datetime.utcnow()
time_window = now - timedelta(hours=1)

# Function to get event counts
def get_event_counts(event_code):

    query = {
        "size": 1000,
        "query": {
            "bool": {
                "must": [
                    {"match": {"event.code": str(event_code)}},
                    {
                        "range": {
                            "@timestamp": {
                                "gte": time_window.isoformat(),
                                "lte": now.isoformat()
                            }
                        }
                    }
                ]
            }
        }
    }

    response = es.search(index="winlogbeat-*", body=query)

    user_counts = {}

    for hit in response["hits"]["hits"]:
        user = hit["_source"].get("user", {}).get("name", "unknown")
        user_counts[user] = user_counts.get(user, 0) + 1

    return user_counts


# Collect event data
failed_logins = get_event_counts(4625)
successful_logins = get_event_counts(4624)
network_connections = get_event_counts(3)
process_creations = get_event_counts(1)

# Merge all users
all_users = set(failed_logins) | set(successful_logins) | set(network_connections) | set(process_creations)

# ==============================
# BASELINE BEHAVIOR CALCULATION
# ==============================

baseline_data = []

for user in all_users:

    F = failed_logins.get(user, 0)
    S = successful_logins.get(user, 0)
    N = network_connections.get(user, 0)
    P = process_creations.get(user, 0)

    score = (3 * F) + (1 * S) + (2 * N) + (4 * P)
    baseline_data.append(score)

baseline_mean = statistics.mean(baseline_data)

if len(baseline_data) > 1:
    baseline_std = statistics.stdev(baseline_data)
else:
    baseline_std = 1

print("\n=== BEHAVIOR BASELINE ===")
print("Mean:", baseline_mean)
print("Std Dev:", baseline_std)

print("\n=== MULTI-FACTOR USER RISK ANALYSIS ===\n")

for user in all_users:

    F = failed_logins.get(user,0)
    S = successful_logins.get(user,0)
    N = network_connections.get(user,0)
    P = process_creations.get(user,0)

    total_activity = F + S + N + P

    # Risk scoring
    risk_score = (3 * F) + (1 * S) + (2 * N) + (4 * P)

    # Threat classification
    if risk_score <= 10:
        threat_level = "LOW"
    elif risk_score <= 25:
        threat_level = "MEDIUM"
    else: 
        threat_level = "HIGH"

    # ===== ANOMALY DETECTION =====
    anomaly = "NORMAL"
    
    if baseline_std > 0:
        threshold= baseline_mean+1.5* baseline_std

        if total_activity > threshold:
            anomaly = "ANOMALOUS"

    if risk_score >= 200:
       anomaly ="ANOMALOUS"

    # Print output
    print(f"User: {user}")
    print(f" Failed Logins: {F}")
    print(f" Successful Logins: {S}")
    print(f" Network Connections: {N}")
    print(f" Process Creations: {P}")
    print(f" Risk Score: {risk_score}")
    print(f" Threat Level: {threat_level}")
    print(f" Behavior Status: {anomaly}")
    print("--------------------------------------------------")

    # Document for Elasticsearch
    doc = {
        "username": user,
        "failed_logins": F,
        "successful_logins": S,
        "network_connections": N,
        "process_creations": P,
        "risk_score": risk_score,
        "threat_level": threat_level,
        "behavior_status": anomaly,
        "timestamp": datetime.utcnow()
    }

    es.index(index="user_risk_index", document=doc)
