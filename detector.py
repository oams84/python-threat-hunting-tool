from collections import defaultdict

def count_failed_attempts(events):
    failed_attempts = defaultdict(int)

    for event in events:
        if event["status"] == "Failed":
            failed_attempts[event["ip"]] += 1

    return dict(failed_attempts)

def detect_brute_force(events, threshold=2):
    failed_attempts = defaultdict(int)
    latest_time = {}
    alerts = []

    for event in events:
        if event["status"] == "Failed":
            ip = event["ip"]
            failed_attempts[ip] += 1
            latest_time[ip] = event["timestamp"]

    for ip, count in failed_attempts.items():
        if count >= threshold:
            alerts.append({
                "type": "Brute Force Suspected",
                "ip": ip,
                "failed_attempts": count,
                "timestamp": latest_time[ip]
            })

    return alerts
