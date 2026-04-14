import csv
import json
from parser import parse_auth_log
from detector import detect_brute_force, count_failed_attempts
from threat_intel import check_ip_reputation
from response import block_ip


def save_alerts(alerts, file_path="reports/alerts.txt"):
    with open(file_path, "w") as file:
        for alert in alerts:
            line = (
                f"Timestamp: {alert['timestamp']} | "
                f"Alert Type: {alert['type']} | "
                f"IP: {alert['ip']} | "
                f"Failed Attempts: {alert['failed_attempts']} | "
                f"Threat Intel: {alert['threat_intel']} | "
                f"Reason: {alert['reason']}\n"
            )
            file.write(line)


def save_alerts_csv(alerts, file_path="reports/alerts.csv"):
    with open(file_path, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Timestamp", "Alert Type", "IP", "Failed Attempts", "Threat Intel", "Reason"])

        for alert in alerts:
            writer.writerow([
                alert["timestamp"],
                alert["type"],
                alert["ip"],
                alert["failed_attempts"],
                alert["threat_intel"],
                alert["reason"]
            ])


def save_alerts_json(alerts, file_path="reports/alerts.json"):
    with open(file_path, "w") as file:
        json.dump(alerts, file, indent=4)


def main():
    log_file = "/var/log/auth.log"

    print("[*] Parsing authentication log...")
    events = parse_auth_log(log_file)

    print(f"[*] Total parsed events: {len(events)}")

    print("\n[*] Failed Login Count by IP:")
    failed_counts = count_failed_attempts(events)
    for ip, count in failed_counts.items():
        print(f"IP: {ip} | Failed Attempts: {count}")

    print("\n[*] Running brute-force detection...")
    alerts = detect_brute_force(events, threshold=2)

    if alerts:
        print("\n[ALERTS DETECTED]")
        for alert in alerts:
            intel = check_ip_reputation(alert["ip"])
            alert["threat_intel"] = "Known Malicious" if intel["malicious"] else "Unknown"
            alert["reason"] = intel["reason"]

            print(
                f"Timestamp: {alert['timestamp']} | "
                f"Alert Type: {alert['type']} | "
                f"IP: {alert['ip']} | "
                f"Failed Attempts: {alert['failed_attempts']} | "
                f"Threat Intel: {alert['threat_intel']} | "
                f"Reason: {alert['reason']}"
            )

            block_ip(alert["ip"])

        save_alerts(alerts)
        save_alerts_csv(alerts)
        save_alerts_json(alerts)

        print("\n[+] Alerts saved to reports/alerts.txt")
        print("[+] Alerts saved to reports/alerts.csv")
        print("[+] Alerts saved to reports/alerts.json")
        print("[+] Blocked IPs saved to reports/blocked_ips.txt")

    else:
        print("\n[OK] No brute-force activity detected.")


if __name__ == "__main__":
    main()
