from collections import defaultdict
from monitor import follow_log
from parser import parse_auth_line
from threat_intel import check_ip_reputation
from response import block_ip_real


def run_realtime_monitor(log_file="/var/log/auth.log", threshold=2):
    failed_attempts = defaultdict(int)

    print(f"[*] Monitoring {log_file} in real time...")
    print("[*] Waiting for new SSH authentication events...\n")

    for line in follow_log(log_file):
        event = parse_auth_line(line)

        if not event:
            continue

        print(f"[EVENT] {event}")

        if event["status"] == "Failed":
            ip = event["ip"]
            failed_attempts[ip] += 1

            print(f"[!] Failed login from {ip} | Count: {failed_attempts[ip]}")

            if failed_attempts[ip] >= threshold:
                intel = check_ip_reputation(ip)
                threat_status = "Known Malicious" if intel["malicious"] else "Unknown"

                print(
                    f"[ALERT] Timestamp: {event['timestamp']} | "
                    f"IP: {ip} | "
                    f"Failed Attempts: {failed_attempts[ip]} | "
                    f"Threat Intel: {threat_status} | "
                    f"Reason: {intel['reason']}"
                )

                block_ip_real(ip)


# ✅ RUNNER (this makes the script executable)
if __name__ == "__main__":
    run_realtime_monitor()
