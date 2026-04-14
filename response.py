import os
import subprocess

SAFE_SKIP_IPS = {"127.0.0.1", "::1"}

def block_ip(ip, file_path="reports/blocked_ips.txt"):
    existing_ips = set()

    if os.path.exists(file_path):
        with open(file_path, "r") as file:
            existing_ips = {line.strip() for line in file}

    if ip not in existing_ips:
        with open(file_path, "a") as file:
            file.write(ip + "\n")


def block_ip_real(ip, file_path="reports/blocked_ips.txt"):
    if ip in SAFE_SKIP_IPS:
        print(f"[SAFE MODE] Skipping real firewall block for {ip}")
        return

    try:
        result = subprocess.run(
            ["sudo", "ufw", "deny", "from", ip],
            capture_output=True,
            text=True,
            check=False
        )

        if result.returncode == 0:
            print(f"[+] UFW rule added to block {ip}")
            block_ip(ip, file_path)
        else:
            if "Skipping adding existing rule" in result.stdout or "Skipping adding existing rule" in result.stderr:
                print(f"[=] UFW rule already exists for {ip}")
                block_ip(ip, file_path)
            else:
                print(f"[ERROR] Could not block {ip}")
                print(result.stderr if result.stderr else result.stdout)

    except Exception as exc:
        print(f"[ERROR] Firewall block failed for {ip}: {exc}")
