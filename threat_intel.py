MALICIOUS_IPS = {
    "192.168.1.10": "Known brute-force source",
    "45.33.32.156": "Listed in threat feed",
    "185.220.101.1": "Suspicious scanning activity"
}

def check_ip_reputation(ip):
    if ip in MALICIOUS_IPS:
        return {
            "ip": ip,
            "malicious": True,
            "reason": MALICIOUS_IPS[ip]
        }
    else:
        return {
            "ip": ip,
            "malicious": False,
            "reason": "No match found in local threat feed"
        }
