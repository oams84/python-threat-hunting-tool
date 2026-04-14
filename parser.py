import re

LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\S+)\s+"
    r"(?P<host>\S+)\s+"
    r"sshd\[\d+\]:\s+"
    r"(?P<status>Failed|Accepted)\s+password\s+for\s+"
    r"(?:(?:invalid|illegal)\s+user\s+)?"
    r"(?P<user>\S+)\s+from\s+"
    r"(?P<ip>[0-9a-fA-F:.]+)"
)

def parse_auth_line(line):
    match = LOG_PATTERN.search(line)
    if match:
        return {
            "timestamp": match.group("timestamp"),
            "host": match.group("host"),
            "status": match.group("status"),
            "user": match.group("user"),
            "ip": match.group("ip"),
        }
    return None

def parse_auth_log(file_path):
    events = []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            event = parse_auth_line(line)
            if event:
                events.append(event)

    return events
