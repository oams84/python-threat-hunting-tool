# Python Threat Hunting Tool

A Python-based threat hunting and incident response project built on Ubuntu Linux. This tool parses authentication logs, detects brute-force login attempts, enriches suspicious IPs with threat intelligence, and exports alerts in multiple formats.

## Features
- Parses real Ubuntu `/var/log/auth.log`
- Detects repeated failed SSH login attempts
- Counts failed logins by source IP
- Enriches alerts with local threat intelligence
- Exports alerts to TXT, CSV, and JSON
- Simulates automated response by recording blocked IPs
- Prevents duplicate blocked IP entries

## Project Files
- `parser.py` - parses authentication logs
- `detector.py` - counts failed attempts and detects brute-force activity
- `threat_intel.py` - checks IP reputation against a local threat feed
- `response.py` - simulates blocking suspicious IPs
- `main.py` - runs the full workflow

## How to Run
```bash
sudo python3 main.py
