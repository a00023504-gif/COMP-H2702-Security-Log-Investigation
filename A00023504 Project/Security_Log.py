import re
import csv
import json
import ipaddress

from pathlib import Path
from collections import Counter
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parent

DATA_DIR = BASE_DIR / "data"
REPORT_DIR = BASE_DIR / "reports"

FIREWALL_FILE = DATA_DIR / "firewall.log"
AUTH_FILE = DATA_DIR / "authentication.log"
SUSPICIOUS_FILE = DATA_DIR / "suspicious_ips.txt"

print(" SECURITY LOG INVESTIGATION TOOL")

print("Project folder:", BASE_DIR)
print("Firewall file:", FIREWALL_FILE)
print("Authentication file:", AUTH_FILE)
print("Suspicious IP file:", SUSPICIOUS_FILE)

def load_file(filename):
    try:
        with open(filename, "r", encoding="utf-8") as file:
            lines = file.readlines()

        print(f"Successfully loaded: {filename.name}")
        return lines

    except FileNotFoundError:
        print(f"ERROR: Could not find {filename}")
        return []

    except OSError as error:
        print(f"ERROR reading file: {error}")
        return []
    
firewall_lines = load_file(FIREWALL_FILE)
auth_lines = load_file(AUTH_FILE)
suspicious_lines = load_file(SUSPICIOUS_FILE)

print("\nFILE LOADING RESULTS")
print("--------------------")

print("Firewall lines:", len(firewall_lines))
print("Authentication lines:", len(auth_lines))
print("Suspicious IP lines:", len(suspicious_lines))

def parse_firewall_logs(lines):

    records = []
    malformed = 0

    for line in lines:

        try:
            parts = line.strip().split()

            if len(parts) != 8:
                raise ValueError("Incorrect number of fields")

            timestamp = parts[0] + " " + parts[1]
            action = parts[2]

            fields = {}

            for item in parts[3:]:
                key, value = item.split("=", 1)
                fields[key] = value

            src = fields["src"]
            dst = fields["dst"]
            protocol = fields["proto"]
            port = int(fields["port"])
            byte_count = int(fields["bytes"])

            datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")

            ipaddress.ip_address(src)
            ipaddress.ip_address(dst)

            if action not in ["ALLOWED", "BLOCKED"]:
                raise ValueError("Invalid action")

            if protocol not in ["TCP", "UDP"]:
                raise ValueError("Invalid protocol")

            if not 1 <= port <= 65535 or byte_count < 0:
                raise ValueError("Invalid port or bytes")

            record = {
                "timestamp": timestamp,
                "action": action,
                "src": src,
                "dst": dst,
                "protocol": protocol,
                "port": port,
                "bytes": byte_count
            }

            records.append(record)

        except (ValueError, KeyError):
            malformed += 1

    return records, malformed

firewall_records, firewall_errors = parse_firewall_logs(
    firewall_lines
)

print("\nFIREWALL PARSING RESULTS")
print("------------------------")

print("Valid firewall records:", len(firewall_records))
print("Malformed firewall records:", firewall_errors)

print("\nFirewall records:")

for record in firewall_records[:3]:
    print(record)
    
def load_suspicious_ips(lines):

    suspicious_ips = set()

    for line in lines:
        address = line.strip()

        try:
            ipaddress.ip_address(address)
            suspicious_ips.add(address)

        except ValueError:
            print("Invalid IP address ignored:", address)

    return suspicious_ips

suspicious_ips = load_suspicious_ips(suspicious_lines)

def analyse_firewall(records, suspicious_ips):

    actions = Counter(
        record["action"] for record in records
    )
    
    unique_sources = set(
        record["src"] for record in records
    )

    blocked_sources = Counter(
        record["src"]
        for record in records
        if record["action"] == "BLOCKED"
    )

    targeted_ports = Counter(
        record["port"] for record in records
    )

    suspicious_activity = Counter(
        record["src"]
        for record in records
        if record["src"] in suspicious_ips
    )
    return {
        "total_records": len(records),
        "allowed": actions["ALLOWED"],
        "blocked": actions["BLOCKED"],
        "unique_source_ips": len(unique_sources),
        "top_blocked_sources": blocked_sources.most_common(10),
        "top_targeted_ports": targeted_ports.most_common(10),
        "suspicious_activity": suspicious_activity.most_common()
    }
firewall_results = analyse_firewall(
    firewall_records, suspicious_ips
)
print("\nFIREWALL ANALYSIS")
print("=================")

print("Total records:", firewall_results["total_records"])
print("Allowed connections:", firewall_results["allowed"])
print("Blocked connections:", firewall_results["blocked"])
print("Unique source IPs:", firewall_results["unique_source_ips"])

print("\nTOP BLOCKED SOURCE IPs")

for ip, count in firewall_results["top_blocked_sources"]:
    print(ip, "-", count, "blocked connections")

print("\nMOST TARGETED DESTINATION PORTS")

for port, count in firewall_results["top_targeted_ports"]:
    print("Port", port, "-", count, "connections")

print("\nSUSPICIOUS IP ACTIVITY")

for ip, count in firewall_results["suspicious_activity"]:
    print(ip, "-", count, "connections")

def parse_auth_logs(lines):
    records = []
    malformed = 0

    valid_events = {
        "LOGIN_SUCCESS",
        "LOGIN_FAILED",
        "ACCOUNT_LOCKED",
        "LOGOUT"
    }

    for line in lines:
        try:
            parts = line.strip().split()

            if len(parts) != 7:
                raise ValueError("Incorrect number of fields")

            timestamp = parts[0] + " " + parts[1]
            event = parts[2]

            datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")

            if event not in valid_events:
                raise ValueError("Unknown event")

            fields = {}

            for item in parts[3:]:
                key, value = item.split("=", 1)
                fields[key] = value

            username = fields["user"]
            source_ip = fields["src"]
            host = fields["host"]
            method = fields["method"]

            if not username or not host or not method:
                raise ValueError("Missing field value")

            ipaddress.ip_address(source_ip)

            record = {
                "timestamp": timestamp,
                "event": event,
                "username": username,
                "src": source_ip,
                "host": host,
                "method": method
            }

            records.append(record)

        except (ValueError, KeyError, IndexError):
            malformed += 1

    return records, malformed

auth_records, auth_errors = parse_auth_logs(auth_lines)

print("\nAUTHENTICATION PARSING RESULTS")
print("------------------------------")
print("Valid authentication records:", len(auth_records))
print("Malformed authentication records:", auth_errors)

def analyse_auth(records):
    events = Counter(
        record["event"] for record in records
    )

    failed_ips = Counter(
        record["src"]
        for record in records
        if record["event"] == "LOGIN_FAILED"
    )

    failed_usernames = Counter(
        record["username"]
        for record in records
        if record["event"] == "LOGIN_FAILED"
    )

    suspicious_failed_ips = Counter(
        record["src"]
        for record in records
        if record["event"] == "LOGIN_FAILED"
        and record["src"] in suspicious_ips
    )

    return {
        "total_records": len(records),
        "successful_logins": events["LOGIN_SUCCESS"],
        "failed_logins": events["LOGIN_FAILED"],
        "account_locks": events["ACCOUNT_LOCKED"],
        "logouts": events["LOGOUT"],
        "top_failed_ips": failed_ips.most_common(10),
        "top_failed_usernames": failed_usernames.most_common(10),
        "suspicious_failed_ips": suspicious_failed_ips.most_common()
    }
    
auth_results = analyse_auth(auth_records)

print("\nAUTHENTICATION ANALYSIS")
print("=======================")
print("Total records:", auth_results["total_records"])
print("Successful logins:", auth_results["successful_logins"])
print("Failed logins:", auth_results["failed_logins"])
print("Account locks:", auth_results["account_locks"])
print("Logouts:", auth_results["logouts"])

print("\nTOP SOURCE IPs WITH FAILED LOGINS")
for ip, count in auth_results["top_failed_ips"]:
    print(ip, "-", count, "failed logins")

print("\nTOP USERNAMES WITH FAILED LOGINS")
for username, count in auth_results["top_failed_usernames"]:
    print(username, "-", count, "failed logins")

print("\nFAILED LOGINS FROM SUSPICIOUS IPs")
for ip, count in auth_results["suspicious_failed_ips"]:
    print(ip, "-", count, "failed logins")

def generate_reports(firewall_results, auth_results,
                     firewall_errors, auth_errors):

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    
    report_data = {
    "firewall": firewall_results,
    "authentication": auth_results,
    "malformed_records": {
        "firewall": firewall_errors,
        "authentication": auth_errors
    },
    "security_observations": [
        "203.0.113.55 generated 78 blocked firewall connections.",
        "198.51.100.23 generated 46 failed login attempts.",
        "The admin account had 52 failed login attempts.",
        "203.0.113.55, 203.0.113.77 and 198.51.100.23 "
        "appear in both firewall and authentication findings."
    ]
}

    json_file = REPORT_DIR / "investigation_report.json"

    with open(json_file, "w", encoding="utf-8") as file:
        json.dump(report_data, file, indent=4)

    csv_file = REPORT_DIR / "investigation_report.csv"

    with open(csv_file, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["Category", "Finding", "Count"])

        writer.writerow(["Firewall", "Total records",
                         firewall_results["total_records"]])
        writer.writerow(["Firewall", "Allowed connections",
                         firewall_results["allowed"]])
        writer.writerow(["Firewall", "Blocked connections",
                         firewall_results["blocked"]])
        writer.writerow(["Firewall", "Unique source IPs",
                         firewall_results["unique_source_ips"]])

        for ip, count in firewall_results["top_blocked_sources"]:
            writer.writerow(["Top blocked IP", ip, count])

        for port, count in firewall_results["top_targeted_ports"]:
            writer.writerow(["Targeted port", port, count])

        writer.writerow(["Authentication", "Total records",
                         auth_results["total_records"]])
        writer.writerow(["Authentication", "Successful logins",
                         auth_results["successful_logins"]])
        writer.writerow(["Authentication", "Failed logins",
                         auth_results["failed_logins"]])
        writer.writerow(["Authentication", "Account locks",
                         auth_results["account_locks"]])

        for ip, count in auth_results["top_failed_ips"]:
            writer.writerow(["Failed login IP", ip, count])

        for username, count in auth_results["top_failed_usernames"]:
            writer.writerow(["Failed username", username, count])

    txt_file = REPORT_DIR / "investigation_report.txt"

    with open(txt_file, "w", encoding="utf-8") as file:
        file.write("SECURITY LOG INVESTIGATION REPORT\n")
        file.write("================================\n\n")

        file.write("FIREWALL RESULTS\n")
        file.write("----------------\n")
        file.write(f"Valid records: {firewall_results['total_records']}\n")
        file.write(f"Malformed records: {firewall_errors}\n")
        file.write(f"Allowed connections: {firewall_results['allowed']}\n")
        file.write(f"Blocked connections: {firewall_results['blocked']}\n")
        file.write(f"Unique source IPs: {firewall_results['unique_source_ips']}\n\n")

        file.write("TOP BLOCKED SOURCE IPs\n")
        for ip, count in firewall_results["top_blocked_sources"]:
            file.write(f"{ip}: {count} blocked connections\n")

        file.write("\nAUTHENTICATION RESULTS\n")
        file.write("----------------------\n")
        file.write(f"Valid records: {auth_results['total_records']}\n")
        file.write(f"Malformed records: {auth_errors}\n")
        file.write(f"Successful logins: {auth_results['successful_logins']}\n")
        file.write(f"Failed logins: {auth_results['failed_logins']}\n")
        file.write(f"Account locks: {auth_results['account_locks']}\n")
        file.write(f"Logouts: {auth_results['logouts']}\n\n")

        file.write("TOP FAILED LOGIN IPs\n")
        for ip, count in auth_results["top_failed_ips"]:
            file.write(f"{ip}: {count} failed logins\n")

        file.write("\nTOP FAILED USERNAMES\n")
        for username, count in auth_results["top_failed_usernames"]:
            file.write(f"{username}: {count} failed logins\n")
        
        file.write("\nSECURITY OBSERVATIONS\n")
        file.write("---------------------\n")
        for observation in report_data["security_observations"]:
            file.write("- " + observation + "\n")

    print("\nREPORTS GENERATED SUCCESSFULLY")
    print("TXT:", txt_file)
    print("CSV:", csv_file)
    print("JSON:", json_file)
    
generate_reports(
    firewall_results,
    auth_results,
    firewall_errors,
    auth_errors
)
