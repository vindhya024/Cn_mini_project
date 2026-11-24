#!/usr/bin/env python3
import time
from collections import defaultdict

VALID_USERS = {
    "admin": "secret123",
    "alice": "password456"
}

from collections import defaultdict
import time

# CONFIGURATION
MAX_LOGIN_ATTEMPTS = 5
LOGIN_TIME_WINDOW = 300          # seconds

MAX_REQUESTS = 20
REQUEST_TIME_WINDOW = 10         # seconds

MAX_PORTS = 5
PORT_SCAN_TIME_WINDOW = 10       # seconds

# STORAGE
failed_logins = defaultdict(list)
requests = defaultdict(list)
port_activity = defaultdict(list)

def remove_old_entries(entries, current_time, time_window):
    """Removes events that are older than the given time window."""
    return [
        timestamp
        for timestamp in entries
        if current_time - timestamp <= time_window
    ]

def reset_failed_logins(ip):
    """Clears failed attempts when a user authenticates legitimately."""
    failed_logins[ip] = []

# RULE 1: BRUTE FORCE DETECTION
def check_failed_login(ip):
    """Detects repeated failed login attempts."""
    current_time = time.time()
    failed_logins[ip].append(current_time)
    failed_logins[ip] = remove_old_entries(
        failed_logins[ip],
        current_time,
        LOGIN_TIME_WINDOW
    )

    if len(failed_logins[ip]) >= MAX_LOGIN_ATTEMPTS:
        return {
            "threat": True,
            "type": "BRUTE_FORCE",
            "ip": ip,
            "severity": "HIGH",
            "message": f"Too many failed login attempts ({len(failed_logins[ip])}/{MAX_LOGIN_ATTEMPTS})"
        }
    return None

# RULE 2: TOO MANY REQUESTS
def check_request_flood(ip):
    """Detects an unusually high number of requests from the same IP."""
    current_time = time.time()
    requests[ip].append(current_time)
    requests[ip] = remove_old_entries(
        requests[ip],
        current_time,
        REQUEST_TIME_WINDOW
    )

    if len(requests[ip]) >= MAX_REQUESTS:
        return {
            "threat": True,
            "type": "REQUEST_FLOOD",
            "ip": ip,
            "severity": "MEDIUM",
            "message": "Too many requests from one IP"
        }
    return None

# RULE 3: PORT SCAN DETECTION
def check_port_scan(ip, port):
    """Detects an IP accessing many different ports in a short period."""
    current_time = time.time()
    port_activity[ip].append((port, current_time))

    port_activity[ip] = [
        (p, t)
        for p, t in port_activity[ip]
        if current_time - t <= PORT_SCAN_TIME_WINDOW
    ]

    unique_ports = set(p for p, t in port_activity[ip])

    if len(unique_ports) >= MAX_PORTS:
        return {
            "threat": True,
            "type": "PORT_SCAN",
            "ip": ip,
            "severity": "HIGH",
            "message": "Multiple ports accessed in a short time"
        }
    return None

# MAIN DETECTION FUNCTION
def detect_intrusion(event):
    """Main function used by the socket/server module."""
    ip = event.get("ip")
    event_type = event.get("type")

    if event_type == "FAILED_LOGIN":
        result = check_failed_login(ip)
        if result:
            return result

    elif event_type == "REQUEST":
        result = check_request_flood(ip)
        if result:
            return result

    elif event_type == "PORT_ACCESS":
        port = event.get("port")
        result = check_port_scan(ip, port)
        if result:
            return result

    return {
        "threat": False,
        "type": "NORMAL",
        "ip": ip,
        "severity": "LOW",
        "message": "No suspicious activity detected"
    }
            

 
