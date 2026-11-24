import socket
import threading
import time
import csv
import os
from datetime import datetime
from detector import detect_intrusion, reset_failed_logins
from response import SDNResponse

sdn = SDNResponse()
PORTS = [8000, 8001, 8002, 8003, 8004, 8005]
CSV_FILE = "login_logs.csv"
csv_lock = threading.Lock()

VALID_USERS = {
    "admin": "secret123",
    "alice": "password456"
}

def init_csv():
    """Creates login_logs.csv with headers if it does not exist."""
    if not os.path.exists(CSV_FILE):
        with open(CSV_FILE, mode="w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(["Timestamp", "Client_IP", "User_ID", "Password_Entered", "Status"])

def log_login_attempt(client_ip, username, password, status):
    """Thread-safe logging of all login attempts (valid and invalid) to CSV."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with csv_lock:
        with open(CSV_FILE, mode="a", newline="") as file:
            writer = csv.writer(file)
            writer.writerow([timestamp, client_ip, username, password, status])

def handle_client(sock, client_ip, port):
    start_time = time.time()
    sdn.record_packet(client_ip)

    # 1. Forwarding Check (SDN Data Plane)
    if sdn.is_blocked(client_ip):
        print(f"[SDN DROP] Blocked packet dropped from {client_ip} (Rule: DROP)")
        sock.close()
        return

    # 2. Request Flood Check
    flood_result = detect_intrusion({"ip": client_ip, "type": "REQUEST"})
    if flood_result and flood_result.get("threat"):
        sdn.apply_sdn_rule(flood_result, start_time)
        sock.close()
        return

    # 3. Port Scan Check
    scan_result = detect_intrusion({"ip": client_ip, "type": "PORT_ACCESS", "port": port})
    if scan_result and scan_result.get("threat"):
        sdn.apply_sdn_rule(scan_result, start_time)
        sock.close()
        return

    # 4. Payload and Authentication Processing
    try:
        raw_data = sock.recv(1024).decode().strip()

        if ":" in raw_data:
            username, password = raw_data.split(":", 1)

            if VALID_USERS.get(username) == password:
                # Classify host as legitimate and reset prior failed attempts
                reset_failed_logins(client_ip)
                log_login_attempt(client_ip, username, password, "SUCCESS")

                sdn.print_status_box(
                    ip=client_ip,
                    action="ALLOW",
                    threat_type="NONE (Authorized User)",
                    reason=f"Login SUCCESS for user '{username}'",
                    start_time=start_time
                )
                sock.sendall(b"200 OK: Login Successful\n")
            else:
                log_login_attempt(client_ip, username, password, "FAILED")
                threat_check = detect_intrusion({"ip": client_ip, "type": "FAILED_LOGIN"})

                if threat_check and threat_check.get("threat"):
                    # Threshold breached: Classify host as malicious & apply DROP rule
                    sdn.apply_sdn_rule(threat_check, start_time)
                    sock.sendall(b"403 FORBIDDEN: Brute Force Detected. Blocked by SDN\n")
                else:
                    sdn.print_status_box(
                        ip=client_ip,
                        action="ALLOW",
                        threat_type="POTENTIAL_ANOMALY (Pending Threshold)",
                        reason=f"Invalid credentials for user '{username}'",
                        start_time=start_time
                    )
                    sock.sendall(b"401 UNAUTHORIZED: Invalid Credentials\n")
        else:
            sdn.print_status_box(
                ip=client_ip,
                action="ALLOW",
                threat_type="NONE",
                reason="Generic REQUEST",
                start_time=start_time
            )
            sock.sendall(b"TCP_ACK: Connection Accepted\n")

    except Exception:
        pass
    finally:
        sock.close()

def listen_on_port(port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(10)
    while True:
        sock, (client_ip, _) = srv.accept()
        threading.Thread(target=handle_client, args=(sock, client_ip, port), daemon=True).start()

if __name__ == "__main__":
    init_csv()
    print(f"[SERVER] Audit logging initialized -> {CSV_FILE}")
    print("[SERVER] Multi-Port TCP Listeners active on ports 8000-8005...")
    for p in PORTS:
        threading.Thread(target=listen_on_port, args=(p,), daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[SERVER] Stopped.")
