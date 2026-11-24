#!/usr/bin/env python3
import socket
import time
import sys

SERVER_IP = "10.0.0.1"

def send_packet(port, payload="admin|secret123"):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((SERVER_IP, port))
        s.sendall(payload.encode('utf-8'))
        resp = s.recv(1024).decode('utf-8', errors='ignore')
        s.close()
        return resp.strip()
    except Exception as e:
        return f"DROP/ERR: {e}"

def test_legitimate():
    print("[+] [TEST] Sending Normal TCP Traffic...")
    resp = send_packet(8000, "admin|secret123")
    print(f"    Server Response: {resp}")

def test_port_scan():
    print("[+] [TEST] Simulating Horizontal Port Scan across ports 8000, 8001, 8002, 8003...")
    for port in [8000, 8001, 8002, 8003]:
        resp = send_packet(port, "PING")
        print(f"    Port {port}: {resp}")
        time.sleep(0.3)

def test_flood():
    print("[+] [TEST] Simulating High Connection-Rate Anomaly (TCP Flood)...")
    for i in range(15):
        resp = send_packet(8000, "FLOOD_PACKET")
        print(f"    Conn #{i+1}: {resp}")
        time.sleep(0.05)

def test_bruteforce():
    print("[+] [TEST] Simulating 5-Attempt Brute-Force Attack...")
    for i in range(1, 6):
        resp = send_packet(8000, f"admin|wrongpass_{i}")
        print(f"    Attempt #{i}: {resp}")
        time.sleep(0.5)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 traffic_gen.py [normal|scan|flood|brute]")
        sys.exit(1)

    mode = sys.argv[1].lower()
    if mode == "normal":
        test_legitimate()
    elif mode == "scan":
        test_port_scan()
    elif mode == "flood":
        test_flood()
    elif mode == "brute":
        test_bruteforce()
