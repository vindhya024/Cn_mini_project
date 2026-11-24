import socket
import sys

# Use "10.0.0.1" when running inside Mininet (h2 -> h1), or "127.0.0.1" for local testing
SERVER_IP = "10.0.0.1"
PORT = 8000

def get_masked_password(prompt="Enter password: "):
    """Reads password input from terminal while displaying '*' for each character."""
    sys.stdout.write(prompt)
    sys.stdout.flush()
    password = []

    if sys.platform == "win32":
        import msvcrt
        while True:
            ch = msvcrt.getch()
            if ch in (b"\r", b"\n"):
                sys.stdout.write("\n")
                sys.stdout.flush()
                break
            elif ch == b"\x08":  # Backspace
                if password:
                    password.pop()
                    sys.stdout.write("\b \b")
                    sys.stdout.flush()
            elif ch == b"\x03":  # Ctrl+C
                raise KeyboardInterrupt
            else:
                password.append(ch.decode("utf-8", errors="ignore"))
                sys.stdout.write("*")
                sys.stdout.flush()
    else:
        import tty
        import termios
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            while True:
                ch = sys.stdin.read(1)
                if ch in ("\r", "\n"):
                    sys.stdout.write("\r\n")
                    sys.stdout.flush()
                    break
                elif ch in ("\x7f", "\b"):  # Backspace
                    if password:
                        password.pop()
                        sys.stdout.write("\b \b")
                        sys.stdout.flush()
                elif ch == "\x03":  # Ctrl+C
                    raise KeyboardInterrupt
                else:
                    password.append(ch)
                    sys.stdout.write("*")
                    sys.stdout.flush()
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

    return "".join(password)

def send_credentials(username, password):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((SERVER_IP, PORT))
        
        payload = f"{username}:{password}"
        s.sendall(payload.encode())
        
        reply = s.recv(1024).decode().strip()
        s.close()
        return reply
    except Exception:
        return "BLOCKED_BY_SDN"

def simulate_port_scan():
    print("\n[*] Simulating Port Scan across ports 8000-8005 from this host...")
    for p in range(8000, 8006):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect((SERVER_IP, p))
            s.sendall(b"PROBE")
            s.close()
            print(f"  -> Probed port {p}")
        except Exception:
            print(f"  -> Port {p} rejected/blocked by SDN")

def main():
    print("=== Single-Host Network Access & Behavioral Classification Portal ===")
    print("Valid accounts: 'admin' (secret123) | 'alice' (password456)")
    print("Special commands: type 'scan' as username to test port-scan detection, or 'exit' to quit.\n")

    while True:
        username = input("Enter username (or 'scan' / 'exit'): ").strip()
        if username.lower() == "exit":
            break
        if username.lower() == "scan":
            simulate_port_scan()
            continue

        password = get_masked_password("Enter password: ").strip()

        reply = send_credentials(username, password)

        if "200 OK" in reply:
            print("\n[CLASSIFIED: LEGITIMATE USER]")
            print(f"-> Server Response: {reply}")
            print("-> Status: Transmission Allowed by SDN Controller.\n")

        elif "401 UNAUTHORIZED" in reply:
            print("\n[WARNING: INVALID CREDENTIALS]")
            print(f"-> Server Response: {reply}")
            print("-> Status: Attempt logged to CSV & tracked by IDS.\n")

        elif "403 FORBIDDEN" in reply or reply == "BLOCKED_BY_SDN":
            print("\n" + "!" * 60)
            print("[CLASSIFIED: MALICIOUS HOST -> IP BLOCKED]")
            print("-> Server Response: Connection dropped by SDN Flow Rule.")
            print("-> Reason: Intrusion threshold exceeded.")
            print("-> All subsequent traffic from this host is now REJECTED.")
            print("!" * 60 + "\n")
            sys.exit()
        else:
            print(f"Server response: {reply}\n")

if __name__ == "__main__":
    main()
