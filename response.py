import time
from collections import defaultdict

class SDNResponse:
    def __init__(self):
        self.flow_table = defaultdict(lambda: "ALLOW")
        self.flow_stats = defaultdict(int)

    def record_packet(self, ip):
        self.flow_stats[ip] += 1

    def is_blocked(self, ip):
        return self.flow_table[ip] == "DROP"

    def print_status_box(self, ip, action, threat_type, reason, start_time):
        """Displays the SDN Controller status table for every transaction."""
        latency_ms = (time.time() - start_time) * 1000

        print("\n" + "=" * 65)
        print(f"[SDN CONTROLLER] *** SDN FLOW TABLE STATUS ***")
        print(f"  Target IP            : {ip}")
        print(f"  Host Classification  : {'MALICIOUS (BLOCKED)' if action == 'DROP' else 'LEGITIMATE / MONITORING'}")
        print(f"  Detected Threat      : {threat_type}")
        print(f"  Status / Reason      : {reason}")
        print(f"  Action Taken         : Flow Table set to {action}")
        print(f"  Cumulative Packets   : {self.flow_stats[ip]}")
        print(f"  Transmission Latency : {latency_ms:.4f} ms")
        print("=" * 65 + "\n")

    def apply_sdn_rule(self, threat, start_time):
        """Installs dynamic DROP rule when threat is detected."""
        ip = threat["ip"]
        self.flow_table[ip] = "DROP"
        self.print_status_box(
            ip=ip,
            action="DROP",
            threat_type=f"{threat['type']} ({threat.get('severity', 'HIGH')})",
            reason=threat["message"],
            start_time=start_time
        )
