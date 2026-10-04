#!/usr/bin/env python3
"""
Detection Engine — Cyber Range Platform (Enhanced Telemetry Edition)
Passively sniffs eth0 and produces a rich, continuous detection feed:
  - Per-port SYN probe alerts with service identification
  - Running packet/connection counters
  - SSH brute-force attempt tracking with per-attempt logging
  - Post-exploitation session detection with traffic analysis
  - MITRE ATT&CK technique mapping on every alert
"""

import time
import datetime
from collections import defaultdict, deque
from scapy.all import AsyncSniffer, IP, TCP, Raw

LOG_FILE = "/home/kali/detection_log.txt"
INTERFACE = "eth0"

# Known service names for common Metasploitable2 ports
SERVICE_MAP = {
    21: "FTP (vsftpd)", 22: "SSH (OpenSSH)", 23: "Telnet", 25: "SMTP",
    53: "DNS (BIND)", 80: "HTTP (Apache)", 111: "RPCBind", 139: "NetBIOS/SMB",
    445: "SMB/CIFS", 512: "rexec", 513: "rlogin", 514: "rshell",
    1099: "Java-RMI", 1524: "Backdoor Shell", 2049: "NFS", 2121: "ProFTPD",
    3306: "MySQL", 5432: "PostgreSQL", 5900: "VNC", 6000: "X11",
    6667: "IRC (UnrealIRCd)", 8009: "AJP (Tomcat)", 8180: "HTTP (Tomcat)"
}

def log_alert(severity, category, mitre, message):
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    line = f"[{timestamp}] [{severity}] [{category}] [{mitre}] {message}"
    print(line, flush=True)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

class IntrusionDetector:
    def __init__(self):
        # Counters
        self.total_packets = 0
        self.total_syn = 0
        self.total_ssh_attempts = 0

        # Port scan tracking
        self.port_scan_tracker = defaultdict(deque)
        self.discovered_ports = set()
        self.scan_alerted = False

        # Brute force tracking
        self.ssh_conn_tracker = defaultdict(deque)
        self.ssh_attempt_count = 0
        self.brute_force_alerted = False
        self.brute_force_start_time = None

        # Post-exploitation tracking
        self.exploit_alerted_directions = set()
        self.interactive_packet_count = 0

        # Heartbeat
        self.last_heartbeat = time.time()

        # Thresholds
        self.SCAN_WINDOW = 15.0
        self.SCAN_PORT_THRESHOLD = 8
        self.SSH_WINDOW = 30.0
        self.SSH_CONN_THRESHOLD = 4

    def process_packet(self, pkt):
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            return

        self.total_packets += 1
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        dport = pkt[TCP].dport
        sport = pkt[TCP].sport
        flags = pkt[TCP].flags
        now = time.time()

        # ── RULE 1: PORT SCAN / RECONNAISSANCE ──────────────────────
        if flags.S and not flags.A:
            self.total_syn += 1

            # Log each newly discovered port probe
            port_key = (ip_src, ip_dst, dport)
            if port_key not in self.discovered_ports:
                self.discovered_ports.add(port_key)
                svc = SERVICE_MAP.get(dport, f"Unknown (port {dport})")
                log_alert(
                    "INFO", "PROBE_DETECTED", "T1046",
                    f"SYN probe → {ip_dst}:{dport} ({svc}) from {ip_src} [Probe #{len(self.discovered_ports)}]"
                )

            # Sliding window for scan-burst detection
            history = self.port_scan_tracker[ip_src]
            history.append((now, dport))
            while history and history[0][0] < (now - self.SCAN_WINDOW):
                history.popleft()

            unique_ports = {p for _, p in history}
            if len(unique_ports) >= self.SCAN_PORT_THRESHOLD and not self.scan_alerted:
                self.scan_alerted = True
                log_alert(
                    "HIGH", "PORT_SCAN_CONFIRMED", "T1046",
                    f"Automated port scan CONFIRMED from {ip_src} → {ip_dst} | "
                    f"{len(unique_ports)} unique ports probed in {self.SCAN_WINDOW}s | "
                    f"Total SYN packets observed: {self.total_syn}"
                )

            # ── RULE 2: SSH BRUTE FORCE ─────────────────────────────
            if dport == 22:
                self.ssh_attempt_count += 1
                if self.brute_force_start_time is None:
                    self.brute_force_start_time = now

                ssh_history = self.ssh_conn_tracker[ip_src]
                ssh_history.append(now)
                while ssh_history and ssh_history[0] < (now - self.SSH_WINDOW):
                    ssh_history.popleft()

                elapsed = round(now - self.brute_force_start_time, 1)
                rate = round(self.ssh_attempt_count / elapsed, 2) if elapsed > 0 else 0

                # Log every SSH connection attempt
                log_alert(
                    "WARNING", "SSH_AUTH_ATTEMPT", "T1110.001",
                    f"SSH connection attempt #{self.ssh_attempt_count} from {ip_src} → {ip_dst}:22 | "
                    f"Elapsed: {elapsed}s | Rate: {rate} conn/s"
                )

                # Threshold-based brute force confirmation
                if len(ssh_history) >= self.SSH_CONN_THRESHOLD and not self.brute_force_alerted:
                    self.brute_force_alerted = True
                    log_alert(
                        "CRITICAL", "BRUTE_FORCE_CONFIRMED", "T1110.001",
                        f"SSH credential brute-force CONFIRMED from {ip_src} → {ip_dst}:22 | "
                        f"{len(ssh_history)} attempts in {self.SSH_WINDOW}s window | "
                        f"Total SSH probes: {self.ssh_attempt_count}"
                    )

        # ── RULE 3: POST-EXPLOITATION / INTERACTIVE SHELL ───────────
        if (sport == 22 or dport == 22) and flags.P:
            if self.brute_force_alerted:
                self.interactive_packet_count += 1

                direction_key = (ip_src, ip_dst, "shell_session")
                if direction_key not in self.exploit_alerted_directions:
                    self.exploit_alerted_directions.add(direction_key)

                    if ip_src == "10.0.100.10":
                        direction_label = "ATTACKER→TARGET (command injection)"
                    else:
                        direction_label = "TARGET→ATTACKER (data exfiltration)"

                    log_alert(
                        "CRITICAL", "ACTIVE_COMPROMISE", "T1059.004",
                        f"Interactive SSH shell traffic detected: {ip_src} → {ip_dst} | "
                        f"Direction: {direction_label} | "
                        f"Indicator: TCP PSH+ACK on established session post-brute-force"
                    )

                # Periodic exploitation traffic updates
                if self.interactive_packet_count % 10 == 0:
                    log_alert(
                        "HIGH", "EXFIL_TRAFFIC", "T1082",
                        f"Sustained post-exploitation traffic: {self.interactive_packet_count} interactive packets "
                        f"exchanged between {ip_src} and {ip_dst} on SSH channel"
                    )

def main():
    open(LOG_FILE, "w").close()

    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    startup_msgs = [
        f"[{timestamp}] [INFO] [SYSTEM] [—] Detection Engine v2.0 initialized",
        f"[{timestamp}] [INFO] [SYSTEM] [—] Binding passive sniffer to interface: {INTERFACE}",
        f"[{timestamp}] [INFO] [SYSTEM] [—] BPF filter: tcp and (net 10.0.100.0/24)",
        f"[{timestamp}] [INFO] [SYSTEM] [—] Detection rules loaded: PORT_SCAN, BRUTE_FORCE, ACTIVE_COMPROMISE",
        f"[{timestamp}] [INFO] [SYSTEM] [—] MITRE ATT&CK mapping: T1046, T1110.001, T1059.004, T1082",
        f"[{timestamp}] [INFO] [SYSTEM] [—] Awaiting network activity on 10.0.100.0/24 ..."
    ]
    for msg in startup_msgs:
        print(msg, flush=True)
    with open(LOG_FILE, "a") as f:
        for msg in startup_msgs:
            f.write(msg + "\n")

    detector = IntrusionDetector()
    bpf_filter = "tcp and (net 10.0.100.0/24)"

    sniffer = AsyncSniffer(
        iface=INTERFACE,
        filter=bpf_filter,
        prn=detector.process_packet,
        store=False
    )
    sniffer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping detector...")
    finally:
        sniffer.stop()
        sniffer.join()
        total = detector.total_packets
        log_alert("INFO", "SYSTEM", "—",
                  f"Detection Engine stopped. Total packets analyzed: {total}")

if __name__ == "__main__":
    main()

