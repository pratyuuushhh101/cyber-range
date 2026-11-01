#!/usr/bin/env python3
"""Passive detector for the original isolated cyber-range attack chain.

It detects network patterns visible in packet headers. SSH authentication is
encrypted, so packets alone cannot reveal failed passwords or successful login.
"""

import datetime
import os
import time
from collections import defaultdict, deque

from scapy.all import AsyncSniffer, IP, TCP

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "detection_log.txt")
INTERFACE = os.environ.get("CYBERRANGE_INTERFACE", "eth0")

SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 111: "RPCBind", 139: "NetBIOS", 445: "SMB",
    512: "rexec", 513: "rlogin", 514: "rsh", 1099: "Java-RMI",
    1524: "Backdoor service", 2049: "NFS", 2121: "FTP",
    3306: "MySQL", 5432: "PostgreSQL", 5900: "VNC", 6000: "X11",
    6667: "IRC", 8009: "AJP", 8180: "HTTP"
}


def log_alert(severity, category, mitre, message):
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    line = f"[{timestamp}] [{severity}] [{category}] [{mitre}] {message}"
    print(line, flush=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")


class IntrusionDetector:
    def __init__(self):
        self.total_packets = 0
        self.total_syn = 0
        self.discovered_ports = set()
        self.port_scan_tracker = defaultdict(deque)
        self.port_scan_alerted = set()
        self.ssh_conn_tracker = defaultdict(deque)
        self.ssh_burst_alerted = set()
        self.ssh_payload_sessions = set()
        self.ssh_payload_packets = defaultdict(int)
        self.login_failure_tracker = defaultdict(deque)
        self.login_pattern_alerted = set()

        self.SCAN_WINDOW = 15.0
        self.SCAN_PORT_THRESHOLD = 8
        self.SSH_WINDOW = 30.0
        self.SSH_CONNECTION_THRESHOLD = 4
        self.LOGIN_WINDOW = 20.0
        self.LOGIN_EVENT_THRESHOLD = 5

    def process_login_event(self, username, outcome_or_label, outcome=None):
        """Handle optional app-supplied login outcome events.

        Older dashboard revisions passed (username, scenario, outcome). The
        scenario argument is deliberately ignored; classification uses only
        outcome timestamps. Network packets do not call this method.
        """
        actual_outcome = outcome if outcome is not None else outcome_or_label
        now = time.monotonic()

        if actual_outcome == "login_failed":
            history = self.login_failure_tracker[username]
            history.append(now)
            while history and history[0] < now - self.LOGIN_WINDOW:
                history.popleft()
            log_alert(
                "INFO", "LOGIN_FAILURE_EVENT", "—",
                f"User={username}; {len(history)} failed-login events in {self.LOGIN_WINDOW:.0f}s "
                "(event source must provide the authentication outcome)"
            )
            if len(history) < self.LOGIN_EVENT_THRESHOLD or username in self.login_pattern_alerted:
                return

            samples = list(history)[-self.LOGIN_EVENT_THRESHOLD:]
            intervals = [samples[i] - samples[i - 1] for i in range(1, len(samples))]
            average = sum(intervals) / len(intervals) if intervals else 0.0
            variance = sum((x - average) ** 2 for x in intervals) / len(intervals) if intervals else 0.0
            cv = (variance ** 0.5) / average if average else 0.0
            if average <= 0.8 and cv <= 0.25:
                category, severity, description = (
                    "AUTOMATION_LIKE_TIMING", "WARNING", "rapid, regular failure timing"
                )
            else:
                category, severity, description = (
                    "HUMAN_LIKE_TIMING", "INFO", "slower or variable failure timing"
                )
            log_alert(
                severity, category, "—",
                f"{description}; {len(samples)} events, mean interval={average:.2f}s, "
                f"interval variation={cv:.2f}. Timing is not identity proof."
            )
            self.login_pattern_alerted.add(username)
        elif actual_outcome in ("password_reset_requested", "login_success"):
            log_alert("INFO", actual_outcome.upper(), "—", f"User={username}")
        else:
            raise ValueError(f"Unsupported login event outcome: {actual_outcome}")

    def process_packet(self, pkt):
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            return

        self.total_packets += 1
        ip_src, ip_dst = pkt[IP].src, pkt[IP].dst
        tcp = pkt[TCP]
        dport, sport = tcp.dport, tcp.sport
        flags = tcp.flags
        now = time.monotonic()

        # A SYN is a TCP connection attempt, not proof of an authentication attempt.
        if flags.S and not flags.A:
            self.total_syn += 1
            key = (ip_src, ip_dst)
            port_key = (ip_src, ip_dst, dport)
            if port_key not in self.discovered_ports:
                self.discovered_ports.add(port_key)
                service = SERVICE_MAP.get(dport, f"port {dport}")
                log_alert(
                    "INFO", "CONNECTION_PROBE", "T1046",
                    f"Source={ip_src}; destination={ip_dst}:{dport}; service={service}"
                )

            probes = self.port_scan_tracker[key]
            probes.append((now, dport))
            while probes and probes[0][0] < now - self.SCAN_WINDOW:
                probes.popleft()
            unique_ports = {port for _, port in probes}
            if len(unique_ports) >= self.SCAN_PORT_THRESHOLD and key not in self.port_scan_alerted:
                self.port_scan_alerted.add(key)
                log_alert(
                    "WARNING", "PORT_SCAN_PATTERN", "T1046",
                    f"Source={ip_src}; destination={ip_dst}; unique ports={len(unique_ports)} "
                    f"within {self.SCAN_WINDOW:.0f}s"
                )

            if dport == 22:
                ssh_key = (ip_src, ip_dst)
                attempts = self.ssh_conn_tracker[ssh_key]
                attempts.append(now)
                while attempts and attempts[0] < now - self.SSH_WINDOW:
                    attempts.popleft()
                log_alert(
                    "INFO", "SSH_CONNECTION_ATTEMPT", "—",
                    f"Source={ip_src}; destination={ip_dst}:22; observed connection #{len(attempts)} "
                    f"in the current {self.SSH_WINDOW:.0f}s window; authentication result unknown"
                )
                if len(attempts) >= self.SSH_CONNECTION_THRESHOLD and ssh_key not in self.ssh_burst_alerted:
                    self.ssh_burst_alerted.add(ssh_key)
                    log_alert(
                        "WARNING", "SSH_CONNECTION_BURST", "—",
                        f"Source={ip_src}; destination={ip_dst}:22; {len(attempts)} TCP connection "
                        f"attempts within {self.SSH_WINDOW:.0f}s; this does not confirm failed passwords"
                    )

        # SSH payload remains encrypted; this records traffic only, not shell commands.
        if (sport == 22 or dport == 22) and flags.P:
            session = (ip_src, ip_dst, sport, dport)
            self.ssh_payload_packets[session] += 1
            if session not in self.ssh_payload_sessions:
                self.ssh_payload_sessions.add(session)
                log_alert(
                    "INFO", "SSH_PAYLOAD_ACTIVITY", "—",
                    f"SSH payload observed from {ip_src} to {ip_dst}; encrypted contents not inspected"
                )


def main():
    open(LOG_FILE, "w", encoding="utf-8").close()
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    startup = [
        f"[{timestamp}] [INFO] [SYSTEM] [—] Detector started",
        f"[{timestamp}] [INFO] [SYSTEM] [—] Interface={INTERFACE}",
        f"[{timestamp}] [INFO] [SYSTEM] [—] Monitoring TCP packet metadata; SSH authentication is encrypted",
        f"[{timestamp}] [INFO] [SYSTEM] [—] Rules: port-scan pattern, SSH connection burst, SSH payload activity",
    ]
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        for line in startup:
            print(line, flush=True)
            f.write(line + "\n")

    detector = IntrusionDetector()
    sniffer = AsyncSniffer(
        iface=INTERFACE,
        filter="tcp and net 10.0.100.0/24",
        prn=detector.process_packet,
        store=False,
    )
    sniffer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping detector...", flush=True)
    finally:
        sniffer.stop()
        sniffer.join()
        log_alert("INFO", "SYSTEM", "—", f"Detector stopped; packets observed={detector.total_packets}")


if __name__ == "__main__":
    main()
