# Two-Sided Cyber Range Platform

An integrated cybersecurity training environment that executes an automated multi-stage attack chain against a deliberately vulnerable target and detects each stage in real time using passive network traffic analysis.

## Architecture

    Host Machine (Dashboard + Browser)
            |
       vboxnet0 / Internal Network (10.0.100.0/24)
            |
      +-------------+        +----------------+
      |   Kali VM   |        | Metasploitable2|
      | 10.0.100.10 |<------>|  10.0.100.20   |
      |  (Attacker) |        |   (Target)     |
      +-------------+        +----------------+

## Components

| Component | File | Description |
|-----------|------|-------------|
| Attack Engine | attack_chain.py | Automated 4-stage attack: Nmap recon, service enumeration, SSH brute-force, post-exploitation triage |
| Detection Engine | detector.py | Scapy-based passive NIDS that sniffs packets and flags port scans, brute-force attempts, and active compromise |
| Dashboard | app.py | Flask web server with live dual-panel dashboard, one-click orchestration, unified timeline, and incident report |
| Credential Dictionary | wordlist.txt | Curated 50-entry password list for brute-force demonstration |

## MITRE ATT&CK Coverage

| Technique ID | Name | Attack Stage |
|-------------|------|-------------|
| T1046 | Network Service Discovery | Stage 1: Reconnaissance |
| T1592 | Gather Victim Host Information | Stage 2: Service Enumeration |
| T1110.001 | Password Guessing | Stage 3: Credential Attack |
| T1059.004 | Unix Shell Execution | Stage 4: Exploitation |
| T1082 | System Information Discovery | Stage 4: Post-Exploitation Triage |

## Lab Setup

### Prerequisites
- VirtualBox 7.x
- Kali Linux VM (2024+)
- Metasploitable2 VM

### Network Configuration
1. Set both VMs to Internal Network named "cyberrange"
2. Assign static IPs:
   - Kali: sudo ip addr add 10.0.100.10/24 dev eth0
   - Metasploitable2: sudo ifconfig eth0 10.0.100.20 netmask 255.255.255.0 up
3. Add a second NAT adapter to Kali for internet/pip access

### Installation (on Kali)
    sudo pip3 install -r requirements.txt --break-system-packages

### Running
    sudo python3 app.py

Open http://localhost:5000 in a browser and click Launch Attack Chain.

## Deliverables
- Automated multi-stage attack chain runnable on demand
- Real-time passive NIDS detecting and classifying each attack stage
- Unified dashboard displaying attack and detection feeds side-by-side
- Auto-generated incident report with MITRE mapping and remediation recommendations

## Tech Stack
Python, Flask, Nmap (python-nmap), Paramiko, Scapy, HTML/CSS/JavaScript, VirtualBox, Kali Linux, Metasploitable2

