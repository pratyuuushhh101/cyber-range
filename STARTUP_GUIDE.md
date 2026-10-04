# Startup Guide — Cyber Range Platform

Complete step-by-step guide to get the platform running from a cold boot.

## Prerequisites (one-time setup)

- VirtualBox installed on host machine
- Kali Linux VM imported (name: `kali-linux-2026.2-virtualbox-amd64`)
- Metasploitable2 VM imported (name: `Metasploitable2`)
- Both VMs on Internal Network named `cyberrange`
- Kali has a second NAT adapter for internet access
- Python packages installed on Kali: `flask`, `python-nmap`, `paramiko`, `scapy`

---

## Startup Procedure

### Step 1: Start the VMs

Open a terminal on your **host machine** (Ubuntu laptop) and run:

    VBoxManage startvm "kali-linux-2026.2-virtualbox-amd64" --type gui
    VBoxManage startvm "Metasploitable2" --type gui

Wait approximately 60 seconds for both VMs to fully boot.

---

### Step 2: Configure Metasploitable2

Click into the **Metasploitable2 VM window** and log in:

    Login: msfadmin
    Password: msfadmin

Then set the static IP:

    sudo ifconfig eth0 10.0.100.20 netmask 255.255.255.0 up

---

### Step 3: Configure Kali

In the **Kali VM**, log in (`kali` / `kali`), open a terminal, and run:

    sudo ip addr add 10.0.100.10/24 dev eth0
    sudo ip link set eth0 up
    sudo ip route add 10.0.100.0/24 dev eth0

---

### Step 4: Verify Network Connectivity

In the **Kali terminal**, run:

    ping -c 2 10.0.100.20

You MUST see `0% packet loss`. If the ping fails:

- Re-check Metasploitable2 IP: log into it and run `ifconfig eth0`
- Re-check Kali IP: run `ip a` and confirm `10.0.100.10` is on `eth0`
- Re-check route: run `ip route` and confirm `10.0.100.0/24 dev eth0` exists

---

### Step 5: Launch the Dashboard

In the **Kali terminal**, run:

    sudo python3 ~/app.py

You will see:

    * Running on all addresses (0.0.0.0)
    * Running on http://127.0.0.1:5000

---

### Step 6: Open in Browser

Open **Firefox inside Kali** and navigate to:

    http://localhost:5000

Click the red **Launch Attack Chain** button and watch both panels populate live.

---

## Quick One-Liner (Steps 3-5 combined)

After both VMs are booted and Metasploitable2 IP is set, paste this single command in Kali:

    sudo ip addr add 10.0.100.10/24 dev eth0 2>/dev/null; sudo ip link set eth0 up; sudo ip route add 10.0.100.0/24 dev eth0 2>/dev/null; ping -c 1 10.0.100.20 && echo "Network OK" && sudo python3 ~/app.py

---

## Shutdown

On your **host machine terminal**:

    VBoxManage controlvm "kali-linux-2026.2-virtualbox-amd64" poweroff
    VBoxManage controlvm "Metasploitable2" poweroff

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Ping fails (100% loss) | Re-run IP assignment on both VMs (Steps 2 and 3) |
| Nmap finds only 1-2 ports | Run attack script with `sudo`; check route with `ip route` |
| SSH brute-force times out | Restart SSH on Metasploitable2: `sudo /etc/init.d/ssh restart` |
| Dashboard not loading | Check `sudo python3 ~/app.py` is running without errors |
| Port 22 shows "filtered" | Restart SSH on Metasploitable2: `sudo /etc/init.d/ssh restart` |
