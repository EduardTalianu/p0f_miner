# p0f_miner


# p0f-miner.py – Advanced Passive PCAP Enumerator for Red-Team

## What it is
A drop-in replacement for the legacy `p0f-client` that turns the venerable p0f fingerprinting engine into a real-time, **IP-grouped** reconnaissance weapon.  
Feed it a live interface or an old PCAP and it will:
1. Build per-host OS / service / distance / NAT profiles in memory  
2. Surface only the “juicy” stuff (EOL boxes, scanners, ADCS, DBs, Citrix, …)  
3. Dump everything into a timestamped **human-readable report** + **machine-friendly JSON**  
4. Keep 70+ curated grep rules as ready-to-use `*.log` files for later pivot scripting

## TL;DR
```bash
# Live fire – intelligence summaries every 15 s
sudo ./p0f-miner.py -i eth0

# Offline forensics – full IP-centric report
./p0f-miner.py -r suspicious.pcap

# Want packet-level noise while it runs?
./p0f-miner.py -i eth0 -v


Install
apt install p0f (or build latest)
pip3 install notify2 (optional – desktop notifications)
Drop p0f-miner.py anywhere in $PATH and chmod +x it.
Why this beats “grep full.log”
Noise reduction: > 70 detection rules with severity emojis; only high-value hits are printed unless you ask for -v.
IP correlation: every OS, service, scanner or suspicious flag is tied to an IP hashmap, so the final report is grouped by host, not scattered lines.
Instant artefacts: eol.log, dc-candidates.log, mysql-servers.log, vpn-endpoints.log, … ready for xargs, nikto, crackmapexec, etc.
JSON export: p0f_profiles_20251021_143052.json gives you a structured list of every host with OS, distance, services, NAT, EOL flag, uptime, link type – perfect for importing into BloodHound, Elastic, or your CI pipeline.
Safe exit: Ctrl-C prints the final IP-centric report and kills the background p0f process; no stale PID files.
Command reference
Table
Copy
Switch	Purpose
-i IFACE	Live capture (requires root)
-r file.pcap	Offline analysis
-L	List interfaces then quit
-p	Promiscuous mode (live)
-v	Verbose – show every packet
-u SEC	Intelligence update interval (default 15 s)
Output files (all time-stamped)
p0f_report_*.txt – Human-readable executive summary grouped by IP
p0f_profiles_*.json – Machine-readable host database
full.log – Raw p0f output (kept for re-grep)
*.log – Individual category files (e.g. rdp-endpoints.log, scada-systems.log, …)



High-value patterns detected
EOL: XP, 2003, 2000, 7 (non-kernel)
Distance 0-2 (same subnet / 1-2 hops)
NAT=yes, bad_sw=1|2 (fake UA / OS mismatch)
Scanner UA: nmap, masscan, sqlmap, Nessus, Burp, Metasploit
Server ports: 3389 (RDP), 445/139 (SMB), 22 (SSH), 3306, 5432, 27017, 6379, 1521, 1433
mgmt: iLO, iDRAC, Citrix, VMware, ESXi, Hyper-V
Cloud: AWS, Azure, GCP metadata
VPN: OpenVPN, IPsec
DevOps: Jenkins, Git, Docker registry, Kubernetes API, Artifactory
Network infra: F5, HAProxy, Palo Alto, Fortinet, Cisco, Squid
Auth: LDAP, AD, RADIUS, TACACS
Files: FTP, NFS, WebDAV, SharePoint, Confluence
VoIP/ICS: SIP, Asterisk, SCADA, PLC
