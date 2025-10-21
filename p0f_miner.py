#!/usr/bin/env python3
"""
p0f-miner.py — Advanced passive pcap enumerator for red-team
Shows only high-value detections by default, full logs with -v
"""
import os
import re
import subprocess
import sys
import time
import signal
import argparse
import threading
import json
from pathlib import Path
from datetime import datetime
from collections import defaultdict

try:
    import notify2
except ImportError:
    notify2 = None

# Global flags
shutdown_flag = False
live_stats = defaultdict(int)
ip_profiles = defaultdict(lambda: {
    'os': None,
    'os_detail': None,
    'distance': None,
    'services': set(),
    'scanners': set(),
    'suspicious': set(),
    'nat': False,
    'uptime': None,
    'link': None,
    'first_seen': None,
    'is_server': False,
    'is_eol': False
})
stats_lock = threading.Lock()
verbose_mode = False

# ANSI color codes
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

# ------------------------------------------------------------------
# Detection rules
# ------------------------------------------------------------------
ONELINERS = {
    "internal-only":     "grep -vE '^\\[.+\\]' full.log | grep -F '-> 192.168.'  > internal-only.log",
    "same-subnet":       "grep -vE '^\\[.+\\]' full.log | grep -E '10\\.|172\\.1[6-9]\\.|172\\.2[0-9]\\.|172\\.3[01]\\.|192\\.168\\.' | grep -F 'distance=0'  > same-subnet.log",
    "jump-candidates":   "grep -vE '^\\[.+\\]' full.log | grep -E 'distance=1|distance=2' | grep -F 'os=Windows'  > jump-candidates.log",
    "remote-sites":      "grep -vE '^\\[.+\\]' full.log | grep -E 'link=DSL|link=modem' | grep -E 'distance=[5-9]'  > remote-sites.log",
    "dmz-hosts":         "grep -vE '^\\[.+\\]' full.log | grep 'distance=1' | grep 'subj=srv' | awk -F '|' '{{print $3}}' | sort -u  > dmz-servers.log",
    "natted":            "grep -vE '^\\[.+\\]' full.log | grep -F 'nat=yes'  > natted.log",
    "proxies":           "grep -vE '^\\[.+\\]' full.log | grep -F 'nat=yes' | grep 'mod=http'  > http-proxies.log",
    "direct-internet":   "grep -vE '^\\[.+\\]' full.log | grep -E 'distance=[3-9]|distance=1[0-9]' | awk -F '|' '{{print $2}}' | sort -u  > internet-exposed.log",
    "eol":               "grep -vE '^\\[.+\\]' full.log | grep -E 'os=Windows XP\\b|os=Windows 2003\\b|os=Windows 7\\b' | grep -v 'NT kernel'  > eol.log",
    "old-kernel":        "grep -vE '^\\[.+\\]' full.log | grep -E 'os=Linux 3\\.|os=Linux 2.6|os=Linux 2.4'  > old-kernel.log",
    "legacy":            "grep -vE '^\\[.+\\]' full.log | grep -E 'os=Windows 2000\\b|os=Windows 2003\\b|os=Windows NT\\b' | grep -v 'NT kernel' | awk -F '|' '{{print $2}}' | sort -u  > legacy.txt",
    "win-ips":           "grep -vE '^\\[.+\\]' full.log | grep -F 'os=Windows' | awk -F '|' '{{ip=$2; sub(/.*:/,\"\",ip); print ip}}' | sort -u  > win-ips.txt",
    "linux-ips":         "grep -vE '^\\[.+\\]' full.log | grep -F 'os=Linux' | awk -F '|' '{{ip=$2; sub(/.*:/,\"\",ip); print ip}}' | sort -u  > linux-ips.txt",
    "bsd-systems":       "grep -vE '^\\[.+\\]' full.log | grep -E 'os=FreeBSD|os=OpenBSD|os=NetBSD'  > bsd-systems.log",
    "macos-systems":     "grep -vE '^\\[.+\\]' full.log | grep -E 'os=Mac OS X|os=iOS'  > macos-systems.log",
    "client-os":         "grep -vE '^\\[.+\\]' full.log | grep 'subj=cli' | grep -F 'os=' | awk -F '|' '{{for(i=1;i<=NF;i++)if($i~/os=/)print $2,$i}}' | sort -u  > client-operating-systems.log",
    "server-os":         "grep -vE '^\\[.+\\]' full.log | grep 'subj=srv' | grep -F 'os=' | awk -F '|' '{{for(i=1;i<=NF;i++)if($i~/os=/)print $2,$i}}' | sort -u  > server-operating-systems.log",
    "win10-servers":     "grep -vE '^\\[.+\\]' full.log | grep -F 'srv=' | grep -F 'os=Windows 10'  > win10-servers.log",
    "win-servers":       "grep -vE '^\\[.+\\]' full.log | grep -E 'os=Windows 2012|os=Windows 2016|os=Windows 2019|os=Windows 2022' | awk -F '|' '{{print $2}}' | sort -u  > windows-servers.log",
    "dc-candidates":     "grep -vE '^\\[.+\\]' full.log | grep -E 'distance=0|distance=1|distance=2' | grep -E 'os=Windows 2012|os=Windows 2016|os=Windows 2019|os=Windows 2022'  > domain-controllers.log",
    "win-workstations":  "grep -vE '^\\[.+\\]' full.log | grep -E 'os=Windows 7|os=Windows 8|os=Windows 10|os=Windows 11' | grep 'subj=cli'  > windows-workstations.log",
    "rdp-candidates":    "grep -vE '^\\[.+\\]' full.log | grep -F 'os=Windows' | grep -E ':3389 |-> [0-9.]+:3389'  > rdp-endpoints.log",
    "smb-hosts":         "grep -vE '^\\[.+\\]' full.log | grep -F 'os=Windows' | grep -E ':445 |:139 '  > smb-enabled.log",
    "linux-srv":         "grep -vE '^\\[.+\\]' full.log | grep 'subj=srv' | grep -F 'os=Linux'  > linux-servers.log",
    "ssh-boxes":         "grep -vE '^\\[.+\\]' full.log | grep -F 'os=Linux' | grep -E ':22 |/22 '  > ssh-boxes.log",
    "ubuntu-hosts":      "grep -vE '^\\[.+\\]' full.log | grep -E 'os=Linux 3.1[3-9]|os=Linux [4-5]' | grep -F 'dist=0'  > ubuntu-modern.log",
    "centos-rhel":       "grep -vE '^\\[.+\\]' full.log | grep -F 'os=Linux' | grep -E 'dist=[1-3]'  > centos-rhel.log",
    "http-clients":      "grep -vE '^\\[.+\\]' full.log | grep 'mod=http request' | awk -F '|' '{{for(i=1;i<=NF;i++)if($i~/app=/)print $2,$i}}'  > http-clients.log",
    "http-servers":      "grep -vE '^\\[.+\\]' full.log | grep 'mod=http response' | awk -F '|' '{{for(i=1;i<=NF;i++)if($i~/app=/)print $2,$i}}'  > http-servers.log",
    "apache-servers":    "grep -vE '^\\[.+\\]' full.log | grep 'mod=http response' | grep -E 'app=Apache|http=Apache'  > apache-servers.log",
    "nginx-servers":     "grep -vE '^\\[.+\\]' full.log | grep 'mod=http response' | grep -E 'app=nginx|http=nginx'  > nginx-servers.log",
    "iis-servers":       "grep -vE '^\\[.+\\]' full.log | grep 'mod=http response' | grep -E 'app=IIS|http=IIS|http=Microsoft'  > iis-servers.log",
    "browsers":          "grep -vE '^\\[.+\\]' full.log | grep -E 'app=Firefox|app=Chrome|app=Safari|app=Edge|app=Opera'  > browsers.log",
    "bad-useragent":     "grep -vE '^\\[.+\\]' full.log | grep -F 'bad_sw=' | grep -v 'bad_sw=0'  > dishonest-useragents.log",
    "scripted-traffic":  "grep -vE '^\\[.+\\]' full.log | grep -E 'app=Python|app=curl|app=Go-http|app=Java|http=Python|http=curl'  > scripted-traffic.log",
    "python-tools":      "grep -vE '^\\[.+\\]' full.log | grep -E 'app=Python|http=Python|http=requests'  > python-scripts.log",
    "scripts-on-windows": "grep -vE '^\\[.+\\]' full.log | grep -F 'os=Windows' | grep -E 'app=Python|app=curl|http=Python'  > suspicious-automation.log",
    "iot":               "grep -vE '^\\[.+\\]' full.log | grep -v -E 'Windows|Linux|Mac OS X|BSD|Solaris' | grep -F 'os='  > iot.log",
    "mobile":            "grep -vE '^\\[.+\\]' full.log | grep -E 'os=Android|os=iPhone|os=iOS'  > mobile-devices.log",
    "printers":          "grep -vE '^\\[.+\\]' full.log | grep -E 'os=Printer|os=Lexmark|os=HP|os=Canon|os=Epson' | awk -F '|' '{{print $2}}'  > printers.log",
    "mgmt-interfaces":   "grep -vE '^\\[.+\\]' full.log | grep -E 'app=Citrix|app=VMware|app=Dell|http=Citrix|http=VMware|http=iLO|http=iDRAC'  > mgmt-interfaces.log",
    "security-appl":     "grep -vE '^\\[.+\\]' full.log | grep -E 'app=Barracuda|app=Fortinet|app=SonicWALL|app=Palo Alto|http=Barracuda|http=Fortinet'  > security-appliances.log",
    "blue-scanners":     "grep -vE '^\\[.+\\]' full.log | grep -E 'app=nmap|app=masscan|http=Scanner|http=Nikto|http=sqlmap|http=Nessus' | awk -F '|' '{{print $2,$3}}'  > blue-team-scanners.log",
    "pentesting-tools":  "grep -vE '^\\[.+\\]' full.log | grep -E 'http=Metasploit|http=sqlmap|http=Burp|http=ZAP'  > pentesting-tools.log",
    
    # Database servers
    "mysql-servers":      "grep -vE '^\\[.+\\]' full.log | grep -E ':3306 |/3306 ' | grep -F 'os=' | awk -F '|' '{{print $2,$3}}' | sort -u  > mysql-servers.log",
    "postgresql-servers": "grep -vE '^\\[.+\\]' full.log | grep -E ':5432 |/5432 ' | grep -F 'os=' | awk -F '|' '{{print $2,$3}}' | sort -u  > postgresql-servers.log",
    "oracle-servers":     "grep -vE '^\\[.+\\]' full.log | grep -E ':1521 |/1521 ' | grep -F 'os=' | awk -F '|' '{{print $2,$3}}' | sort -u  > oracle-servers.log",
    "mssql-servers":      "grep -vE '^\\[.+\\]' full.log | grep -E ':1433 |/1433 ' | grep -F 'os=Windows' | awk -F '|' '{{print $2,$3}}' | sort -u  > mssql-servers.log",
    "redis-servers":      "grep -vE '^\\[.+\\]' full.log | grep -E ':6379 |/6379 ' | grep -F 'os=' | awk -F '|' '{{print $2,$3}}' | sort -u  > redis-servers.log",
    "mongodb-servers":    "grep -vE '^\\[.+\\]' full.log | grep -E ':27017 |/27017 ' | grep -F 'os=' | awk -F '|' '{{print $2,$3}}' | sort -u  > mongodb-servers.log",
    
    # Development and DevOps environments
    "jenkins-servers":    "grep -vE '^\\[.+\\]' full.log | grep -E 'app=Jenkins|http=Jenkins' | awk -F '|' '{{print $2,$3}}' | sort -u  > jenkins-servers.log",
    "git-servers":        "grep -vE '^\\[.+\\]' full.log | grep -E ':9418 |/9418 |app=Git|http=Git' | awk -F '|' '{{print $2,$3}}' | sort -u  > git-servers.log",
    "docker-registries":  "grep -vE '^\\[.+\\]' full.log | grep -E ':5000 |/5000 |app=Docker|http=Docker' | awk -F '|' '{{print $2,$3}}' | sort -u  > docker-registries.log",
    "kubernetes-api":     "grep -vE '^\\[.+\\]' full.log | grep -E ':6443 |/6443 |app=Kubernetes|http=Kubernetes' | awk -F '|' '{{print $2,$3}}' | sort -u  > kubernetes-api.log",
    "artifactory":        "grep -vE '^\\[.+\\]' full.log | grep -E 'app=Artifactory|http=Artifactory' | awk -F '|' '{{print $2,$3}}' | sort -u  > artifactory.log",
    "nexus":              "grep -vE '^\\[.+\\]' full.log | grep -E 'app=Nexus|http=Nexus' | awk -F '|' '{{print $2,$3}}' | sort -u  > nexus.log",
    
    # Cloud services
    "aws-services":       "grep -vE '^\\[.+\\]' full.log | grep -E 'app=AWS|http=AWS|app=Amazon|http=Amazon' | awk -F '|' '{{print $2,$3}}' | sort -u  > aws-services.log",
    "azure-services":     "grep -vE '^\\[.+\\]' full.log | grep -E 'app=Azure|http=Azure|app=Microsoft|http=Microsoft' | awk -F '|' '{{print $2,$3}}' | sort -u  > azure-services.log",
    "gcp-services":       "grep -vE '^\\[.+\\]' full.log | grep -E 'app=GCP|http=GCP|app=Google|http=Google' | awk -F '|' '{{print $2,$3}}' | sort -u  > gcp-services.log",
    
    # VPN endpoints
    "vpn-endpoints":      "grep -vE '^\\[.+\\]' full.log | grep -E ':1194 |/1194 |:500 |/500 |:4500 |/4500 |app=VPN|http=VPN' | awk -F '|' '{{print $2,$3}}' | sort -u  > vpn-endpoints.log",
    "openvpn":            "grep -vE '^\\[.+\\]' full.log | grep -E 'app=OpenVPN|http=OpenVPN' | awk -F '|' '{{print $2,$3}}' | sort -u  > openvpn.log",
    "ipsec-vpn":          "grep -vE '^\\[.+\\]' full.log | grep -E 'app=IPSec|http=IPSec' | awk -F '|' '{{print $2,$3}}' | sort -u  > ipsec-vpn.log",
    
    # File sharing services
    "ftp-servers":        "grep -vE '^\\[.+\\]' full.log | grep -E ':21 |/21 |app=FTP|http=FTP' | awk -F '|' '{{print $2,$3}}' | sort -u  > ftp-servers.log",
    "nfs-servers":        "grep -vE '^\\[.+\\]' full.log | grep -E ':2049 |/2049 |app=NFS|http=NFS' | awk -F '|' '{{print $2,$3}}' | sort -u  > nfs-servers.log",
    "sftp-servers":       "grep -vE '^\\[.+\\]' full.log | grep -E 'app=SFTP|http=SFTP' | awk -F '|' '{{print $2,$3}}' | sort -u  > sftp-servers.log",
    "webdav":             "grep -vE '^\\[.+\\]' full.log | grep -E 'app=WebDAV|http=WebDAV' | awk -F '|' '{{print $2,$3}}' | sort -u  > webdav.log",
    
    # Email servers
    "smtp-servers":       "grep -vE '^\\[.+\\]' full.log | grep -E ':25 |/25 |:587 |/587 |app=SMTP|http=SMTP' | awk -F '|' '{{print $2,$3}}' | sort -u  > smtp-servers.log",
    "pop3-servers":       "grep -vE '^\\[.+\\]' full.log | grep -E ':110 |/110 |:995 |/995 |app=POP3|http=POP3' | awk -F '|' '{{print $2,$3}}' | sort -u  > pop3-servers.log",
    "imap-servers":       "grep -vE '^\\[.+\\]' full.log | grep -E ':143 |/143 |:993 |/993 |app=IMAP|http=IMAP' | awk -F '|' '{{print $2,$3}}' | sort -u  > imap-servers.log",
    "exchange-servers":   "grep -vE '^\\[.+\\]' full.log | grep -E 'app=Exchange|http=Exchange|app=Outlook|http=Outlook' | awk -F '|' '{{print $2,$3}}' | sort -u  > exchange-servers.log",
    
    # DNS servers
    "dns-servers":        "grep -vE '^\\[.+\\]' full.log | grep -E ':53 |/53 |app=DNS|http=DNS' | awk -F '|' '{{print $2,$3}}' | sort -u  > dns-servers.log",
    "dns-over-https":     "grep -vE '^\\[.+\\]' full.log | grep -E ':853 |/853 |app=DoH|http=DoH' | awk -F '|' '{{print $2,$3}}' | sort -u  > dns-over-https.log",
    
    # Remote management tools
    "teamviewer":         "grep -vE '^\\[.+\\]' full.log | grep -E 'app=TeamViewer|http=TeamViewer' | awk -F '|' '{{print $2,$3}}' | sort -u  > teamviewer.log",
    "vnc-servers":        "grep -vE '^\\[.+\\]' full.log | grep -E ':5900 |/5900 |app=VNC|http=VNC' | awk -F '|' '{{print $2,$3}}' | sort -u  > vnc-servers.log",
    "anydesk":            "grep -vE '^\\[.+\\]' full.log | grep -E 'app=AnyDesk|http=AnyDesk' | awk -F '|' '{{print $2,$3}}' | sort -u  > anydesk.log",
    "rdp-gateway":        "grep -vE '^\\[.+\\]' full.log | grep -E 'app=RD Gateway|http=RD Gateway' | awk -F '|' '{{print $2,$3}}' | sort -u  > rdp-gateway.log",
    
    # Backup systems
    "backup-servers":     "grep -vE '^\\[.+\\]' full.log | grep -E 'app=Veeam|http=Veeam|app=Backup|http=Backup' | awk -F '|' '{{print $2,$3}}' | sort -u  > backup-servers.log",
    "veritas-backup":     "grep -vE '^\\[.+\\]' full.log | grep -E 'app=Veritas|http=Veritas' | awk -F '|' '{{print $2,$3}}' | sort -u  > veritas-backup.log",
    
    # Monitoring systems
    "zabbix":             "grep -vE '^\\[.+\\]' full.log | grep -E 'app=Zabbix|http=Zabbix' | awk -F '|' '{{print $2,$3}}' | sort -u  > zabbix.log",
    "nagios":             "grep -vE '^\\[.+\\]' full.log | grep -E 'app=Nagios|http=Nagios' | awk -F '|' '{{print $2,$3}}' | sort -u  > nagios.log",
    "splunk":             "grep -vE '^\\[.+\\]' full.log | grep -E 'app=Splunk|http=Splunk' | awk -F '|' '{{print $2,$3}}' | sort -u  > splunk.log",
    "grafana":            "grep -vE '^\\[.+\\]' full.log | grep -E 'app=Grafana|http=Grafana' | awk -F '|' '{{print $2,$3}}' | sort -u  > grafana.log",
    
    # Authentication systems
    "radius-servers":     "grep -vE '^\\[.+\\]' full.log | grep -E ':1812 |/1812 |:1813 |/1813 |app=RADIUS|http=RADIUS' | awk -F '|' '{{print $2,$3}}' | sort -u  > radius-servers.log",
    "tacacs-servers":     "grep -vE '^\\[.+\\]' full.log | grep -E ':49 |/49 |app=TACACS|http=TACACS' | awk -F '|' '{{print $2,$3}}' | sort -u  > tacacs-servers.log",
    "ldap-servers":       "grep -vE '^\\[.+\\]' full.log | grep -E ':389 |/389 |:636 |/636 |app=LDAP|http=LDAP' | awk -F '|' '{{print $2,$3}}' | sort -u  > ldap-servers.log",
    "ad-servers":         "grep -vE '^\\[.+\\]' full.log | grep -E 'app=Active Directory|http=Active Directory|app=AD|http=AD' | awk -F '|' '{{print $2,$3}}' | sort -u  > ad-servers.log",
    
    # VoIP systems
    "voip-servers":       "grep -vE '^\\[.+\\]' full.log | grep -E ':5060 |/5060 |:5061 |/5061 |app=VoIP|http=VoIP' | awk -F '|' '{{print $2,$3}}' | sort -u  > voip-servers.log",
    "asterisk":           "grep -vE '^\\[.+\\]' full.log | grep -E 'app=Asterisk|http=Asterisk' | awk -F '|' '{{print $2,$3}}' | sort -u  > asterisk.log",
    
    # Industrial control systems
    "scada-systems":      "grep -vE '^\\[.+\\]' full.log | grep -E 'app=SCADA|http=SCADA|app=PLC|http=PLC' | awk -F '|' '{{print $2,$3}}' | sort -u  > scada-systems.log",
    
    # Collaboration tools
    "slack":              "grep -vE '^\\[.+\\]' full.log | grep -E 'app=Slack|http=Slack' | awk -F '|' '{{print $2,$3}}' | sort -u  > slack.log",
    "teams":              "grep -vE '^\\[.+\\]' full.log | grep -E 'app=Teams|http=Teams' | awk -F '|' '{{print $2,$3}}' | sort -u  > teams.log",
    
    # Virtualization platforms
    "vmware-esxi":        "grep -vE '^\\[.+\\]' full.log | grep -E 'app=ESXi|http=ESXi|app=VMware|http=VMware' | awk -F '|' '{{print $2,$3}}' | sort -u  > vmware-esxi.log",
    "hyper-v":            "grep -vE '^\\[.+\\]' full.log | grep -E 'app=Hyper-V|http=Hyper-V' | awk -F '|' '{{print $2,$3}}' | sort -u  > hyper-v.log",
    "xen":                "grep -vE '^\\[.+\\]' full.log | grep -E 'app=Xen|http=Xen' | awk -F '|' '{{print $2,$3}}' | sort -u  > xen.log",
    
    # Development frameworks
    "nodejs":             "grep -vE '^\\[.+\\]' full.log | grep -E 'app=Node.js|http=Node.js|app=NodeJS|http=NodeJS' | awk -F '|' '{{print $2,$3}}' | sort -u  > nodejs.log",
    "django":             "grep -vE '^\\[.+\\]' full.log | grep -E 'app=Django|http=Django' | awk -F '|' '{{print $2,$3}}' | sort -u  > django.log",
    "rails":              "grep -vE '^\\[.+\\]' full.log | grep -E 'app=Rails|http=Rails' | awk -F '|' '{{print $2,$3}}' | sort -u  > rails.log",
    
    # Container technologies
    "container-hosts":    "grep -vE '^\\[.+\\]' full.log | grep -E 'app=Docker|http=Docker|app=Container|http=Container' | awk -F '|' '{{print $2,$3}}' | sort -u  > container-hosts.log",
    
    # High-value targets for lateral movement
    "psremoting":         "grep -vE '^\\[.+\\]' full.log | grep -E ':5985 |/5985 |:5986 |/5986 |app=WinRM|http=WinRM' | awk -F '|' '{{print $2,$3}}' | sort -u  > psremoting.log",
    "wmi":                "grep -vE '^\\[.+\\]' full.log | grep -E 'app=WMI|http=WMI' | awk -F '|' '{{print $2,$3}}' | sort -u  > wmi.log",
    "smb-signing":        "grep -vE '^\\[.+\\]' full.log | grep -E 'app=SMB signing|http=SMB signing' | awk -F '|' '{{print $2,$3}}' | sort -u  > smb-signing.log",
    
    # Unconventional ports
    "uncommon-ports":     "grep -vE '^\\[.+\\]' full.log | grep -E ':[0-9]{4,5} |/[0-9]{4,5} ' | grep -vE ':(80|443|22|3389|445|139|53|25|110|143|993|995|587) |/(80|443|22|3389|445|139|53|25|110|143|993|995|587) ' | awk -F '|' '{{print $2,$3}}' | sort -u  > uncommon-ports.log",
    
    # Potential misconfigurations
    "anonymous-ftp":      "grep -vE '^\\[.+\\]' full.log | grep -E 'app=Anonymous FTP|http=Anonymous FTP' | awk -F '|' '{{print $2,$3}}' | sort -u  > anonymous-ftp.log",
    "default-credentials": "grep -vE '^\\[.+\\]' full.log | grep -E 'app=default|http=default|app=admin|http=admin' | awk -F '|' '{{print $2,$3}}' | sort -u  > default-credentials.log",
    
    # Network infrastructure
    "load-balancers":     "grep -vE '^\\[.+\\]' full.log | grep -E 'app=F5|http=F5|app=HAProxy|http=HAProxy|app=Nginx|http=Nginx' | grep -F 'subj=srv' | awk -F '|' '{{print $2,$3}}' | sort -u  > load-balancers.log",
    "firewalls":          "grep -vE '^\\[.+\\]' full.log | grep -E 'app=Palo Alto|http=Palo Alto|app=Fortinet|http=Fortinet|app=Cisco|http=Cisco' | awk -F '|' '{{print $2,$3}}' | sort -u  > firewalls.log",
    "proxies-extended":   "grep -vE '^\\[.+\\]' full.log | grep -E 'app=Squid|http=Squid|app=Proxy|http=Proxy' | awk -F '|' '{{print $2,$3}}' | sort -u  > proxies-extended.log",
    
    # Potential data stores
    "file-servers":       "grep -vE '^\\[.+\\]' full.log | grep -E 'app=File Server|http=File Server|app=File Share|http=File Share' | awk -F '|' '{{print $2,$3}}' | sort -u  > file-servers.log",
    "sharepoint":         "grep -vE '^\\[.+\\]' full.log | grep -E 'app=SharePoint|http=SharePoint' | awk -F '|' '{{print $2,$3}}' | sort -u  > sharepoint.log",
    "confluence":         "grep -vE '^\\[.+\\]' full.log | grep -E 'app=Confluence|http=Confluence' | awk -F '|' '{{print $2,$3}}' | sort -u  > confluence.log",
}

# High-value detection patterns - FIXED to avoid false positives
HIGH_VALUE_PATTERNS = [
    (r'os=Windows XP\b', '🎯 END-OF-LIFE: Windows XP', Colors.RED),
    (r'os=Windows 2003\b', '🎯 LEGACY SERVER: Windows 2003', Colors.RED),
    (r'os=Windows 7\b', '⚠️  EOL SYSTEM: Windows 7', Colors.YELLOW),
    (r'os=Windows 2000\b', '🎯 ANCIENT: Windows 2000', Colors.RED),
    (r'os=Windows NT\b(?! kernel)', '🎯 ANCIENT: Windows NT 4.0', Colors.RED),  # Exclude "NT kernel"
    (r'os=Windows 2012\b', '💻 SERVER: Windows 2012', Colors.CYAN),
    (r'os=Windows 2016\b', '💻 SERVER: Windows 2016', Colors.CYAN),
    (r'os=Windows 2019\b', '💻 SERVER: Windows 2019', Colors.CYAN),
    (r'os=Windows 2022\b', '💻 SERVER: Windows 2022', Colors.CYAN),
    (r'distance=0\b', '📍 SAME SUBNET', Colors.GREEN),
    (r'distance=1\b', '🔗 1-HOP', Colors.CYAN),
    (r'distance=2\b', '🔗 2-HOPS', Colors.CYAN),
    (r'[:/]3389\b', '🔓 RDP', Colors.MAGENTA),
    (r'[:/]445\b', '📁 SMB', Colors.BLUE),
    (r'[:/]139\b', '📁 NETBIOS', Colors.BLUE),
    (r'[:/]22\b', '🔐 SSH', Colors.GREEN),
    (r'[:/]80\b', '🌐 HTTP', Colors.BLUE),
    (r'[:/]443\b', '🔒 HTTPS', Colors.BLUE),
    (r'nat=yes', '🌐 NAT', Colors.YELLOW),
    (r'bad_sw=1\b', '⚠️  UA/OS MISMATCH', Colors.YELLOW),
    (r'bad_sw=2\b', '🚨 FAKE USER-AGENT', Colors.RED),
    (r'app=Python|http=Python', '🐍 PYTHON', Colors.YELLOW),
    (r'app=curl|http=curl', '⚙️  CURL', Colors.YELLOW),
    (r'app=NMap|http=nmap', '🔍 NMAP SCAN', Colors.RED),
    (r'http=Nikto', '🔍 NIKTO SCAN', Colors.RED),
    (r'http=sqlmap', '💉 SQLMAP', Colors.RED),
    (r'http=Metasploit', '🎭 METASPLOIT', Colors.RED),
    (r'http=Burp', '🔧 BURP SUITE', Colors.RED),
    (r'app=Citrix|http=Citrix', '🏢 CITRIX', Colors.MAGENTA),
    (r'app=VMware|http=VMware', '☁️  VMWARE', Colors.MAGENTA),
    (r'http=iLO|http=iDRAC', '⚙️  MGMT INTERFACE', Colors.MAGENTA),
    
    # Database servers
    (r'[:/]3306\b', '🗄️ MYSQL', Colors.MAGENTA),
    (r'[:/]5432\b', '🗄️ POSTGRESQL', Colors.MAGENTA),
    (r'[:/]1521\b', '🗄️ ORACLE', Colors.MAGENTA),
    (r'[:/]1433\b', '🗄️ MSSQL', Colors.MAGENTA),
    (r'[:/]6379\b', '🗄️ REDIS', Colors.MAGENTA),
    (r'[:/]27017\b', '🗄️ MONGODB', Colors.MAGENTA),
    
    # Development and DevOps environments
    (r'app=Jenkins|http=Jenkins', '🔧 JENKINS', Colors.YELLOW),
    (r'app=Git|http=Git', '📦 GIT', Colors.YELLOW),
    (r'app=Docker|http=Docker', '🐳 DOCKER', Colors.YELLOW),
    (r'app=Kubernetes|http=Kubernetes', '☸️ KUBERNETES', Colors.YELLOW),
    (r'app=Artifactory|http=Artifactory', '📦 ARTIFACTORY', Colors.YELLOW),
    (r'app=Nexus|http=Nexus', '📦 NEXUS', Colors.YELLOW),
    
    # Cloud services
    (r'app=AWS|http=AWS', '☁️ AWS', Colors.CYAN),
    (r'app=Azure|http=Azure', '☁️ AZURE', Colors.CYAN),
    (r'app=GCP|http=GCP', '☁️ GCP', Colors.CYAN),
    
    # VPN endpoints
    (r'[:/]1194\b', '🔐 OPENVPN', Colors.GREEN),
    (r'[:/]500\b', '🔐 IPSEC', Colors.GREEN),
    (r'[:/]4500\b', '🔐 IPSEC-NAT', Colors.GREEN),
    
    # File sharing services
    (r'[:/]21\b', '📁 FTP', Colors.BLUE),
    (r'[:/]2049\b', '📁 NFS', Colors.BLUE),
    (r'app=SFTP|http=SFTP', '📁 SFTP', Colors.BLUE),
    (r'app=WebDAV|http=WebDAV', '📁 WEBDAV', Colors.BLUE),
    
    # Email servers
    (r'[:/]25\b', '📧 SMTP', Colors.BLUE),
    (r'[:/]587\b', '📧 SMTP-SUBMIT', Colors.BLUE),
    (r'[:/]110\b', '📧 POP3', Colors.BLUE),
    (r'[:/]995\b', '📧 POP3S', Colors.BLUE),
    (r'[:/]143\b', '📧 IMAP', Colors.BLUE),
    (r'[:/]993\b', '📧 IMAPS', Colors.BLUE),
    (r'app=Exchange|http=Exchange', '📧 EXCHANGE', Colors.BLUE),
    
    # DNS servers
    (r'[:/]53\b', '🌐 DNS', Colors.BLUE),
    (r'[:/]853\b', '🔒 DNS-OVER-HTTPS', Colors.BLUE),
    
    # Remote management tools
    (r'app=TeamViewer|http=TeamViewer', '🖥️ TEAMVIEWER', Colors.MAGENTA),
    (r'[:/]5900\b', '🖥️ VNC', Colors.MAGENTA),
    (r'app=AnyDesk|http=AnyDesk', '🖥️ ANYDESK', Colors.MAGENTA),
    (r'app=RD Gateway|http=RD Gateway', '🔓 RD-GATEWAY', Colors.MAGENTA),
    
    # Backup systems
    (r'app=Veeam|http=Veeam', '💾 BACKUP', Colors.YELLOW),
    (r'app=Veritas|http=Veritas', '💾 BACKUP', Colors.YELLOW),
    
    # Monitoring systems
    (r'app=Zabbix|http=Zabbix', '📊 ZABBIX', Colors.CYAN),
    (r'app=Nagios|http=Nagios', '📊 NAGIOS', Colors.CYAN),
    (r'app=Splunk|http=Splunk', '📊 SPLUNK', Colors.CYAN),
    (r'app=Grafana|http=Grafana', '📊 GRAFANA', Colors.CYAN),
    
    # Authentication systems
    (r'[:/]1812\b', '🔐 RADIUS', Colors.GREEN),
    (r'[:/]1813\b', '🔐 RADIUS-ACCT', Colors.GREEN),
    (r'[:/]49\b', '🔐 TACACS', Colors.GREEN),
    (r'[:/]389\b', '🔐 LDAP', Colors.GREEN),
    (r'[:/]636\b', '🔐 LDAPS', Colors.GREEN),
    (r'app=Active Directory|http=Active Directory', '🔐 AD', Colors.GREEN),
    
    # VoIP systems
    (r'[:/]5060\b', '📞 SIP', Colors.BLUE),
    (r'[:/]5061\b', '📞 SIP-TLS', Colors.BLUE),
    
    # Industrial control systems
    (r'app=SCADA|http=SCADA', '🏭 SCADA', Colors.RED),
    (r'app=PLC|http=PLC', '🏭 PLC', Colors.RED),
    
    # Collaboration tools
    (r'app=Slack|http=Slack', '💬 SLACK', Colors.MAGENTA),
    (r'app=Teams|http=Teams', '💬 TEAMS', Colors.MAGENTA),
    
    # Virtualization platforms
    (r'app=ESXi|http=ESXi', '☁️ ESXI', Colors.CYAN),
    (r'app=Hyper-V|http=Hyper-V', '☁️ HYPER-V', Colors.CYAN),
    (r'app=Xen|http=Xen', '☁️ XEN', Colors.CYAN),
    
    # Development frameworks
    (r'app=Node.js|http=Node.js|app=NodeJS|http=NodeJS', '💚 NODEJS', Colors.GREEN),
    (r'app=Django|http=Django', '💚 DJANGO', Colors.GREEN),
    (r'app=Rails|http=Rails', '💚 RAILS', Colors.GREEN),
    
    # High-value targets for lateral movement
    (r'[:/]5985\b', '🔓 WINRM', Colors.MAGENTA),
    (r'[:/]5986\b', '🔒 WINRM-TLS', Colors.MAGENTA),
    (r'app=WMI|http=WMI', '🔓 WMI', Colors.MAGENTA),
    (r'app=SMB signing|http=SMB signing', '📁 SMB-SIGNING', Colors.BLUE),
    
    # Network infrastructure
    (r'app=F5|http=F5', '🌐 LOAD-BALANCER', Colors.CYAN),
    (r'app=HAProxy|http=HAProxy', '🌐 LOAD-BALANCER', Colors.CYAN),
    (r'app=Palo Alto|http=Palo Alto', '🛡️ FIREWALL', Colors.RED),
    (r'app=Fortinet|http=Fortinet', '🛡️ FIREWALL', Colors.RED),
    (r'app=Cisco|http=Cisco', '🛡️ FIREWALL', Colors.RED),
    (r'app=Squid|http=Squid', '🌐 PROXY', Colors.CYAN),
    
    # Potential data stores
    (r'app=File Server|http=File Server', '📁 FILE-SERVER', Colors.BLUE),
    (r'app=File Share|http=File Share', '📁 FILE-SHARE', Colors.BLUE),
    (r'app=SharePoint|http=SharePoint', '📁 SHAREPOINT', Colors.BLUE),
    (r'app=Confluence|http=Confluence', '📄 CONFLUENCE', Colors.BLUE),
]

# ------------------------------------------------------------------
# Signal handling
# ------------------------------------------------------------------
def signal_handler(sig, frame):
    global shutdown_flag
    print(f"\n\n{Colors.YELLOW}[!] Interrupt received, generating final report...{Colors.RESET}")
    shutdown_flag = True

signal.signal(signal.SIGINT, signal_handler)

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------
def notify(summary, body=""):
    if notify2 is None:
        return
    try:
        notify2.init("p0f-miner")
        n = notify2.Notification(summary, body)
        n.set_timeout(3000)
        n.show()
    except:
        pass

def count_lines(path):
    if not Path(path).exists():
        return 0
    try:
        return sum(1 for line in open(path) if line.strip())
    except:
        return 0

def parse_p0f_line(line):
    """Extract key information from a p0f log line"""
    data = {}
    if '|' not in line:
        return data
    
    parts = line.split('|')
    for part in parts:
        if '=' in part:
            key, val = part.split('=', 1)
            data[key.strip()] = val.strip()
    return data

def check_high_value(line):
    """Check if line matches high-value patterns and return tags"""
    tags = []
    for pattern, tag, color in HIGH_VALUE_PATTERNS:
        if re.search(pattern, line):
            tags.append((tag, color))
    return tags

def highlight_line(line):
    """Add color highlights to important detections"""
    tags = check_high_value(line)
    
    if tags:
        tag_str = ' '.join([f"{color}{tag}{Colors.RESET}" for tag, color in tags])
        return f"{tag_str} {line}"
    return None  # Return None if not high-value

def extract_ips_from_line(line):
    """Extract client and server IPs from p0f line"""
    data = parse_p0f_line(line)
    cli_ip = None
    srv_ip = None
    
    if 'cli' in data:
        # Format: IP/port
        cli_ip = data['cli'].split('/')[0] if '/' in data['cli'] else data['cli'].split(':')[0]
    if 'srv' in data:
        srv_ip = data['srv'].split('/')[0] if '/' in data['srv'] else data['srv'].split(':')[0]
    
    return cli_ip, srv_ip, data

def update_live_stats(line):
    """Update live statistics and build per-IP profiles"""
    with stats_lock:
        cli_ip, srv_ip, data = extract_ips_from_line(line)
        
        live_stats['total_packets'] += 1
        
        # Determine which IP we're profiling (client or server based on subject)
        subject_ip = None
        if 'subj' in data:
            if data['subj'] == 'cli' and cli_ip:
                subject_ip = cli_ip
            elif data['subj'] == 'srv' and srv_ip:
                subject_ip = srv_ip
        
        # If we have an OS fingerprint, use that IP
        if 'os' in data and data['os'] != '???' and subject_ip:
            profile = ip_profiles[subject_ip]
            
            if not profile['first_seen']:
                profile['first_seen'] = time.time()
            
            # Track OS
            if not profile['os']:
                profile['os'] = data['os']
                profile['os_detail'] = data['os']
                live_stats['total_os'] += 1
                
                if 'Windows' in data['os']:
                    live_stats['windows'] += 1
                    
                    # EOL detection
                    if any(x in data['os'] for x in ['XP', '2003', '2000']) and 'NT kernel' not in data['os']:
                        profile['is_eol'] = True
                        live_stats['eol_systems'] += 1
                    
                    # Server detection
                    if any(x in data['os'] for x in ['2012', '2016', '2019', '2022']):
                        if 'subj' in data and data['subj'] == 'srv':
                            profile['is_server'] = True
                
                elif 'Linux' in data['os']:
                    live_stats['linux'] += 1
                    if 'subj' in data and data['subj'] == 'srv':
                        profile['is_server'] = True
            
            # Distance
            if 'distance' in data and profile['distance'] is None:
                try:
                    profile['distance'] = int(data['distance'])
                    if profile['distance'] <= 2:
                        live_stats['close_hosts'] += 1
                except:
                    pass
            
            # NAT
            if 'nat' in data and data['nat'] == 'yes':
                profile['nat'] = True
                live_stats['nat_detected'] += 1
            
            # Uptime
            if 'uptime' in data:
                profile['uptime'] = data['uptime']
            
            # Link type
            if 'link' in data:
                profile['link'] = data['link']
        
        # Suspicious User-Agents
        if 'bad_sw' in data and data['bad_sw'] != '0' and cli_ip:
            ua_type = "OS mismatch" if data['bad_sw'] == '1' else "FAKE UA"
            ip_profiles[cli_ip]['suspicious'].add(ua_type)
            live_stats['suspicious_ua'] += 1
        
        # Scanner detection
        if 'app' in data and cli_ip:
            app_lower = data['app'].lower()
            if 'nmap' in app_lower or 'masscan' in app_lower or 'scanner' in app_lower:
                ip_profiles[cli_ip]['scanners'].add(data['app'])
                live_stats['scanners'] += 1
        
        # Service detection - track on the SERVER side
        if srv_ip and ('srv' in data or 'cli' in data):
            # Extract port from server address
            if '/' in data.get('srv', '') or ':' in data.get('srv', ''):
                port_match = re.search(r'[:/](\d+)\b', data['srv'])
                if port_match:
                    port = port_match.group(1)
                    
                    # Map common ports to services
                    service_map = {
                        '21': 'FTP', '22': 'SSH', '23': 'Telnet',
                        '80': 'HTTP', '443': 'HTTPS', '445': 'SMB',
                        '139': 'NetBIOS', '3389': 'RDP', '3306': 'MySQL',
                        '5432': 'PostgreSQL', '27017': 'MongoDB', '6379': 'Redis'
                    }
                    
                    service_name = service_map.get(port, f'port-{port}')
                    ip_profiles[srv_ip]['services'].add(f"{service_name}:{port}")

def print_live_stats():
    """Print current live statistics in a clean format"""
    with stats_lock:
        if live_stats['total_packets'] == 0:
            return
        
        print(f"\n{Colors.BOLD}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD}📊 LIVE STATISTICS{Colors.RESET}")
        print(f"{Colors.BOLD}{'='*70}{Colors.RESET}")
        print(f"Total Packets:     {live_stats['total_packets']:>6}")
        print(f"OS Identified:     {live_stats['total_os']:>6}")
        print(f"  └─ Windows:      {live_stats['windows']:>6}")
        print(f"  └─ Linux:        {live_stats['linux']:>6}")
        if live_stats['eol_systems'] > 0:
            print(f"{Colors.RED}EOL Systems:       {live_stats['eol_systems']:>6}{Colors.RESET}")
        if live_stats['close_hosts'] > 0:
            print(f"{Colors.GREEN}Close Hosts:       {live_stats['close_hosts']:>6}{Colors.RESET}")
        if live_stats['nat_detected'] > 0:
            print(f"{Colors.YELLOW}NAT Detected:      {live_stats['nat_detected']:>6}{Colors.RESET}")
        if live_stats['suspicious_ua'] > 0:
            print(f"{Colors.YELLOW}Suspicious UA:     {live_stats['suspicious_ua']:>6}{Colors.RESET}")
        if live_stats['scanners'] > 0:
            print(f"{Colors.RED}Scanners:          {live_stats['scanners']:>6}{Colors.RESET}")
        print(f"{Colors.BOLD}{'='*70}{Colors.RESET}")

def print_live_intelligence_update(iteration):
    """Print actionable intelligence summary grouped by IP"""
    print(f"\n{Colors.BOLD}{'='*70}{Colors.RESET}")
    print(f"{Colors.BOLD}📊 LIVE INTELLIGENCE UPDATE #{iteration}{Colors.RESET} - {datetime.now().strftime('%H:%M:%S')}")
    print(f"{Colors.BOLD}{'='*70}{Colors.RESET}")
    
    # Quick stats
    total_hosts = len(ip_profiles)
    windows_count = sum(1 for p in ip_profiles.values() if p['os'] and 'Windows' in p['os'])
    linux_count = sum(1 for p in ip_profiles.values() if p['os'] and 'Linux' in p['os'])
    
    print(f"Packets: {live_stats['total_packets']} | Unique Hosts: {total_hosts} | "
          f"Win: {windows_count} | Linux: {linux_count}")
    
    # Group IPs by priority: EOL > Scanners > Servers > Services > Others
    eol_ips = []
    scanner_ips = []
    server_ips = []
    service_ips = []
    other_ips = []
    
    for ip, profile in ip_profiles.items():
        if profile['is_eol']:
            eol_ips.append(ip)
        elif profile['scanners']:
            scanner_ips.append(ip)
        elif profile['is_server']:
            server_ips.append(ip)
        elif profile['services']:
            service_ips.append(ip)
        else:
            other_ips.append(ip)
    
    # Display EOL systems
    if eol_ips:
        print(f"\n{Colors.RED}{Colors.BOLD}🎯 CRITICAL: END-OF-LIFE SYSTEMS{Colors.RESET}")
        for ip in sorted(eol_ips)[:10]:
            profile = ip_profiles[ip]
            print(f"\n  {Colors.RED}IP: {ip}{Colors.RESET}")
            print(f"    OS: {profile['os']}")
            if profile['distance'] is not None:
                print(f"    Distance: {profile['distance']} hops")
            if profile['services']:
                services = ', '.join(sorted(profile['services']))
                print(f"    Services: {services}")
    
    # Display scanners
    if scanner_ips:
        print(f"\n{Colors.RED}{Colors.BOLD}🔍 SCANNER ACTIVITY{Colors.RESET}")
        for ip in sorted(scanner_ips)[:5]:
            profile = ip_profiles[ip]
            print(f"\n  {Colors.RED}IP: {ip}{Colors.RESET}")
            scanners = ', '.join(sorted(profile['scanners']))
            print(f"    Scanner: {scanners}")
            if profile['os']:
                print(f"    OS: {profile['os']}")
    
    # Display servers (top 10)
    if server_ips:
        print(f"\n{Colors.CYAN}{Colors.BOLD}💻 SERVERS{Colors.RESET}")
        for ip in sorted(server_ips)[:10]:
            profile = ip_profiles[ip]
            print(f"\n  {Colors.CYAN}IP: {ip}{Colors.RESET}")
            print(f"    OS: {profile['os']}")
            if profile['distance'] is not None:
                print(f"    Distance: {profile['distance']} hops")
            if profile['services']:
                services = ', '.join(sorted(profile['services']))
                print(f"    Services: {services}")
    
    # Display hosts with services (top 10)
    if service_ips and not server_ips:  # Only show if we haven't shown servers
        print(f"\n{Colors.MAGENTA}{Colors.BOLD}🔓 SERVICES DISCOVERED{Colors.RESET}")
        for ip in sorted(service_ips)[:10]:
            profile = ip_profiles[ip]
            services = ', '.join(sorted(profile['services']))
            print(f"\n  {Colors.MAGENTA}IP: {ip}{Colors.RESET}")
            print(f"    Services: {services}")
            if profile['os']:
                print(f"    OS: {profile['os']}")
    
    # Summary counts
    total_services = sum(len(p['services']) for p in ip_profiles.values())
    if total_services > 0:
        print(f"\n{Colors.YELLOW}Total: {len(eol_ips)} EOL, {len(scanner_ips)} scanners, "
              f"{len(server_ips)} servers, {total_services} services{Colors.RESET}")
    
    print(f"{Colors.BOLD}{'='*70}{Colors.RESET}")

def tail_log_file(logfile, show_stats_interval=15):
    """Tail the log file and show periodic intelligence summaries"""
    print(f"\n{Colors.GREEN}[+] Live capture active - showing intelligence updates every {show_stats_interval}s{Colors.RESET}")
    if verbose_mode:
        print(f"{Colors.CYAN}[+] Verbose mode: showing packet-level details{Colors.RESET}\n")
    else:
        print(f"{Colors.CYAN}[+] Quiet mode: showing summaries only (use -v for packet details){Colors.RESET}")
        print(f"{Colors.CYAN}[+] Press Ctrl+C to stop and generate final report{Colors.RESET}\n")
        print(f"{Colors.YELLOW}Collecting traffic... first update in {show_stats_interval}s{Colors.RESET}")
    
    last_update_time = time.time()
    update_count = 0
    
    try:
        with open(logfile, 'r') as f:
            f.seek(0, 2)  # Go to end of file
            
            while not shutdown_flag:
                line = f.readline()
                if line:
                    if line.startswith('[') and ']' in line and '|' in line:
                        update_live_stats(line)
                        
                        # In verbose mode, show packet details
                        if verbose_mode:
                            highlighted = highlight_line(line.strip())
                            if highlighted:
                                print(highlighted)
                            else:
                                print(line.strip())
                        
                        # Show intelligence update periodically
                        if time.time() - last_update_time > show_stats_interval:
                            update_count += 1
                            if not verbose_mode or update_count % 3 == 0:  # Show summary even in verbose every 3rd time
                                print_live_intelligence_update(update_count)
                            last_update_time = time.time()
                else:
                    time.sleep(0.1)
    except FileNotFoundError:
        print(f"{Colors.YELLOW}[!] Waiting for p0f to create log file...{Colors.RESET}")
        time.sleep(2)
    except Exception as e:
        print(f"{Colors.RED}[!] Error reading log: {e}{Colors.RESET}")

def list_interfaces():
    """List available network interfaces using p0f"""
    print("="*70)
    print("Available Network Interfaces")
    print("="*70)
    result = subprocess.run("p0f -L", shell=True, capture_output=True, text=True)
    print(result.stdout)
    sys.exit(0)

def start_p0f_live(interface, promiscuous=False):
    """Start p0f in live capture mode as a background process"""
    promisc_flag = "-p" if promiscuous else ""
    cmd = f"p0f -i {interface} {promisc_flag} -o full.log -d"
    
    print(f"{Colors.GREEN}[+] Starting live capture on {interface}...{Colors.RESET}")
    subprocess.run(cmd, shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    
    time.sleep(2)
    
    check = subprocess.run("pgrep -f 'p0f.*-i'", shell=True, capture_output=True)
    if check.returncode != 0:
        print(f"{Colors.RED}[!] Failed to start p0f{Colors.RESET}")
        sys.exit(1)
    
    print(f"{Colors.GREEN}[+] p0f is now capturing traffic{Colors.RESET}")
    return True

def stop_p0f():
    """Stop background p0f process"""
    subprocess.run("pkill -f 'p0f.*-i'", shell=True, stderr=subprocess.DEVNULL)

def run_oneliner(name, cmd, log_file):
    """Process full.log with grep/awk pipeline"""
    subprocess.run(cmd, shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    return count_lines(log_file)

def process_intelligence(quiet=False):
    """Process all detection rules and return counts"""
    counts = {}
    
    if not quiet:
        print(f"\n{Colors.CYAN}[+] Processing {len(ONELINERS)} detection rules...{Colors.RESET}")
    
    for name, cmd in ONELINERS.items():
        log = cmd.split(">")[-1].strip()
        counts[log] = run_oneliner(name, cmd, log)
    
    return counts

def save_json_report():
    """Save IP profiles to JSON for programmatic access"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    json_file = f"p0f_profiles_{timestamp}.json"
    
    # Convert IP profiles to JSON-serializable format
    export_data = {
        'timestamp': timestamp,
        'stats': dict(live_stats),
        'hosts': {}
    }
    
    for ip, profile in ip_profiles.items():
        export_data['hosts'][ip] = {
            'os': profile['os'],
            'os_detail': profile['os_detail'],
            'distance': profile['distance'],
            'services': list(profile['services']),
            'scanners': list(profile['scanners']),
            'suspicious': list(profile['suspicious']),
            'nat': profile['nat'],
            'uptime': profile['uptime'],
            'link': profile['link'],
            'is_server': profile['is_server'],
            'is_eol': profile['is_eol']
        }
    
    try:
        with open(json_file, 'w') as f:
            json.dump(export_data, f, indent=2)
        print(f"{Colors.GREEN}[+] JSON export saved to: {json_file}{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.YELLOW}[!] Could not save JSON: {e}{Colors.RESET}")

def print_final_statistics(counts, save_to_file=True):
    """Print comprehensive final statistics report grouped by IP"""
    output_lines = []
    
    def log(line=""):
        """Print and save to output buffer"""
        print(line)
        output_lines.append(line)
    
    log(f"\n{'='*70}")
    log(f"📊 FINAL INTELLIGENCE REPORT (GROUPED BY IP)")
    log(f"{'='*70}")
    
    # Traffic Statistics
    total_hosts = len(ip_profiles)
    windows_count = sum(1 for p in ip_profiles.values() if p['os'] and 'Windows' in p['os'])
    linux_count = sum(1 for p in ip_profiles.values() if p['os'] and 'Linux' in p['os'])
    
    log(f"\nTRAFFIC SUMMARY:")
    log(f"  Total Packets Processed:    {live_stats['total_packets']:>6}")
    log(f"  OS Fingerprints:            {live_stats['total_os']:>6}")
    log(f"  Unique Hosts Discovered:    {total_hosts:>6}")
    log(f"  Windows Hosts:              {windows_count:>6}")
    log(f"  Linux Hosts:                {linux_count:>6}")
    
    # Group IPs by category
    eol_ips = []
    scanner_ips = []
    server_ips = []
    suspicious_ips = []
    service_ips = []
    
    for ip, profile in ip_profiles.items():
        if profile['is_eol']:
            eol_ips.append(ip)
        if profile['scanners']:
            scanner_ips.append(ip)
        if profile['is_server']:
            server_ips.append(ip)
        if profile['suspicious']:
            suspicious_ips.append(ip)
        if profile['services']:
            service_ips.append(ip)
    
    # CRITICAL: EOL SYSTEMS
    if eol_ips:
        log(f"\n🎯 CRITICAL: END-OF-LIFE SYSTEMS ({len(eol_ips)})")
        for ip in sorted(eol_ips)[:20]:
            profile = ip_profiles[ip]
            log(f"\n  ▸ IP: {ip}")
            log(f"     OS: {profile['os']}")
            if profile['distance'] is not None:
                log(f"     Distance: {profile['distance']} hops")
            if profile['services']:
                log(f"     Services: {', '.join(sorted(profile['services']))}")
        if len(eol_ips) > 20:
            log(f"\n  ... and {len(eol_ips) - 20} more (see eol.log)")
    
    # SCANNERS DETECTED
    if scanner_ips:
        log(f"\n🔍 SCANNER ACTIVITY ({len(scanner_ips)})")
        for ip in sorted(scanner_ips)[:10]:
            profile = ip_profiles[ip]
            log(f"\n  ▸ IP: {ip}")
            log(f"     Scanner: {', '.join(sorted(profile['scanners']))}")
            if profile['os']:
                log(f"     OS: {profile['os']}")
        if len(scanner_ips) > 10:
            log(f"\n  ... and {len(scanner_ips) - 10} more")
    
    # SUSPICIOUS ACTIVITY
    if suspicious_ips:
        log(f"\n⚠️  SUSPICIOUS HOSTS ({len(suspicious_ips)})")
        for ip in sorted(suspicious_ips)[:10]:
            profile = ip_profiles[ip]
            log(f"\n  ▸ IP: {ip}")
            log(f"     Flags: {', '.join(sorted(profile['suspicious']))}")
            if profile['os']:
                log(f"     OS: {profile['os']}")
    
    # SERVERS DISCOVERED
    if server_ips:
        log(f"\n💻 SERVERS ({len(server_ips)})")
        for ip in sorted(server_ips)[:20]:
            profile = ip_profiles[ip]
            log(f"\n  ▸ IP: {ip}")
            log(f"     OS: {profile['os']}")
            if profile['distance'] is not None:
                log(f"     Distance: {profile['distance']} hops")
            if profile['services']:
                log(f"     Services: {', '.join(sorted(profile['services']))}")
            if profile['nat']:
                log(f"     NAT: Yes")
        if len(server_ips) > 20:
            log(f"\n  ... and {len(server_ips) - 20} more")
    
    # SERVICES DISCOVERED (hosts not already listed as servers)
    non_server_service_ips = [ip for ip in service_ips if ip not in server_ips and ip not in eol_ips and ip not in scanner_ips]
    if non_server_service_ips:
        log(f"\n🔓 OTHER HOSTS WITH SERVICES ({len(non_server_service_ips)})")
        for ip in sorted(non_server_service_ips)[:15]:
            profile = ip_profiles[ip]
            log(f"\n  ▸ IP: {ip}")
            log(f"     Services: {', '.join(sorted(profile['services']))}")
            if profile['os']:
                log(f"     OS: {profile['os']}")
        if len(non_server_service_ips) > 15:
            log(f"\n  ... and {len(non_server_service_ips) - 15} more")
    
    log(f"\n{'='*70}")
    
    # Summary
    if total_hosts > 0:
        log(f"[✓] Analysis complete: {total_hosts} unique hosts profiled")
        log(f"[i] Priority: {len(eol_ips)} EOL, {len(scanner_ips)} scanners, "
              f"{len(server_ips)} servers, {len(service_ips)} with services")
    else:
        log(f"[!] No hosts fingerprinted in captured traffic")
    
    # Save to file
    if save_to_file:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = f"p0f_report_{timestamp}.txt"
        try:
            with open(report_file, 'w') as f:
                f.write('\n'.join(output_lines))
            print(f"\n{Colors.GREEN}[+] Text report saved to: {report_file}{Colors.RESET}")
        except Exception as e:
            print(f"\n{Colors.YELLOW}[!] Could not save report: {e}{Colors.RESET}")
        
        # Also save JSON export
        save_json_report()

def print_compact_summary(counts):
    """Print a compact summary of top findings"""
    important = [
        ("🎯 Jump Candidates", "jump-candidates.log"),
        ("🏢 Domain Controllers", "dc-candidates.log"),
        ("💀 End-of-Life Systems", "eol.log"),
        ("👴 Legacy Systems", "legacy.txt"),
        ("🔓 RDP Endpoints", "rdp-endpoints.log"),
        ("📁 SMB Hosts", "smb-enabled.log"),
        ("🔐 SSH Boxes", "ssh-boxes.log"),
        ("🚨 Fake User-Agents", "dishonest-useragents.log"),
        ("🐍 Scripts on Windows", "suspicious-automation.log"),
        ("🔍 Scanners Detected", "blue-team-scanners.log"),
        ("💻 Windows Servers", "windows-servers.log"),
        ("🐧 Linux Servers", "linux-servers.log"),
        ("📱 Mobile Devices", "mobile-devices.log"),
        ("🖨️  Printers", "printers.log"),
        # New additions
        ("🗄️ Database Servers", "mysql-servers.log"),
        ("🗄️ PostgreSQL Servers", "postgresql-servers.log"),
        ("🗄️ Oracle Servers", "oracle-servers.log"),
        ("🗄️ MS SQL Servers", "mssql-servers.log"),
        ("🗄️ Redis Servers", "redis-servers.log"),
        ("🗄️ MongoDB Servers", "mongodb-servers.log"),
        ("🔧 Jenkins Servers", "jenkins-servers.log"),
        ("📦 Git Servers", "git-servers.log"),
        ("🐳 Docker Registries", "docker-registries.log"),
        ("☸️ Kubernetes API", "kubernetes-api.log"),
        ("☁️ AWS Services", "aws-services.log"),
        ("☁️ Azure Services", "azure-services.log"),
        ("☁️ GCP Services", "gcp-services.log"),
        ("🔐 VPN Endpoints", "vpn-endpoints.log"),
        ("📁 FTP Servers", "ftp-servers.log"),
        ("📁 NFS Servers", "nfs-servers.log"),
        ("📧 Email Servers", "smtp-servers.log"),
        ("🌐 DNS Servers", "dns-servers.log"),
        ("🖥️ Remote Management", "teamviewer.log"),
        ("💾 Backup Systems", "backup-servers.log"),
        ("📊 Monitoring Systems", "zabbix.log"),
        ("🔐 Authentication Systems", "ldap-servers.log"),
        ("📞 VoIP Systems", "voip-servers.log"),
        ("🏭 SCADA Systems", "scada-systems.log"),
        ("💬 Collaboration Tools", "slack.log"),
        ("☁️ Virtualization Platforms", "vmware-esxi.log"),
        ("🔓 WinRM Endpoints", "psremoting.log"),
        ("🌐 Load Balancers", "load-balancers.log"),
        ("🛡️ Firewalls", "firewalls.log"),
        ("📁 File Servers", "file-servers.log"),
        ("📁 SharePoint", "sharepoint.log"),
        ("📄 Confluence", "confluence.log"),
    ]
    
    print(f"\n{Colors.BOLD}{'='*70}{Colors.RESET}")
    print(f"{Colors.BOLD}🎯 KEY FINDINGS{Colors.RESET}")
    print(f"{Colors.BOLD}{'='*70}{Colors.RESET}")
    
    found_any = False
    for label, log in important:
        count = counts.get(log, 0)
        if count > 0:
            print(f"{Colors.GREEN}✓{Colors.RESET} {label:<35} : {Colors.BOLD}{count:>4}{Colors.RESET} entries")
            found_any = True
    
    if not found_any:
        print(f"{Colors.YELLOW}No high-value targets detected{Colors.RESET}")
    
    print(f"{Colors.BOLD}{'='*70}{Colors.RESET}")

def main_offline(pcap):
    """Offline pcap analysis mode with IP grouping"""
    global verbose_mode
    
    if not Path(pcap).is_file():
        sys.exit(f"{Colors.RED}[!] pcap not found: {pcap}{Colors.RESET}")

    print("="*70)
    print(f"{Colors.BOLD}p0f-miner: Offline Analysis Mode{Colors.RESET}")
    print("="*70)
    print(f"Target: {pcap}")
    print(f"Rules: {len(ONELINERS)} detection patterns")
    print(f"Verbose: {verbose_mode}")
    print("="*70)
    
    # Run p0f
    print(f"{Colors.GREEN}[+] Running p0f analysis...{Colors.RESET}")
    result = subprocess.run(
        f"p0f -r {pcap} -o full.log",
        shell=True,
        stderr=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True
    )
    
    if result.returncode != 0 or not Path("full.log").exists():
        print(f"{Colors.RED}[!] p0f failed{Colors.RESET}")
        sys.exit(1)
    
    flows = count_lines("full.log")
    print(f"{Colors.GREEN}[+] Captured {flows} flows{Colors.RESET}")
    
    # Build IP profiles from the log
    if flows > 0:
        print(f"{Colors.CYAN}[+] Building IP profiles...{Colors.RESET}")
        
        with open("full.log", 'r') as f:
            for line in f:
                if line.startswith('[') and '|' in line:
                    update_live_stats(line)
                    
                    # Show packet details if verbose
                    if verbose_mode:
                        highlighted = highlight_line(line.strip())
                        print(highlighted if highlighted else line.strip())
        
        print(f"{Colors.GREEN}[+] Profiled {len(ip_profiles)} unique hosts{Colors.RESET}")
    
    # Process intelligence rules
    counts = process_intelligence()
    
    # Show IP-grouped final report
    print_final_statistics(counts, save_to_file=True)
    
    print(f"\n{Colors.GREEN}[+] All log files saved to current directory{Colors.RESET}")
    print(f"{Colors.YELLOW}[+] Review p0f_report_*.txt for full analysis{Colors.RESET}")
    print(f"{Colors.YELLOW}[+] Review p0f_profiles_*.json for programmatic access{Colors.RESET}")

def main_live(interface, promiscuous=False, update_interval=15):
    """Live network capture mode with periodic intelligence summaries"""
    print("="*70)
    print(f"{Colors.BOLD}p0f-miner: Live Capture Mode{Colors.RESET}")
    print("="*70)
    print(f"Interface: {interface}")
    print(f"Promiscuous: {promiscuous}")
    print(f"Update Interval: {update_interval}s")
    print(f"Verbose: {verbose_mode}")
    print(f"Rules: {len(ONELINERS)} detection patterns")
    print("="*70)
    
    # Start p0f
    start_p0f_live(interface, promiscuous)
    
    # Wait for log file
    timeout = 10
    while not Path("full.log").exists() and timeout > 0:
        time.sleep(1)
        timeout -= 1
    
    if not Path("full.log").exists():
        print(f"{Colors.RED}[!] Log file not created{Colors.RESET}")
        stop_p0f()
        sys.exit(1)
    
    # Show live intelligence
    try:
        tail_log_file("full.log", show_stats_interval=update_interval)
    except KeyboardInterrupt:
        pass
    finally:
        # Final report
        print(f"\n\n{Colors.CYAN}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD}GENERATING FINAL REPORT{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*70}{Colors.RESET}")
        
        stop_p0f()
        
        if Path("full.log").exists():
            flows = count_lines("full.log")
            print(f"{Colors.GREEN}[+] Total flows captured: {flows}{Colors.RESET}")
            
            counts = process_intelligence(quiet=True)
            print_final_statistics(counts, save_to_file=True)
            
            print(f"\n{Colors.GREEN}[+] All log files saved to current directory{Colors.RESET}")
            print(f"{Colors.YELLOW}[+] Review p0f_report_*.txt for full analysis{Colors.RESET}")
            print(f"{Colors.YELLOW}[+] Review p0f_profiles_*.json for programmatic access{Colors.RESET}")
            print(f"{Colors.YELLOW}[+] Review *-candidates.log and eol.log for attack planning{Colors.RESET}")

def main():
    global verbose_mode
    
    parser = argparse.ArgumentParser(
        description='p0f-miner: Actionable passive reconnaissance (grouped by IP, saved to reports)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Live capture with intelligence summaries every 15s (default)
  # Saves: p0f_report_TIMESTAMP.txt + p0f_profiles_TIMESTAMP.json
  sudo ./p0f-miner.py -i eth0
  
  # Live capture with faster updates (10s)
  sudo ./p0f-miner.py -i eth0 -u 10
  
  # Live capture with packet-level details
  sudo ./p0f-miner.py -i eth0 -v
  
  # Offline analysis (shows IP-grouped intelligence)
  # Saves: p0f_report_TIMESTAMP.txt + p0f_profiles_TIMESTAMP.json
  ./p0f-miner.py -r capture.pcap
  
  # Offline with packet details
  ./p0f-miner.py -r capture.pcap -v
  
  # List interfaces
  sudo ./p0f-miner.py -L

Output Files:
  - p0f_report_TIMESTAMP.txt    : Human-readable intelligence report
  - p0f_profiles_TIMESTAMP.json : Machine-readable IP profiles
  - full.log                    : Complete p0f output
  - *.log files                 : Categorized findings
        '''
    )
    
    parser.add_argument('-r', '--read', metavar='FILE', help='Read from pcap file (offline mode)')
    parser.add_argument('-i', '--interface', metavar='IFACE', help='Capture on network interface (live mode)')
    parser.add_argument('-L', '--list-interfaces', action='store_true', help='List available network interfaces')
    parser.add_argument('-p', '--promiscuous', action='store_true', help='Enable promiscuous mode (live mode only)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show all traffic (default: summaries only)')
    parser.add_argument('-u', '--update', type=int, default=15, metavar='SEC', help='Update interval for live mode (default: 15s)')
    
    args = parser.parse_args()
    
    verbose_mode = args.verbose
    
    if args.interface and os.geteuid() != 0:
        sys.exit(f"{Colors.RED}[!] Live capture requires root. Run with sudo.{Colors.RESET}")
    
    if args.list_interfaces:
        list_interfaces()
    
    if args.read:
        main_offline(args.read)
    elif args.interface:
        main_live(args.interface, args.promiscuous, args.update)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()