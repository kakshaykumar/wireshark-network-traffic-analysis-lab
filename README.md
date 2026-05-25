# Wireshark Network Traffic Analysis Lab

A hands-on network security lab documenting real packet captures across three analysis domains: network reconnaissance, authentication attack detection, and protocol security analysis. Built to develop and demonstrate SOC analyst skills through attacker simulation and defender-perspective analysis.

---

## Lab Environment

| Component | Details |
|-----------|---------|
| Attacker | Kali Linux — 192.168.110.132 |
| Target | Ubuntu 22.04 — 192.168.110.130 |
| Network | VMware Host-only (192.168.110.0/24) |
| Hypervisor | VMware Workstation |
| Capture tool | Wireshark / tcpdump |

**Services deployed on Ubuntu target:**

| Port | Service | Version |
|------|---------|---------|
| 21/tcp | FTP | vsftpd 3.0.5 |
| 22/tcp | SSH | OpenSSH 10.2p1 Ubuntu |
| 80/tcp | HTTP | Apache httpd 2.4.66 |

---

## Network Topology

```
┌─────────────────────────────────────────────────┐
│            VMware Host-only Network             │
│               192.168.110.0/24                  │
│                                                 │
│  ┌─────────────────┐    ┌─────────────────────┐ │
│  │   Kali Linux    │    │   Ubuntu Server     │ │
│  │ 192.168.110.132 │◄──►│  192.168.110.130    │ │
│  │   (Attacker)    │    │  FTP · SSH · HTTP   │ │
│  └─────────────────┘    └─────────────────────┘ │
│                                                 │
│  Gateway: 192.168.110.1                         │
│  DHCP:    192.168.110.254                       │
└─────────────────────────────────────────────────┘
```

---

## Repository Structure

```
wireshark-network-traffic-analysis-lab/
├── README.md
├── lab-setup/
│   └── network-topology.md
│
├── network-reconnaissance/
│   ├── icmp-ping-sweep.md
│   ├── tcp-syn-scan.md
│   ├── service-version-detection.md
│   ├── aggressive-scan.md
│   ├── nmap-terminal-output.txt
│   └── screenshots/
│
├── authentication-attacks/
│   ├── ssh-brute-force.md
│   ├── ftp-brute-force.md
│   ├── ftp-credential-capture.md
│   ├── http-basic-auth-attack.md
│   └── screenshots/
│
├── protocol-analysis/
│   ├── ftp-vs-ssh-comparison.md
│   ├── http-traffic-analysis.md
│   ├── tcp-handshake-analysis.md
│   ├── dns-analysis.md
│   └── screenshots/
│
├── pcap-files/
│   ├── network-reconnaissance/
│   ├── authentication-attacks/
│   └── protocol-analysis/
│
├── mitre-attack-mapping.md
├── wireshark-filters-reference.md
└── findings-summary.md
```

---

## Topics

### Network Reconnaissance
Host discovery, port scanning, banner grabbing, and OS fingerprinting using Nmap. Captured from the attacker interface with documented defender perspective for each technique.

| Scenario | Technique | MITRE |
|----------|-----------|-------|
| [ICMP Ping Sweep](network-reconnaissance/icmp-ping-sweep.md) | Host discovery via ICMP + ARP | T1018, T1595 |
| [TCP SYN Scan](network-reconnaissance/tcp-syn-scan.md) | Half-open port scan | T1046 |
| [Service Version Detection](network-reconnaissance/service-version-detection.md) | Banner grabbing | T1046, T1082 |
| [Aggressive Scan](network-reconnaissance/aggressive-scan.md) | OS detection + NSE scripting | T1082, T1595 |

### Authentication Attacks
Brute force attacks against SSH, FTP, and HTTP. Captured from Ubuntu's interface — the defender view — demonstrating what a monitored server sees during each attack.

| Scenario | Protocol | Key Finding | MITRE |
|----------|----------|-------------|-------|
| [SSH Brute Force](authentication-attacks/ssh-brute-force.md) | TCP/22 | Encrypted but pattern-detectable | T1110.001 |
| [FTP Brute Force](authentication-attacks/ftp-brute-force.md) | TCP/21 | Every password in plaintext | T1110.001 |
| [FTP Credential Capture](authentication-attacks/ftp-credential-capture.md) | TCP/21 | Full credential exposure, single session | T1040 |
| [HTTP Basic Auth Attack](authentication-attacks/http-basic-auth-attack.md) | TCP/80 | Base64 is encoding, not encryption | T1110.001 |

### Protocol Analysis
Comparative analysis of secure vs insecure protocols, TCP handshake behaviour, and DNS traffic patterns.

| Scenario | Key Finding |
|----------|-------------|
| [FTP vs SSH Comparison](protocol-analysis/ftp-vs-ssh-comparison.md) | Same action, opposite security outcomes |
| [HTTP Traffic Analysis](protocol-analysis/http-traffic-analysis.md) | All headers, credentials, and content in plaintext |
| [TCP Handshake Analysis](protocol-analysis/tcp-handshake-analysis.md) | Abnormal TCP flags identify port scanning |
| [DNS Analysis](protocol-analysis/dns-analysis.md) | NXDOMAIN pattern signals C2 or DGA activity |

---

## Key Findings

1. FTP transmits credentials in plaintext — `PASS labuser` readable in packet list without decryption
2. HTTP Basic Auth uses Base64 encoding — `echo "YWRtaW46YWRtaW4=" | base64 -d` → `admin:admin`
3. SSH brute force detectable by connection pattern even though credentials are encrypted
4. Hydra fingerprinted by `SSH-2.0-libssh_0.11.3` (SSH) and `User-Agent: Mozilla/4.0 (Hydra)` (HTTP)
5. Nmap fingerprinted by `TCP Win=1024` probe and `SSH-1.5-NmapNSE_1.0` banner
6. Exact software versions exposed by banner grabbing — sufficient for targeted CVE lookup
7. Password = username on both accounts — cracked in 1–9 attempts from a 12-entry wordlist
8. NXDOMAIN flood pattern is the DNS-level fingerprint of DGA malware C2 activity

---

## MITRE ATT&CK Coverage

| ID | Technique | Scenario |
|----|-----------|---------|
| T1018 | Remote System Discovery | ICMP Ping Sweep |
| T1046 | Network Service Scanning | SYN Scan, Version Detection |
| T1082 | System Information Discovery | Version Detection, Aggressive Scan |
| T1595 | Active Scanning | Aggressive Scan |
| T1110.001 | Brute Force: Password Guessing | SSH, FTP, HTTP brute force |
| T1040 | Network Sniffing | FTP credential capture |
| T1071.001 | Application Layer Protocol: Web | HTTP traffic analysis |
| T1071.004 | Application Layer Protocol: DNS | DNS analysis |
| T1568 | Dynamic Resolution | DNS — DGA/NXDOMAIN pattern |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Nmap 7.98 | Network reconnaissance |
| Hydra 9.x | Brute force simulation |
| Wireshark 4.x | Packet capture and analysis |
| tcpdump 4.x | CLI capture on Ubuntu |
| curl 8.18.0 | HTTP request generation |

---

*Lab conducted: May 2026 · VMware Workstation · Isolated Host-only network*
