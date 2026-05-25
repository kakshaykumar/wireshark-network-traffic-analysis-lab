# MITRE ATT&CK Technique Mapping

All techniques observed, demonstrated, or relevant to detection across the three analysis topics. Techniques marked as **observed** were directly evidenced in packet captures. Techniques marked as **detection-relevant** describe attacker methods that the corresponding analysis teaches recognition of — useful for detection engineering context even where the scenario itself demonstrates normal traffic.

---

## Full Mapping Table

| Topic | Scenario | ID | Technique | Tactic | Type | Evidence |
|-------|----------|-----|-----------|--------|------|---------|
| Network Reconnaissance | Host Discovery | T1018 | Remote System Discovery | Discovery | Observed | ARP + ICMP sweep across /24 subnet; 4 hosts identified |
| Network Reconnaissance | Host Discovery | T1595.001 | Active Scanning: Scanning IP Blocks | Reconnaissance | Observed | nmap -sn across 256 addresses |
| Network Reconnaissance | Port Scan | T1046 | Network Service Scanning | Discovery | Observed | SYN probes to 1000 ports; Win=1024 Nmap fingerprint |
| Network Reconnaissance | Service Enumeration | T1046 | Network Service Scanning | Discovery | Observed | Full TCP connections for banner grabbing on ports 21, 22, 80 |
| Network Reconnaissance | Service Enumeration | T1082 | System Information Discovery | Discovery | Observed | vsftpd 3.0.5, OpenSSH 10.2p1, Apache 2.4.66 exposed in banners |
| Network Reconnaissance | Active Recon | T1595 | Active Scanning | Reconnaissance | Observed | NSE scripts probing HTTP paths, FTP credentials, SSH service |
| Network Reconnaissance | Active Recon | T1082 | System Information Discovery | Discovery | Observed | OS fingerprint attempted; /.git/HEAD probe; /HNAP1, PROPFIND |
| Authentication Attacks | SSH Brute Force | T1110.001 | Brute Force: Password Guessing | Credential Access | Observed | 5 rapid SSH connections from same source; libssh_0.11.3 banner |
| Authentication Attacks | FTP Brute Force | T1110.001 | Brute Force: Password Guessing | Credential Access | Observed | 12 PASS attempts visible in plaintext; 230 Login successful |
| Authentication Attacks | FTP Brute Force | T1040 | Network Sniffing | Credential Access | Observed | All FTP credentials transmitted without encryption |
| Authentication Attacks | FTP Session | T1040 | Network Sniffing | Credential Access | Observed | PASS labuser in packet list; full session reconstructible |
| Authentication Attacks | HTTP Attack | T1110.001 | Brute Force: Password Guessing | Credential Access | Observed | Authorization headers with decoded credentials; Hydra User-Agent |
| Authentication Attacks | HTTP Attack | T1040 | Network Sniffing | Credential Access | Observed | Base64-encoded credentials decoded trivially from HTTP traffic |
| Protocol Analysis | FTP vs SSH | T1040 | Network Sniffing | Credential Access | Observed | FTP exposes full session; SSH provides complete confidentiality |
| Protocol Analysis | HTTP Analysis | T1071.001 | Application Layer Protocol: Web | Command and Control | Detection-relevant | HTTP used for C2 communication by attackers; analysis demonstrates what to inspect |
| Protocol Analysis | TCP Handshake | T1046 | Network Service Scanning | Discovery | Observed | SYN scan pattern identified via TCP flag and window size analysis |
| Protocol Analysis | DNS Investigation | T1071.004 | Application Layer Protocol: DNS | Command and Control | Detection-relevant | DNS used for C2 beaconing by malware; NXDOMAIN pattern documents detection basis |
| Protocol Analysis | DNS Investigation | T1568 | Dynamic Resolution | Command and Control | Detection-relevant | DGA technique produces high-volume NXDOMAIN — documented as detection reference |

---

## Tactic Coverage

| Tactic | Techniques |
|--------|-----------|
| Reconnaissance | T1595, T1595.001 |
| Discovery | T1018, T1046, T1082 |
| Credential Access | T1040, T1110.001 |
| Command and Control | T1071.001, T1071.004, T1568 |

---

## Tool Fingerprint IOCs

Indicators extracted from captures that identify specific attack tools:

| Tool | Protocol | Fingerprint | Location in capture |
|------|----------|-------------|-------------------|
| Nmap | TCP | `Win=1024` in SYN probe | TCP Window Size field |
| Nmap NSE | SSH | `SSH-1.5-NmapNSE_1.0` | SSH Client Protocol banner |
| Hydra | SSH | `SSH-2.0-libssh_0.11.3` | SSH Client Protocol banner |
| Hydra | HTTP | `Mozilla/4.0 (Hydra)` | HTTP User-Agent header |

---

## Detection Thresholds Referenced

| Technique | Detection threshold | Confidence |
|-----------|-------------------|-----------|
| T1018 / T1595 — Host scanning | >10 ICMP Echo Requests from one source within 10 seconds | Medium |
| T1046 — Port scanning | >50 SYN packets from one source to different ports within 5 seconds | High |
| T1046 — Nmap SYN scan | TCP SYN with `Win=1024` from external source | High (tool-specific) |
| T1110.001 — SSH brute force | 3+ SSH connections from one IP within 10 seconds + libssh banner | High |
| T1110.001 — HTTP brute force | 5+ consecutive 401 responses to same path from one source | Medium |
| T1568 / T1071.004 — DGA activity | 20+ NXDOMAIN responses from one internal host within 60 seconds | High |
