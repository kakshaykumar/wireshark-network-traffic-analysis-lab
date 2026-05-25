# MITRE ATT&CK Mapping

All techniques observed and documented across the three lab topics.

---

## Full Technique Table

| Topic | Scenario | ID | Technique | Tactic | Evidence |
|-------|----------|-----|-----------|--------|----------|
| Network Reconnaissance | ICMP Ping Sweep | T1018 | Remote System Discovery | Discovery | ARP + ICMP sweep; 4 hosts found |
| Network Reconnaissance | ICMP Ping Sweep | T1595.001 | Active Scanning: IP Blocks | Reconnaissance | nmap -sn across 256 addresses |
| Network Reconnaissance | TCP SYN Scan | T1046 | Network Service Scanning | Discovery | SYN probes to 1000 ports; 3 open found |
| Network Reconnaissance | Version Detection | T1046 | Network Service Scanning | Discovery | Full connections for banner grabbing |
| Network Reconnaissance | Version Detection | T1082 | System Information Discovery | Discovery | vsftpd 3.0.5, OpenSSH 10.2p1, Apache 2.4.66 |
| Network Reconnaissance | Aggressive Scan | T1595 | Active Scanning | Reconnaissance | NSE scripts across multiple protocols |
| Network Reconnaissance | Aggressive Scan | T1082 | System Information Discovery | Discovery | OS fingerprint; .git/HEAD probed |
| Authentication Attacks | SSH Brute Force | T1110.001 | Brute Force: Password Guessing | Credential Access | 5 rapid SSH connections; libssh banner |
| Authentication Attacks | FTP Brute Force | T1110.001 | Brute Force: Password Guessing | Credential Access | 12 PASS attempts in plaintext |
| Authentication Attacks | FTP Brute Force | T1040 | Network Sniffing | Credential Access | All FTP credentials unencrypted |
| Authentication Attacks | FTP Credential Capture | T1040 | Network Sniffing | Credential Access | PASS labuser visible in packet list |
| Authentication Attacks | HTTP Basic Auth Attack | T1110.001 | Brute Force: Password Guessing | Credential Access | 12 Authorization headers with decoded creds |
| Authentication Attacks | HTTP Basic Auth Attack | T1040 | Network Sniffing | Credential Access | Base64 credentials trivially decoded |
| Protocol Analysis | FTP vs SSH | T1040 | Network Sniffing | Credential Access | FTP exposure vs SSH encryption |
| Protocol Analysis | HTTP Traffic Analysis | T1071.001 | App Layer Protocol: Web | Command and Control | All HTTP content and headers visible |
| Protocol Analysis | TCP Handshake Analysis | T1046 | Network Service Scanning | Discovery | SYN scan pattern via TCP flag analysis |
| Protocol Analysis | DNS Analysis | T1071.004 | App Layer Protocol: DNS | Command and Control | NXDOMAIN; external resolver bypass |
| Protocol Analysis | DNS Analysis | T1568 | Dynamic Resolution | Command and Control | DGA detection via NXDOMAIN pattern |

---

## Tactic Coverage

| Tactic | Techniques |
|--------|-----------|
| Reconnaissance | T1595, T1595.001 |
| Discovery | T1018, T1046, T1082 |
| Credential Access | T1040, T1110.001 |
| Command and Control | T1071.001, T1071.004, T1568 |

---

## IOC Summary by Technique

### T1046 — Network Service Scanning
- `TCP Win=1024` in SYN probes → Nmap fingerprint
- `SSH-1.5-NmapNSE_1.0` in SSH client banner → Nmap NSE module
- 200+ SYN probes/second from one source → automated scanner

### T1110.001 — Brute Force: Password Guessing
- `SSH-2.0-libssh_0.11.3` in SSH client banner → Hydra fingerprint
- `User-Agent: Mozilla/4.0 (Hydra)` in HTTP headers → Hydra fingerprint
- 3+ SSH connections within 10s from one IP → SSH brute force pattern
- Multiple 401 responses to same path from one IP → HTTP brute force pattern

### T1040 — Network Sniffing
- FTP `PASS` command visible in packet list → cleartext credential
- HTTP `Authorization: Basic` header → Base64-encoded credential

### T1071.004 — DNS
- DNS response code 3 (NXDOMAIN) for non-existent domain
- DNS query to 8.8.8.8 directly → internal resolver bypass
- 20 NXDOMAINs/minute from one host → DGA/C2 high-confidence indicator
