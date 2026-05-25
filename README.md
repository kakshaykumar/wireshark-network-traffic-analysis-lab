# Network Threat Investigation

Network traffic analysis project documenting packet-level investigation of attacker reconnaissance, credential attacks, and protocol vulnerabilities using Wireshark. Conducted in an controlled VMware lab environment with Kali Linux as the attack platform and Ubuntu as the target. Each scenario includes attacker simulation, traffic capture, defender-perspective analysis, MITRE ATT&CK mapping, and detection recommendations.

---

## Environment

| Component | Details |
|-----------|---------|
| Attack platform | Kali Linux — 192.168.110.132 |
| Target host | Ubuntu 22.04 — 192.168.110.130 |
| Network | VMware Host-only — 192.168.110.0/24 |
| Capture tool | Wireshark 4.x / tcpdump |

**Target services:** vsftpd 3.0.5 (FTP/21) · OpenSSH 10.2p1 (SSH/22) · Apache 2.4.66 (HTTP/80)

Full environment details: [environment-setup/network-topology.md](environment-setup/network-topology.md)

---

## Network Topology

```
┌──────────────────────────────────────────────────┐
│             VMware Host-only Network             │
│                192.168.110.0/24                  │
│                                                  │
│   ┌─────────────────┐    ┌──────────────────────┐│
│   │   Kali Linux    │    │    Ubuntu Server     ││
│   │  .110.132       │◄──►│    .110.130          ││
│   │  Attack         │    │    FTP · SSH · HTTP  ││
│   └─────────────────┘    └──────────────────────┘│
│                                                  │
│   Gateway: .110.1   DHCP: .110.254               │
└──────────────────────────────────────────────────┘
```

---

## Repository Structure

```
network-threat-investigation/
│
├── network-reconnaissance/
│   ├── host-discovery-analysis.md
│   ├── port-scan-investigation.md
│   ├── service-version-enumeration.md
│   ├── active-recon-investigation.md
│   ├── nmap-recon-terminal-output.txt
│   └── screenshots/
│
├── authentication-attacks/
│   ├── ssh-credential-attack-analysis.md
│   ├── ftp-credential-attack-analysis.md
│   ├── ftp-session-credential-exposure.md
│   ├── http-auth-attack-analysis.md
│   ├── simulated-credential-wordlist.txt
│   └── screenshots/
│
├── protocol-analysis/
│   ├── plaintext-vs-encrypted-protocol-analysis.md
│   ├── http-traffic-analysis.md
│   ├── tcp-handshake-analysis.md
│   ├── dns-traffic-investigation.md
│   └── screenshots/
│
├── environment-setup/
│   └── network-topology.md
│
├── pcap-files/
│   ├── network-reconnaissance/
│   ├── authentication-attacks/
│   └── protocol-analysis/
│
├── investigation-findings.md
├── mitre-attack-technique-mapping.md
└── wireshark-detection-filters-reference.md
```

---

## Network Reconnaissance

Host discovery, port enumeration, service fingerprinting, and automated script probing. Captured from the attack platform interface.

| Scenario | File | MITRE |
|----------|------|-------|
| Host discovery via ICMP and ARP — OS fingerprinting through TTL analysis | [host-discovery-analysis.md](network-reconnaissance/host-discovery-analysis.md) | T1018, T1595.001 |
| TCP SYN scan — half-open port enumeration and Nmap probe signature | [port-scan-investigation.md](network-reconnaissance/port-scan-investigation.md) | T1046 |
| Service version enumeration — banner grabbing across FTP, SSH, HTTP | [service-version-enumeration.md](network-reconnaissance/service-version-enumeration.md) | T1046, T1082 |
| Aggressive scan — NSE script probing, FTP default credentials, SSH fingerprint | [active-recon-investigation.md](network-reconnaissance/active-recon-investigation.md) | T1595, T1082 |

---

## Authentication Attacks

Brute-force credential attacks against SSH, FTP, and HTTP. Captured from the target host interface — the defender view of inbound attacks.

| Scenario | File | MITRE |
|----------|------|-------|
| SSH brute force — Hydra tool fingerprint, pattern detection without credential visibility | [ssh-credential-attack-analysis.md](authentication-attacks/ssh-credential-attack-analysis.md) | T1110.001 |
| FTP brute force — all password attempts visible in plaintext | [ftp-credential-attack-analysis.md](authentication-attacks/ftp-credential-attack-analysis.md) | T1110.001, T1040 |
| FTP session credential exposure — complete session reconstruction from single login | [ftp-session-credential-exposure.md](authentication-attacks/ftp-session-credential-exposure.md) | T1040 |
| HTTP Basic Auth attack — Base64 encoding decoded, Hydra User-Agent fingerprint | [http-auth-attack-analysis.md](authentication-attacks/http-auth-attack-analysis.md) | T1110.001, T1040 |

**Wordlist used across attacks:** [simulated-credential-wordlist.txt](authentication-attacks/simulated-credential-wordlist.txt)

---

## Protocol Analysis

Comparative analysis of secure vs insecure protocols, TCP connection behaviour, and DNS traffic patterns.

| Scenario | File | Key Finding |
|----------|------|-------------|
| FTP vs SSH — same authentication action, opposite security outcomes | [plaintext-vs-encrypted-protocol-analysis.md](protocol-analysis/plaintext-vs-encrypted-protocol-analysis.md) | Protocol selection is a security decision |
| HTTP traffic — server disclosure, response codes, credential exposure | [http-traffic-analysis.md](protocol-analysis/http-traffic-analysis.md) | All HTTP content visible to network observers |
| TCP handshake — normal three-way handshake vs SYN scan half-open pattern | [tcp-handshake-analysis.md](protocol-analysis/tcp-handshake-analysis.md) | TCP flags identify port scanning at packet level |
| DNS traffic — normal resolution, NXDOMAIN, external resolver bypass | [dns-traffic-investigation.md](protocol-analysis/dns-traffic-investigation.md) | NXDOMAIN volume signals DGA or C2 activity |

---

## Key Findings

**FTP transmits credentials in plaintext.** `PASS labuser` is readable in the Wireshark packet list without any decryption. Passive monitoring of port 21 captures all FTP credentials automatically.

**HTTP Basic Auth uses encoding, not encryption.** `Authorization: Basic YWRtaW46YWRtaW4=` decodes to `admin:admin` in one command. Wireshark displays the decoded credential automatically.

**SSH brute force is detectable without credential visibility.** Five rapid connections from the same source IP to port 22 is the pattern. The `SSH-2.0-libssh_0.11.3` client banner fingerprints Hydra specifically.

**Nmap is fingerprinted by TCP window size.** Every SYN probe carries `Win=1024` — not a real OS value. Identifies Nmap across all scan types without signature databases.

**Aggressive scans actively test for misconfigurations.** `GET /.git/HEAD` and `USER anonymous` are sent automatically by NSE scripts — beyond port enumeration into configuration probing.

**Password equals username on both test accounts.** `labuser:labuser` cracked in 9 FTP attempts. `admin:admin` cracked on the first HTTP attempt. Predictable patterns require minimal wordlist effort.

**NXDOMAIN from one host at high volume signals DGA malware.** A single NXDOMAIN is normal. 20+ per minute from one internal host is a high-confidence C2 indicator.

---

## MITRE ATT&CK Coverage

| ID | Technique | Scenario |
|----|-----------|---------|
| T1018 | Remote System Discovery | Host discovery analysis |
| T1046 | Network Service Scanning | Port scan, service enumeration |
| T1082 | System Information Discovery | Service enumeration, active recon |
| T1595 | Active Scanning | Active recon investigation |
| T1595.001 | Active Scanning: Scanning IP Blocks | Host discovery analysis |
| T1110.001 | Brute Force: Password Guessing | SSH, FTP, HTTP credential attacks |
| T1040 | Network Sniffing | FTP credential exposure, HTTP analysis |
| T1071.001 | Application Layer Protocol: Web | HTTP traffic analysis |
| T1071.004 | Application Layer Protocol: DNS | DNS traffic investigation |
| T1568 | Dynamic Resolution | DNS — NXDOMAIN/DGA pattern |

Full mapping with evidence and IOCs: [mitre-attack-technique-mapping.md](mitre-attack-technique-mapping.md)

---

## Reference Files

| File | Contents |
|------|---------|
| [investigation-findings.md](investigation-findings.md) | All security findings ranked by impact with remediation |
| [mitre-attack-technique-mapping.md](mitre-attack-technique-mapping.md) | Complete ATT&CK mapping table with IOC summary |
| [wireshark-detection-filters-reference.md](wireshark-detection-filters-reference.md) | All Wireshark display filters used across every scenario |

---

*Conducted: May 2026 · VMware Workstation · Controlled Host-only network*
