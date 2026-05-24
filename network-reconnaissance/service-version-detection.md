# Service and Version Detection

## Objective
Demonstrate how Nmap's version detection retrieves exact software versions through banner grabbing, and how that information directly enables targeted attack planning.

---

## Lab Setup
| Property | Value |
|----------|-------|
| Attacker | Kali Linux — 192.168.110.132 |
| Target | Ubuntu 22.04 — 192.168.110.130 |
| Capture interface | Kali ens37 (attacker perspective) |
| Capture file | `version-detection.pcapng` |

---

## Command Used

```bash
nmap -sV 192.168.110.130
```

Without `sudo`, `-sV` falls back to a TCP connect scan (full handshake). This is visible in the capture as complete connections rather than half-open probes.

---

## Nmap Output

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
22/tcp open  ssh     OpenSSH 10.2p1 Ubuntu 2ubuntu3.2 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.66 ((Ubuntu))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```
*Full terminal output: [`nmap-terminal-output.txt`](nmap-terminal-output.txt)*

---

## Wireshark Filter

```
tcp and ip.addr == 192.168.110.130
```

---

## Traffic Analysis

### Full TCP handshake vs SYN scan

Version detection completes full connections to retrieve banners — visually distinct from the SYN scan's RST pattern:

```
Kali → Ubuntu:21   [SYN]               ← connection attempt
Ubuntu → Kali      [SYN, ACK]          ← accepted
Kali → Ubuntu:21   [ACK]               ← handshake COMPLETED
Ubuntu → Kali      220 (vsFTPd 3.0.5)  ← banner returned
Kali → Ubuntu:21   [FIN, ACK]          ← graceful close
```

### Banners retrieved

**FTP (port 21):**
```
220 (vsFTPd 3.0.5)
```

**SSH (port 22):**
```
SSH-2.0-OpenSSH_10.2p1 Ubuntu-2ubuntu3.2
```

**HTTP (port 80):**
```
Server: Apache/2.4.66 (Ubuntu)
```
Apache's default page also exposed: `Apache2 Ubuntu Default Page: It works` — confirming a default installation with no custom application deployed.

### Why version information is dangerous

Each string maps directly to public vulnerability databases:
- `vsftpd 3.0.5` → searchable in NVD, Exploit-DB
- `OpenSSH 10.2p1` → any known CVEs for this release identifiable
- `Apache 2.4.66` → patch level determines vulnerability exposure

Complete attack surface intelligence from a single 10.95-second scan.

---

## Attacker Perspective
Exact software versions for all three services obtained in under 11 seconds. Sufficient to proceed to CVE lookup and targeted exploitation without further reconnaissance.

## Defender Perspective
Rapid full connections from 192.168.110.132 to ports 21, 22, and 80 in succession, each closing after minimal data exchange. Pattern — rapid multi-service connections with minimal data transfer — is characteristic of automated banner grabbing. FTP banner delivered in cleartext and visible to any observer.

---

## Screenshot

**Version detection: FTP banner 220 vsFTPd 3.0.5 expanded. SSH and HTTP banners visible in packet list Info column.**

![Version detection banner grab](screenshots/version-detection.png)

---

## Key Findings

- `vsftpd 3.0.5` — FTP version exposed via 220 banner
- `OpenSSH 10.2p1 Ubuntu-2ubuntu3.2` — SSH version and Ubuntu package revision exposed
- `Apache httpd 2.4.66 (Ubuntu)` — web server version and OS distribution exposed
- Default Apache page confirmed — no custom application deployed
- Full connections logged on target — `-sV` leaves an audit trail unlike the SYN scan

---

## MITRE ATT&CK

| ID | Technique |
|----|-----------|
| T1046 | Network Service Scanning |
| T1082 | System Information Discovery |

---

## Defensive Recommendations

- Suppress banners: `ServerTokens Prod` (Apache), `ftpd_banner=` (vsftpd), `DebianBanner no` (SSH)
- Remove the Apache default page to avoid confirming infrastructure details
- Replace FTP with SFTP — vsftpd transmits credentials in cleartext; SFTP is already available via OpenSSH on port 22
- Keep software patched — known versions are immediately searchable against CVE databases
