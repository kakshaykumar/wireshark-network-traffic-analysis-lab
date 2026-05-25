# FTP Credential Attack Analysis

## Overview

A brute-force credential attack was executed against the FTP service on the target host. Unlike SSH, FTP transmits all authentication data in cleartext — every username and password attempt is transmitted as readable text on the wire. The complete attack, including every tested credential and the confirmed successful entry, is recoverable from the packet capture without any decryption or specialised tooling.

**Capture file:** [`ftp-credential-attack.pcapng`](../pcap-files/authentication-attacks/ftp-credential-attack.pcapng)

---

## Environment

| Property | Value |
|----------|-------|
| Source | 192.168.110.132 (Kali Linux) |
| Target | 192.168.110.130 (Ubuntu — vsftpd 3.0.5, port 21) |
| Interface captured | Ubuntu ens37 (defender perspective) |
| Capture perspective | Inbound traffic at target |

---

## Commands Used

```bash
# FTP brute force — verbose output, sequential attempts
# Wordlist: wordlist-credentials.txt (12 entries)
hydra -l labuser -P wordlist-credentials.txt ftp://192.168.110.130 -V
```

**Wordlist used:** [`wordlist-credentials.txt`](wordlist-credentials.txt)

---

## Wireshark Filter

```
ftp
```

---

## Analysis

### Authentication Attempts — Fully Visible in Plaintext

FTP provides no encryption at any layer. Every command exchanged between client and server appears directly in the Wireshark packet list as readable text without any filtering, decoding, or analysis:

```
Response: 220 (vsFTPd 3.0.5)        ← service banner — software version exposed
Request:  USER labuser               ← target username in plaintext
Response: 331 Please specify the password.
Request:  PASS welcome               ← attempt 1
Response: 530 Login incorrect.
Request:  PASS adminpass123          ← attempt 2
Response: 530 Login incorrect.
Request:  PASS password              ← attempt 3
Response: 530 Login incorrect.
Request:  PASS 123456                ← attempt 4
Response: 530 Login incorrect.
Request:  PASS qwerty                ← attempt 5
Response: 530 Login incorrect.
Request:  PASS password123           ← attempt 6
Response: 530 Login incorrect.
Request:  PASS test123               ← attempt 7
Response: 530 Login incorrect.
Request:  PASS admin                 ← attempt 8
Response: 530 Login incorrect.
Request:  PASS labuser               ← attempt 9 — correct credential
Response: 230 Login successful.
```

### Information Exposed in the 220 Banner

The server's initial 220 response discloses the FTP daemon name and version before any authentication occurs:

```
220 (vsFTPd 3.0.5)
```

This version string is returned to any client that connects to port 21 — no authentication is required to receive it.

### Credential Recovery

An observer capturing this traffic can recover the following without any analysis tools:

| Data | Value |
|------|-------|
| Username | labuser |
| Correct password | labuser |
| Attempts before success | 9 |
| All tested passwords | welcome, adminpass123, password, 123456, qwerty, password123, test123, admin, labuser |
| FTP software | vsftpd 3.0.5 |

### Weak Credential Observation

The successful credential `labuser:labuser` uses password equal to username — one of the most commonly targeted patterns in credential attacks. It appeared at position 9 in a 12-entry wordlist, confirming that minimal wordlist effort is sufficient to compromise accounts with predictable passwords.

---

## Evidence

**Figure 1 — FTP brute-force: all PASS commands visible in packet list. Response 230 Login successful visible at the bottom.**

![FTP cleartext credential spray](screenshots/ftp-cleartext-credential-spray.png)

---

## Key Findings

- **All credentials visible in plaintext** — no decryption, no specialised tooling required
- **Service version disclosed pre-authentication** — `vsftpd 3.0.5` in the 220 banner
- **Entire tested wordlist recoverable** — all 9 PASS attempts visible as sequential FTP packets
- **Successful credential confirmed** — `labuser:labuser` (password equals username)
- **192 total packets** — complete attack and authentication story in a small capture file
- **530 responses confirm failed attempts** — server provides explicit failure confirmation per attempt, accelerating brute-force efficiency

---

## MITRE ATT&CK

| ID | Technique | Tactic |
|----|-----------|--------|
| T1110.001 | Brute Force: Password Guessing | Credential Access |
| T1040 | Network Sniffing | Credential Access |

---

## Detection Recommendations

- **Disable FTP** — no configuration change makes FTP safe for credential transmission; the protocol is architecturally cleartext
- **Replace with SFTP** — OpenSSH is already running on this host (port 22); configure the SFTP subsystem: `Subsystem sftp /usr/lib/openssh/sftp-server`
- **Password policy** — enforce that passwords cannot match usernames; implement minimum complexity requirements
- **If FTP must remain:** configure FTPS (`ssl_enable=YES` in `/etc/vsftpd.conf`) as an absolute minimum; suppress the version banner (`ftpd_banner=FTP Server Ready`)
- **Network monitoring** — any IDS inspecting port 21 traffic captures FTP credentials without any special configuration; use this visibility for early attack detection
