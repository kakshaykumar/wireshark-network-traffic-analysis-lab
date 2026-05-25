# SSH Credential Attack Analysis

## Overview

A brute-force credential attack was executed against the SSH service running on the target host to assess authentication resilience and evaluate network-level detectability. SSH encrypts all post-handshake traffic, meaning the authentication content itself is not visible in packet captures. However, the connection behaviour produced by automated tooling creates a distinct pattern that is reliably detectable through traffic analysis — and the attack tool can be fingerprinted from the SSH protocol banner without inspecting any encrypted payload.

**Capture file:** [`ssh-credential-attack.pcapng`](../pcap-files/authentication-attacks/ssh-credential-attack.pcapng)

---

## Environment

| Property | Value |
|----------|-------|
| Source | 192.168.110.132 (Kali Linux) |
| Target | 192.168.110.130 (Ubuntu — OpenSSH 10.2p1, port 22) |
| Interface captured | Ubuntu ens37 (defender perspective) |
| Capture perspective | Inbound traffic at target |

---

## Commands Used

```bash
# SSH brute force — 4 parallel threads, verbose output
# Wordlist: simulated-credential-wordlist.txt (12 entries)
hydra -l labuser -P simulated-credential-wordlist.txt ssh://192.168.110.130 -t 4 -V
```

**Wordlist used:** [`simulated-credential-wordlist.txt`](simulated-credential-wordlist.txt)

---

## Wireshark Filter

```
tcp.port == 22
```

---

## Analysis

### Connection Pattern

Five TCP conversations were established to port 22 from the same source IP (192.168.110.132) within seconds:

| Connection | Packets | Duration |
|-----------|---------|---------|
| 192.168.110.132:37932 → :22 | 22 | 0.078s |
| 192.168.110.132:37946 → :22 | 27 | 6.242s |
| 192.168.110.132:37962 → :22 | 27 | 6.251s |
| 192.168.110.132:37968 → :22 | 27 | 4.718s |
| 192.168.110.132:37972 → :22 | 28 | 3.585s |

Hydra was configured with `-t 4` (4 parallel threads), allowing multiple authentication attempts to proceed simultaneously. The wordlist entry `labuser` at position 8 was identified across the parallel thread pool, resulting in 5 connections rather than 12 sequential attempts. The correct credential was confirmed: `labuser:labuser`.

### Connection Lifecycle

Each connection follows an identical pattern:

```
[SYN] → [SYN-ACK] → [ACK]                    ← three-way handshake
Client: SSH-2.0-libssh_0.11.3                 ← Hydra tool fingerprint
Server: SSH-2.0-OpenSSH_10.2p1                ← target service version
[Key Exchange Init]
[ECDH Key Exchange Reply, New Keys]           ← session fully encrypted
[Encrypted packets — auth attempt not visible]
[FIN-ACK] → [FIN-ACK]                         ← connection closed
```

### Tool Fingerprint — Hydra Identified via SSH Banner

```
SSH-2.0-libssh_0.11.3
```

Hydra's SSH module uses the `libssh` library rather than the standard OpenSSH client. A user authenticating with the native `ssh` command would produce `SSH-2.0-OpenSSH_x.x`. The presence of `libssh` in an SSH Client Protocol banner indicates automated tooling. This IOC is present in every connection in the capture — 5 separate occurrences — and requires no inspection of encrypted content to identify.

### Encryption Confirmed

Expanding any post-handshake packet in the capture confirms encryption is effective:

```
SSH Version 2 (encryption: chacha20-poly1305@openssh.com)
Encrypted Packet: [hex — no readable content]
MAC: [message authentication code]
```

The authentication credentials, commands issued, and any response from the server are cryptographically protected. Detection of this attack relies entirely on connection behaviour and protocol metadata — not packet content.

---

## Evidence

**Figure 1 — SSH brute-force connections: repeated sessions to port 22 with Hydra fingerprint and encrypted payload visible**

*Packet list shows rapid repeated connections. Middle pane confirms chacha20-poly1305 encryption — no credential content visible.*

![SSH credential attack Hydra fingerprint](screenshots/ssh-credential-attack-hydra-fingerprint.png)

---

## Key Findings

- **Credentials not visible** — SSH encryption is effective; authentication content is fully protected at the packet level
- **Attack detectable by behaviour** — 5 rapid connections from the same source to port 22 within seconds is the brute-force pattern
- **Hydra fingerprinted** — `SSH-2.0-libssh_0.11.3` in the SSH client banner is a reliable IOC for Hydra; a human user would show `SSH-2.0-OpenSSH_x.x`
- **Parallel threading** — `-t 4` flag caused Hydra to attempt 4 credentials simultaneously, finding the match (`labuser`) in 5 connections rather than 8 sequential attempts
- **Encryption algorithm confirmed** — `chacha20-poly1305@openssh.com`: modern, authenticated cipher; no known practical weakness

---

## MITRE ATT&CK

| ID | Technique | Tactic |
|----|-----------|--------|
| T1110.001 | Brute Force: Password Guessing | Credential Access |

---

## Detection Recommendations

- **Fail2ban:** Block source IPs after 3–5 failed SSH authentication attempts within 60 seconds
- **SSH key authentication:** Set `PasswordAuthentication no` in `/etc/ssh/sshd_config` — eliminates password brute-force viability entirely regardless of tool or wordlist size
- **IDS rule:** Alert on `libssh` in SSH Client Protocol banner — identifies automated SSH tooling; no legitimate interactive user produces this string
- **SIEM correlation:** Multiple SSH connections from one source IP within 10 seconds + `libssh` client banner = high-confidence Hydra brute-force alert
