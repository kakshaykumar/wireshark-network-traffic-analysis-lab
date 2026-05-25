# Port Scan Investigation

## Overview

Following host discovery, a TCP SYN scan was performed against the identified target (192.168.110.130) to enumerate open ports and exposed services. The SYN scan technique sends probe packets but deliberately avoids completing the TCP three-way handshake — a characteristic behaviour that produces a distinct traffic pattern detectable through TCP flag analysis. Packet capture confirmed three open services and identified Nmap's tool-specific probe signature.

**Capture file:** [`port-scan-syn-half-open.pcapng`](../pcap-files/network-reconnaissance/port-scan-syn-half-open.pcapng)

---

## Environment

| Property | Value |
|----------|-------|
| Source | 192.168.110.132 (Kali Linux) |
| Target | 192.168.110.130 (Ubuntu) |
| Interface captured | ens37 (Host-only network) |
| Capture perspective | Attacker interface |

---

## Commands Used

```bash
# TCP SYN scan — requires root to craft raw packets
sudo nmap -sS 192.168.110.130
```

Full terminal output: [`nmap-recon-terminal-output.txt`](nmap-recon-terminal-output.txt)

---

## Wireshark Filters

```
# All TCP traffic directed at the target
tcp and ip.dst == 192.168.110.130

# Isolate the half-open sequence on a specific open port
tcp and ip.addr == 192.168.110.130 and tcp.port == 22
```

---

## Analysis

### Open Ports Identified

```
PORT   STATE  SERVICE
21/tcp open   ftp
22/tcp open   ssh
80/tcp open   http

997 closed tcp ports (reset)
Scan completed in 4.78 seconds
```

Three services confirmed exposed. The remaining 997 probed ports returned RST responses, indicating they are closed.

### Half-Open Scan Mechanism

The SYN scan operates by sending SYN packets to each target port and observing the response — without completing the handshake:

**Open port behaviour (port 22):**
```
192.168.110.132 → 192.168.110.130:22  [SYN]      Seq=0 Win=1024
192.168.110.130 → 192.168.110.132     [SYN, ACK] Seq=0 Ack=1
192.168.110.132 → 192.168.110.130:22  [RST]      Seq=1 Win=0
```

**Closed port behaviour:**
```
192.168.110.132 → 192.168.110.130:995 [SYN]      Seq=0 Win=1024
192.168.110.130 → 192.168.110.132     [RST, ACK] Seq=1 Win=0
```

On an open port, the target responds with SYN-ACK confirming the service is listening. The scanner then sends RST to tear down the connection before it completes — avoiding a full session that would be logged by application-layer services. On a closed port, the target immediately responds with RST.

### Nmap Probe Signature — Tool Fingerprinting

Every SYN probe in the capture carries a non-standard TCP window size:

```
Flags: SYN
Window size: 1024
MSS: 1460
```

A standard OS TCP stack uses a significantly larger window — legitimate connections from this machine show `Win=64240`. The value `Win=1024` is not a real OS default; it is Nmap's crafted packet value and serves as a reliable tool fingerprint. IDS systems can identify Nmap SYN scans specifically through this value without needing signature databases.

### Scan Speed and Volume

Approximately 1,000 ports were probed in 4.78 seconds — roughly 200 SYN packets per second from a single source. Wireshark flags each incomplete conversation with `Conversation completeness: Incomplete (35)`, confirming that no handshake was finalised across the entire scan.

---

## Evidence

**Figure 1 — High-volume SYN probe: rapid sequential port scanning from single source**

![Port scan SYN flood evidence](screenshots/port-scan-syn-flood-evidence.png)

**Figure 2 — Half-open handshake: SYN → SYN-ACK → RST sequence with TCP flags expanded**

*Flags: 0x002 (SYN set), Window: 1024 — Nmap probe signature confirmed*

![SYN scan half-open Nmap signature](screenshots/syn-scan-half-open-nmap-signature.png)

---

## Key Findings

- **3 open ports confirmed:** 21/tcp (FTP), 22/tcp (SSH), 80/tcp (HTTP)
- **Nmap tool fingerprint:** `Win=1024` in every SYN probe — not a standard OS value
- **Half-open pattern confirmed:** RST sent by scanner after receiving SYN-ACK — no full connection established
- **997 closed ports** returned RST-ACK immediately — no services behind them
- **Scan duration:** 4.78 seconds for 1,000-port sweep — volume and speed alone are sufficient IDS triggers

---

## MITRE ATT&CK

| ID | Technique | Tactic |
|----|-----------|--------|
| T1046 | Network Service Scanning | Discovery |

---

## Detection Recommendations

- Alert on TCP SYN packets from a single source IP exceeding 50 distinct destination ports within 5 seconds
- IDS signature: TCP SYN with `window_size == 1024` and `MSS == 1460` from an external source — Nmap default probe fingerprint
- `Conversation completeness: Incomplete` flags in network monitoring tools indicate half-open scan activity
- Reducing the exposed service count directly limits the information returned to a scanner — FTP (port 21) on this host has no justification given SSH is available for encrypted file transfer
