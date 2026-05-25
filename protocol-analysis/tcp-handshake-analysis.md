# TCP Handshake Analysis

## Overview

TCP connection behaviour was analysed across two scenarios to document the visual and structural difference between a normal three-way handshake and the half-open handshake produced by a SYN scan. Understanding this distinction is foundational to network security monitoring — the TCP flag field and conversation completeness are the primary indicators used to distinguish legitimate connections from port scanning activity at the packet level.

**Capture files:**
- Normal handshake: [`tcp-handshake-analysis.pcapng`](../pcap-files/protocol-analysis/tcp-handshake-analysis.pcapng)
- SYN scan handshake: [`port-scan-syn-half-open.pcapng`](../pcap-files/network-reconnaissance/port-scan-syn-half-open.pcapng)

---

## Environment

| Property | Value |
|----------|-------|
| Source | 192.168.110.132 (Kali Linux) |
| Target | 192.168.110.130 (Ubuntu) |
| Interface captured | Ubuntu ens37 (defender perspective) |

---

## Wireshark Filters

```
# Normal handshake — show SYN and FIN packets only
tcp.flags.syn == 1

# SYN scan — isolate the half-open sequence on an open port
tcp and ip.addr == 192.168.110.130 and tcp.port == 22
```

---

## Analysis

### Normal TCP Three-Way Handshake

A legitimate TCP connection — observed in the HTTP traffic capture — follows a predictable and complete sequence:

```
Step 1 — Client initiates:
192.168.110.132 → 192.168.110.130:80  [SYN]      Seq=0 Win=64240

Step 2 — Server acknowledges and responds:
192.168.110.130 → 192.168.110.132     [SYN, ACK] Seq=0 Ack=1

Step 3 — Client completes handshake:
192.168.110.132 → 192.168.110.130:80  [ACK]      Seq=1 Ack=1

[Application data exchange — HTTP request and response]

Step 4 — Graceful close:
192.168.110.132 → 192.168.110.130:80  [FIN, ACK]
192.168.110.130 → 192.168.110.132     [FIN, ACK]
```

Key TCP fields in a normal SYN packet:

```
Flags: 0x002 (SYN)
  SYN: Set
  ACK: Not set
Window size: 64240    ← real OS TCP window size
Conversation completeness: Complete, WITH_DATA
```

The handshake completes, data is exchanged, and the connection closes gracefully with FIN packets acknowledged by both sides.

### SYN Scan — Half-Open Handshake

A SYN scan probing the same target produces a structurally different sequence for each open port:

```
Step 1 — Scanner sends SYN:
192.168.110.132 → 192.168.110.130:22  [SYN]      Seq=0 Win=1024

Step 2 — Target responds (port is open):
192.168.110.130 → 192.168.110.132     [SYN, ACK] Seq=0 Ack=1

Step 3 — Scanner sends RST instead of ACK:
192.168.110.132 → 192.168.110.130:22  [RST]      Seq=1 Win=0
```

Key TCP fields in the RST packet:

```
Flags: 0x004 (RST)
  Reset: Set
  SYN: Not set
  ACK: Not set
Window size: 0
Conversation completeness: Incomplete (35)
```

The connection is deliberately terminated by the scanner before completion. No application-layer session is established, and no data is exchanged.

### Diagnostic Comparison

| Property | Normal Connection | SYN Scan |
|----------|-----------------|----------|
| Third packet | ACK — handshake completes | RST — deliberately aborted |
| Window size (SYN) | 64240 (real OS value) | 1024 (Nmap crafted value) |
| ACK flag on final packet | Yes | No — RST has no ACK |
| Data exchange | Yes | Never |
| Conversation status | Complete, WITH_DATA | Incomplete (35) |
| Graceful close | FIN-ACK sequence | No — RST is abrupt |

### Window Size as a Tool Fingerprint

The SYN probe `Win=1024` is not a real OS TCP window value. A legitimate OS connection from the same machine uses `Win=64240`. The crafted value `1024` is Nmap's default SYN probe configuration and is consistently present across all 1,000 probes in the scan capture. This value alone allows IDS systems to fingerprint Nmap SYN scans independently of any other indicator.

### Conversation Completeness Flag

Wireshark automatically evaluates each TCP stream and marks it with a completeness value. Normal connections show `Complete, WITH_DATA` — the handshake finished and application data was exchanged. SYN scan streams show `Incomplete (35)` — the handshake started but was abandoned before completion. This flag provides an automatic signal in any Wireshark-based analysis workflow.

---

## Evidence

**Figure 1 — SYN scan RST packet: Flags 0x004 (RST set), Window=0, Incomplete conversation**

*Three-packet sequence visible: SYN → SYN-ACK → RST. Reset: Set highlighted in packet details.*

![TCP SYN scan RST incomplete handshake](screenshots/tcp-syn-scan-rst-incomplete-handshake.png)

---

## Key Findings

- **Normal handshake:** SYN → SYN-ACK → ACK → data → FIN-ACK; `Win=64240`; `Complete, WITH_DATA`
- **SYN scan:** SYN → SYN-ACK → RST; `Win=1024`; `Incomplete (35)`; no data exchange
- **`Win=1024` is Nmap's fingerprint** — not a real OS default; identifies Nmap specifically regardless of scan flags
- **RST without ACK** is the structural tell of an aborted connection — occurs when a client intentionally refuses to complete the handshake
- **`Conversation completeness: Incomplete`** — Wireshark's automatic flag for any stream terminated without a proper close sequence

---

## MITRE ATT&CK

| ID | Technique | Tactic |
|----|-----------|--------|
| T1046 | Network Service Scanning | Discovery |

---

## Detection Recommendations

- **IDS signature:** TCP SYN with `window_size == 1024` from external sources — Nmap default probe value
- **Volume threshold:** Alert on more than 50 SYN packets from a single source IP to different destination ports within 5 seconds
- **Conversation completeness monitoring:** High volumes of `Incomplete` TCP conversations from one source is a reliable scan indicator regardless of tool
- **Stateful firewall logging:** SYN packets without a corresponding ACK within the session timeout period indicate half-open scan activity and can be flagged by stateful inspection engines
