# Investigation Environment

## Overview

All packet captures in this project were conducted within an isolated VMware virtual network. No traffic reached the internet or the host network during any attack simulation. The environment consists of two virtual machines connected through a Host-only virtual switch, with a secondary NAT interface on each VM used exclusively for the DNS analysis scenario.

---

## Virtual Machines

### Kali Linux — Attack Platform

| Property | Value |
|----------|-------|
| Operating system | Kali Linux (rolling release, 2026) |
| IP address (lab network) | 192.168.110.132 |
| Primary interface | ens37 — VMware Host-only (VMnet1) |
| Secondary interface | ens33 — VMware NAT (internet access) |
| Role | Attack simulation — Nmap, Hydra, curl, ftp client |

### Ubuntu 22.04 — Target Host

| Property | Value |
|----------|-------|
| Operating system | Ubuntu 22.04 LTS |
| IP address (lab network) | 192.168.110.130 |
| IP address (NAT network) | 192.168.91.131 |
| Primary interface | ens37 — VMware Host-only (VMnet1) |
| Secondary interface | ens33 — VMware NAT (internet access) |
| Role | Target — vsftpd, OpenSSH, Apache with Basic Auth |

---

## Services Deployed on Target

| Service | Port | Software | Version |
|---------|------|---------|---------|
| FTP | 21/tcp | vsftpd | 3.0.5 |
| SSH | 22/tcp | OpenSSH | 10.2p1 Ubuntu 2ubuntu3.2 |
| HTTP | 80/tcp | Apache httpd | 2.4.66 (Ubuntu) |

HTTP was configured with Basic Authentication (`AuthType Basic`) to support the credential attack scenarios. FTP was configured to allow local user authentication with anonymous login disabled.

---

## Network Topology

```
                    [Windows Host — VMware Workstation]
                                    │
               ─────────────────────────────────────────
               │                                       │
         [VMnet1 — Host-only]                 [VMnet8 — NAT]
         192.168.110.0/24                    192.168.91.0/24
               │                                       │
    ┌──────────┴──────────┐               ┌────────────┴────────────┐
    │                     │               │                         │
    │     Kali Linux      │               │   Ubuntu ens33          │
    │     ens37           │               │   192.168.91.131        │
    │     .110.132        │               │   (DNS analysis only)   │
    └──────────┬──────────┘               └─────────────────────────┘
               │
    ┌──────────┴──────────┐
    │   Ubuntu Server     │
    │   ens37             │
    │   .110.130          │
    │   FTP · SSH · HTTP  │
    └─────────────────────┘

    Gateway: 192.168.110.1   (VMware virtual gateway)
    DHCP:    192.168.110.254 (VMware DHCP service)
```

---

## Dual-Interface Design

Both VMs carry two network interfaces with distinct roles:

| Interface | Network | Purpose |
|-----------|---------|---------|
| ens37 | Host-only (VMnet1) | All attack and defence traffic — isolated from internet |
| ens33 | NAT (VMnet8) | Internet access — used only for DNS analysis |

All reconnaissance and credential attack traffic ran exclusively over the ens37 Host-only network. The ens33 NAT interface was only active during the DNS traffic investigation scenario to generate real DNS queries against live external domains.

---

## Capture Strategy

Traffic was captured from different interfaces depending on the analysis objective:

| Topic | Capture host | Interface | Perspective |
|-------|-------------|-----------|-------------|
| Network Reconnaissance | Kali | ens37 | Attacker — outbound probes and inbound responses |
| Authentication Attacks | Ubuntu | ens37 | Defender — inbound attacks arriving at the target |
| Protocol Analysis (FTP, SSH, HTTP, TCP) | Ubuntu | ens37 | Defender — protocol comparison from server side |
| Protocol Analysis (DNS) | Ubuntu | ens33 | Internet-facing — real DNS resolution traffic |

Capturing from Ubuntu's interface in the authentication and protocol analysis topics replicates the perspective of a network analyst monitoring a server through a network tap or SPAN port — the standard SOC analyst view.

---

## Test Accounts

| Account | Service | Username | Password | Security weakness |
|---------|---------|----------|----------|--------------------|
| Standard user | FTP / SSH | labuser | labuser | Password equals username |
| Administrator | HTTP Basic Auth | admin | admin | Password equals username |

Credentials were intentionally set to match username values to demonstrate how predictable password patterns reduce brute-force resistance to a trivial level.

---

## Tools Used

| Tool | Version | Purpose |
|------|---------|---------|
| Nmap | 7.98 | Network reconnaissance — host discovery, port scanning, service enumeration |
| Hydra | 9.x | Credential attack simulation — SSH, FTP, HTTP |
| Wireshark | 4.x | Packet capture and traffic analysis |
| tcpdump | 4.x | CLI packet capture on Ubuntu target |
| curl | 8.18.0 | HTTP request generation |
| OpenSSH client | — | SSH session generation for protocol comparison |
| ftp (lftp) | — | FTP session generation for protocol comparison |
