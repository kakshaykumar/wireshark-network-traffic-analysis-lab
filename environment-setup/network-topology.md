# Lab Setup and Network Topology

## Virtual Machines

### Kali Linux (Attacker)
| Property | Value |
|----------|-------|
| IP (lab network) | 192.168.110.132 |
| Interface | ens37 — Host-only VMnet |
| Second interface | ens33 — NAT (internet access) |
| Role | Attacker — Nmap, Hydra, Wireshark |

### Ubuntu 22.04 Server (Target)
| Property | Value |
|----------|-------|
| IP (lab network) | 192.168.110.130 |
| Interface | ens37 — Host-only VMnet |
| Second interface | ens33 — NAT — 192.168.91.131 (used for DNS analysis) |
| Role | Target — vsftpd, OpenSSH, Apache |

---

## Services on Ubuntu

| Service | Port | Version |
|---------|------|---------|
| FTP | 21/tcp | vsftpd 3.0.5 |
| SSH | 22/tcp | OpenSSH 10.2p1 |
| HTTP | 80/tcp | Apache httpd 2.4.66 |

---

## Network Topology

```
                    [Windows Host Laptop]
                            │
           ─────────────────────────────────
           │                               │
     [VMnet1 Host-only]              [VMnet8 NAT]
     192.168.110.0/24               192.168.91.0/24
           │                               │
   ┌───────┴───────┐               ┌───────┴───────┐
   │  Kali Linux   │               │  Ubuntu ens33 │
   │  ens37        │               │ 192.168.91.131│
   │ .110.132      │               │ (DNS chapter) │
   └───────┬───────┘               └───────────────┘
           │
   ┌───────┴───────┐
   │ Ubuntu Server │
   │  ens37        │
   │ .110.130      │
   │ FTP·SSH·HTTP  │
   └───────────────┘

Gateway: 192.168.110.1
DHCP:    192.168.110.254
```

---

## Dual-Interface Design

Both VMs have two network interfaces:
- **ens37 (Host-only):** Isolated lab network — all attack and defence traffic
- **ens33 (NAT):** Internet access — used only for DNS analysis to generate real DNS queries against live domains

All attack traffic is isolated from the internet. The NAT interface is only activated for the DNS analysis scenario.

---

## Capture Strategy

| Topic | Capture machine | Interface | Perspective |
|-------|----------------|-----------|-------------|
| Network Reconnaissance | Kali | ens37 | Attacker — outbound probes + responses |
| Authentication Attacks | Ubuntu | ens37 | Defender — inbound attacks arriving at server |
| Protocol Analysis (FTP/SSH/HTTP/TCP) | Ubuntu | ens37 | Defender — protocol comparison |
| Protocol Analysis (DNS) | Ubuntu | ens33 | Internet-facing — real DNS queries |

Capturing from Ubuntu's interface in Authentication Attacks and Protocol Analysis simulates a SOC analyst monitoring a server via a network tap or SPAN port.

---

## Test Accounts

| Account | Service | Username | Password | Security issue |
|---------|---------|----------|----------|----------------|
| FTP user | vsftpd | labuser | labuser | Password = username |
| HTTP admin | Apache Basic Auth | admin | admin | Password = username |

Both accounts use weak credentials intentionally to demonstrate how quickly predictable password patterns are cracked.
