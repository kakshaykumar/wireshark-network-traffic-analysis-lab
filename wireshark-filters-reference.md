# Wireshark Display Filters Reference

Quick reference for all filters used across this lab.

---

## Network Reconnaissance

| Scenario | Filter |
|----------|--------|
| ICMP ping sweep | `icmp` |
| ICMP — Ubuntu only | `icmp and ip.addr == 192.168.110.130` |
| SYN scan — all to target | `tcp and ip.dst == 192.168.110.130` |
| SYN scan — open port sequence | `tcp and ip.addr == 192.168.110.130 and tcp.port == 22` |
| Version detection | `tcp and ip.addr == 192.168.110.130` |
| Aggressive scan — all protocols | `ip.addr == 192.168.110.130` |
| Aggressive scan — HTTP NSE only | `http and ip.addr == 192.168.110.130` |
| Aggressive scan — FTP probe only | `ftp and ip.addr == 192.168.110.130` |

---

## Authentication Attacks

| Scenario | Filter |
|----------|--------|
| SSH brute force | `tcp.port == 22` |
| FTP brute force | `ftp` |
| FTP credential capture | `ftp` |
| HTTP basic auth attack | `http` |
| HTTP requests only | `http.request` |
| HTTP 401 responses | `http.response.code == 401` |
| HTTP 200 responses | `http.response.code == 200` |

---

## Protocol Analysis

| Scenario | Filter |
|----------|--------|
| FTP stream | `ftp` |
| SSH stream | `tcp.port == 22` |
| HTTP traffic | `http` |
| Normal TCP handshake | `tcp.flags.syn == 1` |
| SYN scan handshake | `tcp and ip.addr == 192.168.110.130 and tcp.port == 22` |
| DNS all | `dns` |
| DNS NXDOMAIN only | `dns.flags.rcode == 3` |
| DNS to external resolver | `dns and ip.dst == 8.8.8.8` |

---

## General Purpose

| Filter | Purpose |
|--------|---------|
| `ip.addr == 192.168.110.130` | All traffic involving a specific IP |
| `ip.src == 192.168.110.132` | Traffic from Kali only |
| `tcp.flags.syn == 1 and tcp.flags.ack == 0` | SYN packets only (not SYN-ACK) |
| `tcp.flags.reset == 1` | RST packets only |
| `tcp.window_size_value == 1024` | Nmap SYN probe fingerprint |
| `!arp` | Hide ARP traffic |

---

## Filter Syntax

```
==    equals
!=    not equals
&&    AND
||    OR
!     NOT
```

**Examples:**

```wireshark
# Traffic between two specific IPs
ip.addr == 192.168.110.132 && ip.addr == 192.168.110.130

# HTTP traffic excluding 200 responses
http && http.response.code != 200

# DNS NXDOMAIN from a specific host
dns.flags.rcode == 3 && ip.src == 192.168.91.131

# Nmap probe signature
tcp.flags.syn == 1 && tcp.window_size_value == 1024
```
