# DNS Traffic Investigation

## Overview

DNS traffic was captured and analysed across multiple query types to document normal resolution behaviour and contrast it with anomalous patterns relevant to security monitoring. DNS is one of the most important protocols to baseline and monitor in any network environment — it is widely used by malware for command-and-control communication, data exfiltration, and detection evasion. Understanding what normal DNS looks like on the wire is a prerequisite for identifying what is abnormal.

**Capture file:** [`dns-query-nxdomain-analysis.pcapng`](../pcap-files/protocol-analysis/dns-query-nxdomain-analysis.pcapng)

---

## Environment

| Property | Value |
|----------|-------|
| Source | Ubuntu 22.04 — 192.168.91.131 (NAT interface) |
| DNS resolver | 192.168.91.2 (VMware NAT gateway) |
| External resolver | 8.8.8.8 (Google Public DNS) |
| Interface captured | Ubuntu ens33 (NAT interface — internet-facing) |

---

## Commands Used

```bash
# Standard A record resolution
nslookup google.com
nslookup github.com

# Non-existent domain — generates NXDOMAIN response
nslookup nonexistent-fake-domain-xyz123.com

# ALL record query — tests resolver restrictions
dig google.com ANY

# Direct query to external resolver — bypasses internal DNS
dig @8.8.8.8 google.com
```

---

## Wireshark Filter

```
dns
```

---

## Analysis

### Normal A Record Resolution — google.com

A standard DNS A record query and response:

```
Query:    Standard query A google.com
Response: A 64.233.180.113
          A 64.233.180.101
          A 64.233.180.100
          A 64.233.180.139
          A 64.233.180.102
          A 64.233.180.138
```

Six A records returned — Google uses multiple IPs across its infrastructure for load distribution and redundancy. Each record carries a TTL value defining how long the resolver should cache the result before issuing a fresh query. This is normal, expected DNS behaviour.

### NXDOMAIN Response — Non-Existent Domain

A query for a domain that does not exist:

```
Query:    Standard query A nonexistent-fake-domain-xyz123.com
Response: No such name (DNS response code 3)
          SOA a.gtld-servers.net
```

DNS response code 3 is NXDOMAIN — the authoritative server confirmed the queried domain does not exist. The SOA (Start of Authority) record in the response identifies the authoritative name server for the TLD.

**Security significance of NXDOMAIN:**
A single NXDOMAIN is unremarkable — users mistype domains regularly. The security signal emerges from volume and pattern. Malware using Domain Generation Algorithms (DGA) generates pseudo-random domain names programmatically and queries them in sequence, searching for the one registered by the attacker as the active command-and-control endpoint. Each failed query produces an NXDOMAIN response. A host generating 20 or more NXDOMAIN responses per minute is a high-confidence indicator of DGA activity.

### Direct Query to External Resolver — 8.8.8.8

```
Source:      192.168.91.131
Destination: 8.8.8.8         ← external resolver, not the internal gateway
Port:        UDP 53
Query:       A google.com
Response:    A 172.253.115.139 (different IP set than internal resolver returned)
```

DNS traffic sent directly to `8.8.8.8` bypasses the internal resolver entirely. In a corporate environment, this is a detection-evasion technique — malware may query external resolvers to avoid enterprise DNS filtering, logging, or sinkholing. A firewall rule blocking outbound port 53 to any destination other than the authorised internal resolver prevents this. Any DNS traffic reaching external IPs on port 53 should be treated as anomalous.

### Background NTP Traffic

The capture opens with Ubuntu's NTP service automatically resolving pool time servers:

```
Standard query A 1.ntp.ubuntu.com
Standard query A 2.ntp.ubuntu.com
Standard query A 3.ntp.ubuntu.com
Standard query A 4.ntp.ubuntu.com
```

These queries are OS-generated, not user-initiated, and are normal background activity on any Ubuntu host. Establishing this baseline is important — including `*.ntp.ubuntu.com` in a DNS allowlist prevents these legitimate queries from generating false positive alerts in threshold-based NXDOMAIN or query-volume rules.

### ANY Record Query — RFC 8482 Restriction

```
dig google.com ANY
```

The response returned only minimal data rather than all record types. Modern authoritative DNS servers restrict ANY queries per RFC 8482 to prevent DNS amplification attacks where attackers use large ANY responses to amplify DDoS traffic. This is expected behaviour, not a network issue. A small ANY response from a major domain is confirmation of RFC 8482 compliance on the queried server.

---

## Evidence

**Figure 1 — DNS capture: NXDOMAIN response for non-existent domain. Query/response pair visible alongside normal google.com and github.com resolutions.**

![DNS NXDOMAIN nonexistent domain response](screenshots/dns-nxdomain-nonexistent-domain-response.png)

---

## Key Findings

- **Normal A record resolution:** Multiple IPs returned for major domains — consistent with load balancing infrastructure
- **NXDOMAIN (response code 3):** Authoritative confirmation the domain does not exist; high-volume NXDOMAIN from one host is a DGA/C2 indicator
- **Direct DNS to 8.8.8.8:** Bypasses internal resolver and monitoring — detection-evasion technique used by malware
- **NTP background queries:** OS-generated DNS activity; must be baselined to avoid false positives in threshold monitoring rules
- **ANY query restriction:** RFC 8482 compliance confirmed — expected modern DNS behaviour

---

## MITRE ATT&CK

| ID | Technique | Tactic |
|----|-----------|--------|
| T1071.004 | Application Layer Protocol: DNS | Command and Control |
| T1568 | Dynamic Resolution | Command and Control |

---

## Detection Recommendations

- **NXDOMAIN threshold:** Alert on more than 20 NXDOMAIN responses from a single internal host within 60 seconds — high-confidence DGA/C2 indicator
- **Block external DNS:** Implement a firewall rule preventing outbound UDP/TCP port 53 to any destination other than the authorised internal resolver; any external DNS traffic is anomalous
- **DNS logging:** Enable full DNS query logging at the resolver level; DNS logs are among the most valuable sources for threat hunting and incident investigation
- **Allowlist NTP:** Add `*.ntp.ubuntu.com` and `*.ntp.org` to a monitoring allowlist to prevent legitimate OS time synchronisation from triggering volume-based alerts
- **Monitor DNS over HTTPS (DoH):** Modern operating systems and browsers can route DNS queries over HTTPS to resolvers at `8.8.8.8:443` or `1.1.1.1:443`, bypassing traditional DNS monitoring entirely; monitor for outbound HTTPS to known DoH resolver IPs as a separate detection category
