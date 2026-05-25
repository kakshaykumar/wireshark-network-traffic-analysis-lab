# Investigation Findings

Consolidated security findings across all three analysis topics, ranked by impact. Each finding references the scenario where the evidence was captured.

---

## Critical

### Credential transmission in plaintext over FTP

**Scenarios:** [FTP Credential Attack Analysis](authentication-attacks/ftp-credential-attack-analysis.md) · [FTP Session Credential Exposure](authentication-attacks/ftp-session-credential-exposure.md) · [Plaintext vs Encrypted Protocol Analysis](protocol-analysis/plaintext-vs-encrypted-protocol-analysis.md)

Every FTP username, password, command, and server response is transmitted as readable text. `PASS labuser` is visible directly in the Wireshark packet list Info column — no filtering, decryption, or analysis tools required. A passive observer on any network segment between client and server captures complete credentials automatically from any user's normal session.

**Confirmed credential:** `labuser:labuser` · **Attempts to crack:** 9 out of 12-entry wordlist

**Remediation:** Disable vsftpd. Configure SFTP via the OpenSSH subsystem already running on port 22: `Subsystem sftp /usr/lib/openssh/sftp-server`

---

### HTTP Basic Authentication exposes credentials through trivial Base64 decoding

**Scenarios:** [HTTP Authentication Attack Analysis](authentication-attacks/http-auth-attack-analysis.md) · [HTTP Traffic Analysis](protocol-analysis/http-traffic-analysis.md)

HTTP Basic Authentication encodes credentials as Base64 in the `Authorization` header. Base64 is not encryption — any captured HTTP request containing an Authorization header yields plaintext credentials in one command: `echo "<value>" | base64 -d`. Wireshark decodes it automatically in the packet details panel.

**Confirmed credential:** `admin:admin` · **Attempts to crack:** 1 (first wordlist entry)

**Remediation:** Deploy HTTPS. Replace Basic Authentication with session-based or token-based authentication.

---

### Weak credentials — password equals username on both accounts

**Scenarios:** [FTP Credential Attack Analysis](authentication-attacks/ftp-credential-attack-analysis.md) · [HTTP Authentication Attack Analysis](authentication-attacks/http-auth-attack-analysis.md)

Both test accounts used passwords identical to the account username (`labuser:labuser`, `admin:admin`). These patterns are the first entries in any credential wordlist. Combined with cleartext protocols, they represent the minimum possible resistance to a credential attack.

**Remediation:** Enforce password complexity policy. Password must not match username. Audit all existing accounts for this pattern.

---

## Major

### Exact software versions exposed via service banners

**Scenario:** [Service Version Enumeration](network-reconnaissance/service-version-enumeration.md)

All three services returned version strings before any authentication was required:

| Service | Banner |
|---------|--------|
| FTP | `220 (vsFTPd 3.0.5)` |
| SSH | `SSH-2.0-OpenSSH_10.2p1 Ubuntu-2ubuntu3.2` |
| HTTP | `Server: Apache/2.4.66 (Ubuntu)` |

Each string is directly searchable in NVD and Exploit-DB. OS distribution (Ubuntu) and kernel type (Linux) were inferred from the SSH banner without running a dedicated OS scan.

**Remediation:** Suppress banners: `ServerTokens Prod` (Apache), `ftpd_banner=` (vsftpd), `DebianBanner no` (SSH).

---

### Nmap fingerprinted by TCP window size across all scan types

**Scenario:** [Port Scan Investigation](network-reconnaissance/port-scan-investigation.md)

Every Nmap SYN probe in the capture carries `Win=1024` — not a standard OS TCP window value. Legitimate connections from the same machine use `Win=64240`. This crafted value is present in all 1,000 probes and allows IDS systems to fingerprint Nmap specifically without signature databases.

**Detection:** IDS rule — TCP SYN with `window_size == 1024` from external source.

---

### Hydra fingerprinted in both SSH and HTTP traffic

**Scenarios:** [SSH Credential Attack Analysis](authentication-attacks/ssh-credential-attack-analysis.md) · [HTTP Authentication Attack Analysis](authentication-attacks/http-auth-attack-analysis.md)

Hydra embeds its identity in two different protocol headers:

| Protocol | Fingerprint | Location |
|----------|-------------|---------|
| SSH | `SSH-2.0-libssh_0.11.3` | SSH Client Protocol banner |
| HTTP | `Mozilla/4.0 (Hydra)` | HTTP User-Agent header |

Both strings are present in every connection and require no content inspection to identify — they appear in unencrypted protocol metadata.

**Detection:** IDS alert on `libssh` in SSH client banner. WAF rule blocking `User-Agent: *Hydra*`.

---

### Aggressive scan NSE probed /.git/HEAD automatically

**Scenario:** [Active Reconnaissance Investigation](network-reconnaissance/active-recon-investigation.md)

Nmap's default NSE scripts sent `GET /.git/HEAD` to the HTTP service without any additional configuration. This checks whether a Git repository is accessible from the web root — a common misconfiguration in environments where application code is deployed with `.git/` directories intact. A positive response would expose commit history, internal file paths, and any credentials stored in version-controlled configuration files.

**Remediation:**
```apache
<DirectoryMatch "\.git">
    Require all denied
</DirectoryMatch>
```

---

### FTP anonymous login automatically tested by NSE

**Scenario:** [Active Reconnaissance Investigation](network-reconnaissance/active-recon-investigation.md)

The aggressive scan sent `USER anonymous` to the FTP service as part of the default NSE FTP scripts — active credential testing without any additional flags. This behaviour is built into the `-A` scan and executes against any open FTP port by default.

**Remediation:** Ensure `anonymous_enable=NO` in `/etc/vsftpd.conf`. Verify with: `grep anonymous_enable /etc/vsftpd.conf`.

---

## Informational

### OS fingerprinting from ICMP TTL without dedicated OS scan

**Scenario:** [Host Discovery Analysis](network-reconnaissance/host-discovery-analysis.md)

TTL values in ICMP Echo Reply packets confirmed OS type for two hosts: Ubuntu returned TTL 64 (Linux default), the VMware gateway returned TTL 128 (Windows default). No dedicated OS detection scan was required.

**Note:** TTL values can be modified through OS configuration or normalised at the firewall. This is a heuristic, not definitive identification.

---

### SSH brute force detectable by pattern without credential visibility

**Scenario:** [SSH Credential Attack Analysis](authentication-attacks/ssh-credential-attack-analysis.md)

SSH encryption is effective — no authentication content is visible in the capture. However, five complete SSH connection cycles from the same source IP within seconds is the behavioural fingerprint. Detection relies on connection rate analysis, not packet content inspection.

---

### NXDOMAIN response identified — DGA/C2 detection reference

**Scenario:** [DNS Traffic Investigation](protocol-analysis/dns-traffic-investigation.md)

A single NXDOMAIN response was captured for a non-existent domain query. This scenario documents the individual pattern — a single NXDOMAIN is not an indicator. The detection threshold is volume: 20 or more NXDOMAIN responses per minute from a single internal host is a high-confidence indicator of Domain Generation Algorithm activity or malware C2 beaconing.

---

### Direct DNS query to external resolver detected

**Scenario:** [DNS Traffic Investigation](protocol-analysis/dns-traffic-investigation.md)

A DNS query was sent directly to `8.8.8.8` (Google Public DNS) rather than the local resolver. In a monitored environment this bypasses internal DNS filtering and logging. Outbound UDP/TCP port 53 to any destination other than the authorised internal resolver should be blocked at the firewall.

---

## Remediation Priority Summary

| Priority | Action | Finding addressed |
|----------|--------|------------------|
| Critical | Disable FTP — configure SFTP | Plaintext credential transmission |
| Critical | Deploy HTTPS on port 80 | HTTP credential exposure |
| Critical | Enforce password complexity policy | Weak credentials |
| High | Suppress service version banners | Version disclosure |
| High | SSH key authentication (`PasswordAuthentication no`) | SSH brute force |
| High | Fail2ban for SSH and Apache | Brute force rate limiting |
| High | Block outbound port 53 to non-authorised resolvers | External DNS bypass |
| Medium | IDS rules for Nmap (Win=1024) and Hydra fingerprints | Tool fingerprinting |
| Medium | Protect `.git/` from web access | NSE Git probe |
| Medium | SIEM threshold for NXDOMAIN volume | DGA/C2 detection |**Fix:** Firewall rule blocking outbound UDP/TCP port 53 to any destination except authorised resolvers

---

## Informational

### OS fingerprinting via ICMP TTL
TTL 64 = Linux, TTL 128 = Windows — identifiable from ping responses without a dedicated OS scan.

### SSH brute force detectable without credential visibility
5 rapid connections from same source within seconds — behavioural pattern is unmistakable even though SSH encryption is effective.

### NXDOMAIN pattern identified for DGA detection
Single NXDOMAIN is normal. High-volume NXDOMAIN from one host = DGA malware indicator.

---

## Attack Path Reconstruction

Using only information captured in this lab:

1. **Reconnaissance:** 3 live hosts, 3 open services, exact software versions, web paths — from two Nmap scans
2. **Credential access:** FTP cracked in 9 attempts, HTTP in 1 attempt — both from a 12-entry wordlist
3. **Post-access intelligence from FTP session:** home directory `/home/labuser`, OS type, filesystem structure, supported protocols

Complete path from initial scan to active access: one Nmap scan (30s) + one Hydra run (5s). The entire attack surface was exposed by the absence of three controls: encryption (FTP/HTTP), password policy, and brute force protection.

---

## Priority Control Recommendations

| Priority | Control | Findings addressed |
|----------|---------|-------------------|
| Critical | Disable FTP; configure SFTP | Finding 1, 3 |
| Critical | Deploy HTTPS | Finding 2, 3 |
| Critical | Password complexity policy | Finding 3 |
| High | Suppress version banners | Finding 4 |
| High | SSH key auth; disable password auth | Finding 6 |
| High | Fail2ban for SSH and HTTP | Finding 6 |
| High | Block outbound DNS to unauthorised resolvers | Finding 8 |
| Medium | IDS rules for Nmap and Hydra fingerprints | Findings 5, 7 |
| Medium | Remove .git from webroot | Finding 7 |
| Medium | SIEM rule: NXDOMAIN flood detection | Finding 10 |
