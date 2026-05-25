# HTTP Authentication Attack Analysis

## Overview

A brute-force credential attack was executed against an HTTP Basic Authentication-protected web endpoint on the target host. HTTP Basic Authentication transmits credentials as Base64-encoded strings in the `Authorization` request header. Base64 is an encoding scheme — not encryption — meaning any observer with access to the network traffic can recover plaintext credentials with a single decode operation. This scenario demonstrates both the attack pattern and the fundamental security limitation of HTTP Basic Authentication over unencrypted HTTP.

**Capture file:** [`http-auth-credential-attack.pcapng`](../pcap-files/authentication-attacks/http-auth-credential-attack.pcapng)

---

## Environment

| Property | Value |
|----------|-------|
| Source | 192.168.110.132 (Kali Linux) |
| Target | 192.168.110.130 (Ubuntu — Apache httpd 2.4.66, port 80) |
| Interface captured | Ubuntu ens37 (defender perspective) |
| Capture perspective | Inbound traffic at target |

---

## Commands Used

```bash
# HTTP Basic Auth brute force — GET method
# Wordlist: wordlist-credentials.txt (12 entries)
hydra -l admin -P simulated-credential-wordlist.txt http-get://192.168.110.130 -V
```

**Wordlist used:** [`simulated-credential-wordlist.txt`](simulated-credential-wordlist.txt)

---

## Wireshark Filter

```
http
```

---

## Analysis

### Authorization Headers — Decoded

Every HTTP GET request in the capture contains an `Authorization` header with a Base64-encoded credential string. The following table documents all attempts and their decoded values:

| Base64 Value | Decoded Credential | HTTP Response |
|-------------|-------------------|---------------|
| `YWRtaW46YWRtaW4=` | admin:admin | **200 OK** |
| `YWRtaW46cGFzc3dvcmQ=` | admin:password | 401 Unauthorized |
| `YWRtaW46MTIzNDU2` | admin:123456 | 401 Unauthorized |
| `YWRtaW46d2VsY29tZQ==` | admin:welcome | 401 Unauthorized |
| `YWRtaW46bGV0bWVpbg==` | admin:letmein | 401 Unauthorized |
| `YWRtaW46cXdlcnR5` | admin:qwerty | 401 Unauthorized |
| `YWRtaW46bGFicGFzczEyMw==` | admin:labpass123 | 401 Unauthorized |
| `YWRtaW46bGFidXNlcg==` | admin:labuser | 401 Unauthorized |
| `YWRtaW46dGVzdDEyMw==` | admin:test123 | 401 Unauthorized |
| `YWRtaW46cGFzc3dvcmQxMjM=` | admin:password123 | 401 Unauthorized |
| `YWRtaW46YWRtaW5wYXNzMTIz` | admin:adminpass123 | 401 Unauthorized |
| `YWRtaW46YWRtaW4xMjM` | admin:admin123 | 401 Unauthorized |


The credential `admin:admin` — the first entry in the wordlist — returned HTTP 200 OK on the initial attempt. Wireshark automatically decodes the Base64 value and displays `Credentials: admin:admin` in the packet details panel without requiring any manual decoding.

### Decoding Base64 Manually

```bash
echo "YWRtaW46YWRtaW4=" | base64 -d
# Output: admin:admin
```

A single terminal command recovers the plaintext credential from any captured Authorization header. This applies equally to all failed attempts — every tested password is recoverable from the capture.

### Tool Fingerprint — Hydra Identified via User-Agent

```
User-Agent: Mozilla/4.0 (Hydra)
```

Hydra explicitly includes its name in the HTTP User-Agent header of every request. This string is present in all 11 GET requests in the capture. A WAF or HTTP log monitoring rule can identify and block this traffic based on the User-Agent value alone, independent of any IP-based rate limiting.

### Response Code Pattern — Brute-Force Signature

```
HTTP/1.1 401 Unauthorized   ← failed attempt
HTTP/1.1 401 Unauthorized   ← failed attempt
...
HTTP/1.1 200 OK             ← correct credential found
```

Multiple 401 responses from the same destination to a single source IP followed by a 200 OK is the HTTP brute-force signature. Two 200 OK responses appear in the capture — Hydra made two connections with the confirmed credential upon finding it.

---

## Evidence

**Figure 1 — HTTP brute-force: Authorization header decoded to admin:admin by Wireshark. Hydra User-Agent visible in packet details.**

![HTTP basic auth decoded credentials](screenshots/http-basic-auth-decoded-credentials.png)

**Figure 2 — Base64 decode: terminal proof that Authorization header encoding is trivially reversible**

![HTTP Base64 decode credential proof](screenshots/http-base64-decode-credential-proof.png)

---

## Key Findings

- **Base64 is encoding, not encryption** — credentials are recoverable in one command: `echo "<value>" | base64 -d`
- **All 11 tested credentials recoverable** from the capture without specialised tools
- **Hydra fingerprinted** by `User-Agent: Mozilla/4.0 (Hydra)` — present in every request
- **Wireshark auto-decodes** — `Credentials: admin:admin` displayed automatically in packet details
- **Successful credential: `admin:admin`** — password equals username; matched on the first wordlist attempt
- **Two 200 OK responses** — Hydra opened dual connections once the correct credential was confirmed

---

## MITRE ATT&CK

| ID | Technique | Tactic |
|----|-----------|--------|
| T1110.001 | Brute Force: Password Guessing | Credential Access |
| T1040 | Network Sniffing | Credential Access |

---

## Detection Recommendations

- **Deploy HTTPS** — TLS encrypts the entire HTTP session including request headers, preventing credential capture regardless of authentication method; this is the primary control
- **Replace Basic Authentication** — move to session-based, token-based, or OAuth2 authentication; Basic Auth was not designed for internet-facing systems
- **Rate limit 401 responses** — configure `mod_evasive` or Fail2ban for Apache: block source IPs generating more than 5 consecutive 401 responses within 30 seconds
- **WAF rule** — block requests with `User-Agent` matching `*Hydra*`; this tool self-identifies in every request
- **Suppress the server version header** — `ServerTokens Prod` in Apache reduces the information returned in 401 and 200 responses
- **Credential policy** — `admin:admin` is the most commonly attempted username/password pair in HTTP brute-force campaigns; enforce that privileged account passwords cannot match usernames
