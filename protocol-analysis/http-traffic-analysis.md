# HTTP Traffic Analysis

## Overview

HTTP traffic was generated across four distinct request types to document how the protocol exposes request content, authentication credentials, server information, and response behaviour to any observer on the network path. Each request type produces a different HTTP response code, and each code carries specific significance for security monitoring. All content — including authorization headers, server version strings, and HTML response bodies — is transmitted without encryption.

**Capture file:** [`http-traffic-protocol-analysis.pcapng`](../pcap-files/protocol-analysis/http-traffic-protocol-analysis.pcapng)

---

## Environment

| Property | Value |
|----------|-------|
| Source | 192.168.110.132 (Kali Linux) |
| Target | 192.168.110.130 (Ubuntu — Apache httpd 2.4.66, port 80) |
| Interface captured | Ubuntu ens37 (defender perspective) |

---

## Commands Used

```bash
# Request 1 — No credentials (unauthenticated access attempt)
curl http://192.168.110.130/

# Request 2 — Non-existent path (path enumeration)
curl http://192.168.110.130/nonexistent-page

# Request 3 — Incorrect credentials
curl -u admin:wrongpassword http://192.168.110.130/

# Request 4 — Correct credentials
curl -u admin:admin http://192.168.110.130/
```

---

## Wireshark Filter

```
http
```

---

## Analysis

### Four Requests, Four Response Codes

The capture contains 8 HTTP packets — 4 requests and 4 responses — each pair separated by a deliberate pause to keep the transactions clearly distinguishable:

| Packet | Request | Response |
|--------|---------|---------|
| 4 | `GET /` (no auth) | `401 Unauthorized` |
| 14 | `GET /nonexistent-page` (no auth) | `401 Unauthorized` |
| 24 | `GET /` (wrong credentials) | `401 Unauthorized` |
| 34 | `GET /` (correct credentials) | `200 OK` |

### Request 1 — Unauthenticated Access → 401

A bare GET request with no Authorization header returns a 401 response along with a `WWW-Authenticate` header:

```
WWW-Authenticate: Basic realm="Restricted Area"
```

This response confirms authentication is required, identifies Basic as the authentication method, and names the protected realm — providing reconnaissance value before any credential is submitted.

### Request 2 — Non-Existent Path → 401 (Not 404)

A request to `/nonexistent-page` returns 401 rather than 404. Apache evaluates Basic Authentication before resolving the requested path — meaning the server requires authentication before confirming whether a resource exists. From a monitoring perspective, 401 responses to varied paths from a single source indicate directory enumeration: an attacker probing for accessible resources.

### Request 3 — Incorrect Credentials → 401

The Authorization header contains `admin:wrongpassword` encoded as Base64:

```
Authorization: Basic YWRtaW46d3JvbmdwYXNzd29yZA==
```

Decoded: `admin:wrongpassword`. Every failed authentication attempt is visible in the capture with the exact credential tested. There is no ambiguity about what was tried.

### Request 4 — Correct Credentials → 200 OK

The Authorization header contains `admin:admin` encoded as Base64:

```
Authorization: Basic YWRtaW46YWRtaW4=
```

Decoded: `admin:admin`. The 200 OK response includes full server metadata in plaintext:

```
HTTP/1.1 200 OK
Server: Apache/2.4.66 (Ubuntu)
Date: Sun, 24 May 2026 18:17:28 GMT
Content-Type: text/html
Content-Length: 10672
```

The server version (`Apache/2.4.66`), OS distribution (`Ubuntu`), response timestamp, and the complete 10,672-byte HTML response body are all transmitted without encryption.

### Response Codes as Security Monitoring Signals

| Code | Meaning | Monitoring significance |
|------|---------|------------------------|
| 401 | Unauthorized | Failed auth attempt — track source IP and frequency |
| 404 | Not Found | Path probing — repeated 404s from one source indicate enumeration |
| 200 | OK | Successful access — verify the source and path are expected |
| 405 | Method Not Allowed | Unusual HTTP method (OPTIONS, PUT, PROPFIND) — scanner activity |

---

## Evidence

**Figure 1 — HTTP 200 OK with Apache server header disclosed in response**

*Server: Apache/2.4.66 (Ubuntu) highlighted. Full response visible including date, content-type, and HTML body.*

![HTTP server version disclosure](screenshots/http-server-version-disclosure.png)

**Figure 2 — HTTP GET with Authorization header decoded to admin:admin**

*Authorization: Basic YWRtaW46YWRtaW40= → Credentials: admin:admin displayed by Wireshark automatically.*

![HTTP cleartext credential transmission](screenshots/http-cleartext-credential-transmission.png)

---

## Key Findings

- **Server version in every response** — `Apache/2.4.66 (Ubuntu)` cannot be suppressed without explicit configuration; returned on 200, 401, and error responses
- **Every failed credential is visible** — 401 responses document which credentials were attempted and rejected
- **Non-existent paths return 401 not 404** — server reveals authentication requirement before confirming path existence
- **Wireshark auto-decodes Base64** — `Credentials: admin:admin` displayed in packet details without manual decoding
- **Full HTML response body in plaintext** — all served content visible to any observer on the network path

---

## MITRE ATT&CK

| ID | Technique | Tactic |
|----|-----------|--------|
| T1071.001 | Application Layer Protocol: Web Protocols | Command and Control |
| T1040 | Network Sniffing | Credential Access |

---

## Detection Recommendations

- **Deploy HTTPS** — TLS encrypts all HTTP content including headers, Authorization values, and response bodies; this is the primary control
- **Suppress server version** — `ServerTokens Prod` in Apache returns `Server: Apache` rather than `Server: Apache/2.4.66 (Ubuntu)`
- **Alert on 401 patterns** — multiple 401 responses from a single source IP within a short window is a brute-force indicator regardless of the tool used
- **Replace Basic Authentication** — session-based or token-based authentication does not transmit credentials in the Authorization header on every request
