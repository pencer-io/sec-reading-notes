---
title: "Provisioning and Managing Certificates in the Web PKI"
url: https://www.ncsc.gov.uk/guidance/provisioning-and-managing-certificates-in-the-web-pki
date_added: 2026-04-13
phase: planning-and-preparation
tags: pki, tls, certificates, certificate-authority, x509, caa, ocsp, crl, acme, certificate-transparency, wildcard-certificates, domain-validation, post-quantum, key-management, ncsc, port-443, port-80
images: 1 found — recommend reviewing article for full context
---

## Disclaimer
This is an automated AI generated summary, it's accuracy has not been checked. Read the full article contained
in the url above. Never copy/paste code without first reviewing to ensure you understand what it does.

## Summary
NCSC guidance for architects, engineers and service owners on securely provisioning and managing TLS certificates
within the Web PKI. It covers the three principal threats to certificate integrity — attacker-obtained certs,
mis-managed/expired certs, and undetected compromise — and provides practical recommendations for each. The
guidance emphasises automation, minimal key exposure, CAA records, and Certificate Transparency monitoring.

## Key Learnings
- **Three core threats** to Web PKI: (1) attacker obtains a cert for your domain, (2) weak or expired cert
  breaks user connectivity, (3) either goes undetected prolonging damage
- **Private key protection** — never back up Web PKI private keys; use cloud KMS where possible; minimise
  human access; key export options (BYOK/HYOK) should be avoided
- **Certificate revocation is unreliable** — CRLs are impractical at scale; OCSP has privacy issues and isn't
  mandatory; OCSP stapling is poorly supported. Revoke anyway, but don't rely on it propagating to all clients
- **Scope certs to infrastructure** — a device should only hold keys for the domains it serves; use SANs to
  list specific domains on a single cert where infrastructure is shared
- **Avoid wildcard certificates** unless genuinely necessary (e.g. dynamic per-customer subdomains) — a
  compromised wildcard covers all subdomains including attacker-created ones
- **CAA DNS records** restrict which CAs can issue certs for a domain; use `issuewild ";"` to ban wildcard
  issuance globally; override on specific subdomains if needed; prefer CAs that help configure CAA correctly
- **Automate certificate renewal** using ACME or equivalent; renew when 25–33% validity remains; generate a
  new private key on every renewal cycle; consider ACME Renewal Information (ARI / RFC 9773) if supported
- **Shorter validity periods incoming** — CA/Browser Forum ballot reduces max validity to 47 days by 2029;
  plan for this now; automation is non-negotiable at that frequency
- **DV certificates are sufficient** for all use cases — browsers treat DV, OV and EV equivalently; OV/EV
  require manual validation steps and cannot be fully automated
- **Certificate Transparency (CT) logs** — CAs should publish to CT logs; monitor them for unexpected issuance
  against your domains as an early-warning mechanism for compromise
- **Post-quantum transition** — classical Web PKI algorithms are vulnerable to CRQCs; NCSC has separate
  migration timeline guidance; plan accordingly
- **Modern cryptography** — follow CA/Browser Forum algorithm requirements; refer to NCSC TLS guidance for
  recommended algorithm/parameter sets

## Tool Usage Examples

### Check CAA records for spen.local domain
```bash
# Query CAA DNS record for the spen.local domain via the primary DC
dig CAA spen.local @192.168.0.9

# Query CAA for a specific subdomain (e.g. a web service)
dig CAA speniis102.spen.local @192.168.0.9
```

### Set a CAA record to restrict certificate issuance (DNS zone file example)
```bash
# Allow only Let's Encrypt to issue certs for spen.local
# Add to DNS zone on spendc09.spen.local
spen.local. CAA 0 issue "letsencrypt.org"

# Prohibit all wildcard certificate issuance globally
spen.local. CAA 0 issuewild ";"
```

### Enumerate certificates for a domain via Certificate Transparency (crt.sh)
```bash
# Check publicly logged certs for spen.local equivalent (useful against external targets)
curl -s "https://crt.sh/?q=%.spendev.onmicrosoft.com&output=json" | jq '.[].name_value' | sort -u

# Or use certspotter-style enumeration from Kali
curl -s "https://crt.sh/?q=%.spen.local&output=json" | python3 -m json.tool
```

### Check TLS certificate details on a target web server
```bash
# Check cert expiry and SAN fields on the IIS servers
openssl s_client -connect 192.168.1.102:443 </dev/null 2>/dev/null | openssl x509 -noout -text | grep -E "Subject:|DNS:|Not After"

# Verify cert chain on speniis100
openssl s_client -connect 192.168.1.100:443 -showcerts </dev/null
```

### ACME certificate renewal check (Certbot example on Linux target)
```bash
# Check cert renewal status on spenub18 (Ubuntu 18.04 / Apache)
ssh spensa@192.168.1.18 "sudo certbot certificates"

# Dry-run renewal to test ACME flow
ssh spensa@192.168.1.18 "sudo certbot renew --dry-run"
```

## CVEs Referenced
None.

## Notes
- This is a **blue team / defensive** guidance document from NCSC, published December 2025. Relevant to
  pen testing engagements for reporting and remediation advice sections — particularly where wildcard certs,
  missing CAA records, or expired/weak certs are findings
- The NCSC explicitly recommends **DV certs only** — if an org is paying for EV certs they're wasting money
  and adding manual renewal friction with no security benefit
- CT log monitoring (e.g. crt.sh, Censys, Facebook CT Monitor) is a useful **recon technique** as well as
  a defensive control — subdomain enumeration via CT logs is a standard OSINT step
- The incoming **47-day max validity** (2029) will break any org relying on manual certificate renewal
- Scoped to **server authentication only** — the NCSC has separate guidance for private/internal PKI
  (relevant to AD CS environments like spen.local)
