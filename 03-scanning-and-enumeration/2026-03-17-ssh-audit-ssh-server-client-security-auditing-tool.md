---
title: ssh-audit - SSH Server & Client Security Auditing Tool
url: https://github.com/jtesta/ssh-audit
date_added: 2026-03-17
phase: Scanning and Enumeration
tags: ssh, auditing, cryptography, key-exchange, hardening, openssh, cve-2002-20001, cve-2023-48795, terrapin, diffie-hellman, quantum, port-22
---

## Summary
ssh-audit is an actively maintained Python tool for auditing the security configuration of SSH servers and clients. It analyses banners, key exchange algorithms, encryption ciphers, MACs, and compression settings, flagging weak, obsolete, or unsafe primitives. The tool supports policy-based scanning to enforce hardened configurations, and includes a web front-end at ssh-audit.com. It is the maintained successor to the original arthepsy/ssh-audit (v1.x).

## Key Learnings
- Audits both SSH **server** and **client** configurations — client auditing is done by having the tool spin up a listener on port 2222
- Flags algorithms as: unsafe, weak, legacy, or removed — and provides version-specific recommendations (append/remove)
- Supports **policy scanning** to test adherence to hardening guides (e.g., CIS, platform-specific); policies can be built-in or custom
- Includes a **DHEat DoS test** (`--dheat`) implementing CVE-2002-20001 (CPU exhaustion via repeated DH group exchange requests)
- Detects the **Terrapin vulnerability** (CVE-2023-48795) — a message prefix truncation attack affecting CBC ciphers and ChaCha20-Poly1305
- Issues warnings for key exchanges lacking **post-quantum protections** (relevant to Harvest Now, Decrypt Later attacks)
- Built-in hardening guides available via `--get-hardening-guide` for common platforms (Ubuntu, Debian, OpenSSH versions, etc.)
- Available as PyPI package, Docker image, Snap package, and Windows executable
- Returns exit code `0` only when all algorithms pass — useful for automation and CI/CD pipeline integration

## Tool Usage Examples

```bash
# Standard server audit
ssh-audit <hostname>

# Audit against multiple targets from a file
ssh-audit -T servers.txt

# Client audit (starts listener on port 2222)
ssh-audit -c
# Connect with: ssh -p 2222 anything@localhost

# JSON output for programmatic use
ssh-audit -j <hostname>

# Run DHEat DoS test (CVE-2002-20001) with 10 concurrent sockets
ssh-audit --dheat=10 <hostname>

# DHEat with specific key exchange and small packet lengths
ssh-audit --dheat=10:diffie-hellman-group-exchange-sha256:4 <hostname>

# DH Group Exchange modulus size test
ssh-audit -g 2000:3072:5000 <hostname>

# List available built-in hardening guides
ssh-audit --list-hardening-guides

# Get hardening guide for a specific platform
ssh-audit --get-hardening-guide <platform>

# Policy audit against a server
ssh-audit -P "Built-In Policy Name" <hostname>

# Create a custom policy from a target server
ssh-audit -M custom_policy.txt <hostname>

# Look up an algorithm in the internal database
ssh-audit --lookup diffie-hellman-group14-sha1
```

## CVEs Referenced
- **CVE-2002-20001** — DHEat: CPU exhaustion DoS via excessive Diffie-Hellman Group Exchange requests
- **CVE-2023-48795** — Terrapin: SSH message prefix truncation attack affecting ChaCha20-Poly1305 and CBC ciphers

## Notes
- Phase assigned as **Scanning and Enumeration** — ssh-audit is a non-exploitation enumeration tool used to profile SSH service security posture
- The tool is excellent for both offensive (identifying weak configs to target) and defensive (hardening validation) use cases
- 3072-bit DH moduli are the current recommended minimum (equivalent to 128-bit symmetric security); note the tool updated from a previous 4096-bit expectation
- The web UI at https://www.ssh-audit.com is handy for quick checks without local install
- Be aware the Windows executable may be flagged by Windows Defender as a false positive
- Harvest Now, Decrypt Later warnings are a useful flag when assessing environments with long-lived sensitive data