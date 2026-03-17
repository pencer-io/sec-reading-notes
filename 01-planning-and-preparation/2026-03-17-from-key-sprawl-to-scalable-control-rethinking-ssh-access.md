---
title: "From Key Sprawl to Scalable Control: Rethinking SSH Access"
url: https://www.hashicorp.com/en/blog/from-key-sprawl-to-scalable-control-rethinking-ssh-access
date_added: 2026-03-17
phase: Planning and Preparation
tags: ssh, ssh-certificates, credential-management, vault, hashicorp, boundary, key-management, zero-trust, privilege-access, secret-sprawl, ca, ed25519, rsa
---

## Summary
Static SSH keys are a long-standing security and operational liability at scale — they are rarely rotated, often shared, and leave no audit trail, creating serious exposure risk especially with third-party contractors. SSH certificates, signed by a Certificate Authority (CA), offer a significant improvement by introducing expiry, principal-based access control, and centralised management. HashiCorp Vault's SSH secrets engine combined with Boundary's credential injection takes this further, enabling fully ephemeral, short-lived SSH certificates that users never directly handle.

## Key Learnings
- Static SSH keys are inherently problematic at scale: no automatic expiry, no per-user traceability, difficult rotation, and high risk when shared with third parties or contractors
- SSH certificates wrap an existing public key in a CA-signed structure — they don't introduce new encryption but add validity periods, principals (allowed Linux usernames), and centralized trust
- ED25519 is preferred over RSA for SSH certificates: smaller key size (68 chars vs 2048–4096 bits), comparable security to 3000-bit RSA, and faster key generation/signature validation
- Principals in SSH certificates define which Linux usernames a certificate holder can authenticate as on a target — this replaces `authorized_keys` file management
- HashiCorp Vault's SSH secrets engine can issue or sign SSH certificates on-demand, eliminating long-lived static keys
- HashiCorp Boundary uses **credential injection** — the Boundary controller fetches ephemeral credentials from Vault and injects them into the session via a self-managed worker; the end-user never sees the private key
- Two Vault SSH endpoint options:
  - `/issue` — Vault generates *and* signs the key pair
  - `/sign` — Boundary generates the key pair and sends the public key to Vault to sign
- When an SSH session ends, all associated credentials are automatically destroyed — no residual access
- This model provides full auditability: each user gets a unique key pair per session, making tracing trivial

## Tool Usage Examples

### Signing an SSH public key with a CA (manual workflow)
In the lab, a sysadmin might sign a key for access to the Ubuntu file server `spenub24` (192.168.1.24), allowing principals for standard access and read-only:

```bash
ssh-keygen -s /path/to/ca_key \
  -I spenub24-session \
  -n spensa,spenuser1,readonly \
  id_ed25519.pub
```

Flags explained:
- `-s /path/to/ca_key` — Sign using the CA's private key (trusted by target's `sshd_config`)
- `-I spenub24-session` — Human-readable label for this certificate
- `-n spensa,spenuser1,readonly` — Principals allowed: server admin (`spensa`), standard user (`spenuser1`), and a restricted `readonly` account
- `id_ed25519.pub` — The public key to sign; output will be `id_ed25519-cert.pub`

### Configuring sshd on target to trust the CA
On `spenub24` (192.168.1.24), add to `/etc/ssh/sshd_config`:

```bash
TrustedUserCAKeys /etc/ssh/trusted_ca.pub
```

Then restart sshd:
```bash
sudo systemctl restart sshd
```

### SSH connection using the signed certificate (from Kali on tun0)
```bash
ssh -i id_ed25519 -i id_ed25519-cert.pub spensa@192.168.1.24
```

### Vault SSH secrets engine — enable and configure (lab context)
```bash
# Enable the SSH secrets engine
vault secrets enable ssh

# Configure a CA for signing client keys
vault write ssh/config/ca generate_signing_key=true

# Create a role for server access targeting spenub24
vault write ssh/roles/spenub24-role \
  key_type=ca \
  allowed_principals="spensa,spenuser1" \
  default_user="spensa" \
  ttl=5m \
  max_ttl=30m

# Sign a user's public key via Vault
vault write ssh/sign/spenub24-role \
  public_key=@~/.ssh/id_ed25519.pub \
  valid_principals="spensa"
```

## CVEs Referenced
None.

## Notes
- This article is vendor-authored (HashiCorp/IBM) and focuses on promoting Vault + Boundary as the solution — treat the architecture recommendations as sound but be aware of the commercial framing
- The credential injection model is directly relevant to a pentest lab for testing whether Boundary/Vault-protected SSH targets are exploitable via session hijacking, worker compromise, or policy misconfigurations
- In the lab, the Linux servers (`spenub18`, `spenub22`, `spenub24`) would be the natural targets for testing SSH certificate-based access controls and misconfigurations in CA trust configuration
- Key audit question for assessments: check `~/.ssh/authorized_keys` on all lab servers — the presence of unknown or old keys is a direct finding
- The `/sign` vs `/issue` distinction in Vault is worth noting for Boundary-specific pentest scenarios: compromise of the Boundary controller in the `/sign` flow means intercepting key pairs before they reach Vault
