---
title: PKI Requirements for Windows Hello for Business Cert Trust
url: https://msendpointmgr.com/2025/11/24/pki-requirements-for-windows-hello-for-business-cert-trust
date_added: 2026-03-17
phase: Planning and Preparation
tags: windows-hello-for-business, pki, certificate-templates, active-directory, kerberos, ksp, cng, ad-cs, hybrid-identity, smart-card-logon, kdc-authentication, enrollment-agent, tpm, ad-fs, passwordless, port-88, port-389, port-443
images: 1 found — recommend reviewing article for full context
---

## Summary
This MSEndpointMgr article by Anders Ahl covers the PKI certificate template requirements for deploying Windows Hello for Business (WHfB) in certificate trust mode within hybrid Active Directory environments. It details the two certificate templates required — a Kerberos Authentication template for domain controllers and a Smart Card Logon-derived template for WHfB users — with a focus on modernising legacy PKIs to meet current requirements. Key changes include mandating Key Storage Providers (KSP) over legacy CSPs, enforcing SHA-256 and RSA 2048, using enrollment agent-based issuance via AD FS, and applying newer template flags such as the Hello logon key flag.

## Key Learnings
- WHfB certificate trust requires **two certificate templates**: one for domain controllers (Kerberos Authentication-based) and one for WHfB user authentication (Smartcard Logon-based).
- **Domain Controller template** must: use KSP, RSA 2048, SHA-256; include KDC Authentication EKU (OID 1.3.6.1.5.2.3.5); supersede legacy DC templates; be auto-enrolled to all DCs.
- **WHfB user authentication template** must: use KSP, RSA 2048, SHA-256; include Smart Card Logon EKU (OID 1.3.6.1.4.1.311.20.2.2); require 1 authorised signature from a Certificate Request Agent (AD FS); include user UPN in SAN; enable *Renew with same key*.
- **Key Storage Provider (KSP)** is the critical shift from legacy CSPs — it enables CNG-based keys, TPM key storage (Microsoft Platform Crypto Provider), and modern algorithm support. Legacy CSP-based templates do not support TPM-backed keys.
- The **HELLO\_LOGON\_KEY flag** (CT\_PRIVATEKEY\_FLAG value `0x00200000`) must be applied to the WHfB user template via `certutil -dsTemplate`. This is a recent addition not present in any legacy templates.
- **Enrollment agent brokered issuance**: AD FS holds an Enrollment Agent certificate and signs the user's CSR on their behalf. Direct user self-enrollment is not used — this is a pattern unfamiliar to most legacy PKI deployments.
- **CT\_FLAG\_REQUIRE\_SAME\_KEY\_RENEWAL**: Ensures the same TPM-bound key pair is reused on cert renewal, avoiding key churn. Only available in v4 (Windows Server 2012+) templates.
- Legacy PKIs may need CA upgrades (minimum Windows Server 2016 CA), SHA-1 migration to SHA-256, and new template creation from scratch — old templates cannot simply be modified in place for version compatibility.
- CRL Distribution Points and AIA must be HTTP-accessible, not LDAP-only, for hybrid/Entra-joined devices.
- **TPM key attestation** (CT\_FLAG\_ATTEST\_REQUIRED) is optional but recommended as a hardening measure for organisations that want cryptographic proof keys are hardware-protected.

## Tool Usage Examples

### 1. Set the WHfB Hello Logon Key flag on the user certificate template
```cmd
:: Run on a CA admin workstation or directly on the CA
:: Replace "WHfBUserAuth" with your actual template display name
certutil -dsTemplate WHfBUserAuth +CTPRIVATEKEY_FLAG_HELLO_LOGON_KEY
```

### 2. Verify the flag was applied correctly
```cmd
certutil -dsTemplate WHfBUserAuth
:: Look for msPKI-Private-Key-Flag value — confirm bit 0x00200000 is set
```

### 3. Force auto-enrollment on domain controllers via Group Policy (PowerShell)
```powershell
# Run on spendc09.spen.local as spenda (Domain Admin)
# Trigger immediate auto-enrollment on all DCs to pick up the new Kerberos Auth template
Invoke-Command -ComputerName spendc06,spendc07,spendc08,spendc09 `
    -Credential (Get-Credential spen\spenda) `
    -ScriptBlock { certutil -pulse }
```

### 4. Verify domain controller certificate contains KDC Authentication EKU
```powershell
# Run on any DC — check the cert store for the correct EKU
# KDC Authentication OID = 1.3.6.1.5.2.3.5
Invoke-Command -ComputerName spendc09.spen.local `
    -ScriptBlock {
        Get-ChildItem Cert:\LocalMachine\My |
        Where-Object { $_.EnhancedKeyUsageList -match "1.3.6.1.5.2.3.5" } |
        Select-Object Subject, NotAfter, Thumbprint
    }
```

### 5. Check for legacy SHA-1 certificates on DCs (identifies templates to supersede)
```powershell
# Run on Kali — check DCs for weak certs before deploying new templates
foreach ($dc in @("spendc06","spendc07","spendc08","spendc09")) {
    Invoke-Command -ComputerName "$dc.spen.local" -ScriptBlock {
        Get-ChildItem Cert:\LocalMachine\My |
        Where-Object { $_.SignatureAlgorithm.FriendlyName -match "sha1" } |
        Select-Object Subject, Thumbprint, NotAfter
    }
}
```

### 6. Confirm WHfB user certificate issued correctly (check from enrolled workstation)
```powershell
# Run on spenpc10 (192.168.2.10) after WHfB provisioning
# Verify the cert has the correct EKU and UPN in SAN
Get-ChildItem Cert:\CurrentUser\My |
    Where-Object { $_.EnhancedKeyUsageList -match "Smart Card Logon" } |
    Select-Object Subject, Thumbprint, NotAfter |
    Format-List
```

### 7. Enumerate CA templates to identify legacy CSP-based templates (offensive recon)
```powershell
# From Kali or any domain-joined host — use Certify to find misconfigured templates
# Useful for identifying if WHfB templates have been misconfigured (e.g. missing enrollment agent requirement)
./Certify.exe find /vulnerable /domain:spen.local
```

### 8. Check AD CS certificate template flags in AD (offensive enumeration)
```powershell
# Query AD for WHfB template msPKI-Private-Key-Flag value
# Confirms whether HELLO_LOGON_KEY (0x200000) is set
$template = Get-ADObject -Filter { name -eq "WHfBUserAuth" } `
    -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=spen,DC=local" `
    -Properties msPKI-Private-Key-Flag
$template.'msPKI-Private-Key-Flag'
# Expect a value that includes 0x200000 (2097152 decimal) if flag is set
```

## CVEs Referenced
None.

## Notes
- **Offensive relevance**: Misconfigured WHfB certificate templates are a known AD CS attack surface (ESC1–ESC13 family). If the enrollment agent signature requirement is missing or set incorrectly, standard users may be able to self-enrol for the WHfB authentication template, impersonating other users. Always validate with `Certify.exe find /vulnerable` or `certipy find` after template deployment.
- In the lab, AD CS is hosted on the domain controllers (spendc06–spendc09). The spendc09 (FSMO holder) is the most likely primary issuing CA. The WHfB authentication template should be published there.
- The article explicitly discourages Hybrid Entra Join and recommends cloud-native where possible. For a pure on-prem lab like spen.local, full certificate trust is the relevant path.
- The Enrollment Agent certificate for AD FS (if deployed) would need to be issued from the same internal CA — tie this to `spen.service2` or a dedicated service account on the AD FS/IIS tier.
- From a red team perspective, locating the Enrollment Agent certificate private key on the AD FS host is high-value — it can be used to request WHfB user auth certs on behalf of any user in the domain (similar to golden cert attacks via ADCS).
- The `certutil -pulse` command forces a certificate auto-enrollment cycle — useful both for admin testing and as a post-exploitation action to check what templates a compromised host can enrol for.