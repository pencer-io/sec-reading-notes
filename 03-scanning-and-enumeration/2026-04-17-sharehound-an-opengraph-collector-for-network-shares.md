---
title: "ShareHound: An OpenGraph Collector for Network Shares"
url: https://specterops.io/blog/2025/10/30/sharehound-an-opengraph-collector-for-network-shares/
date_added: 2026-04-17
phase: scanning-and-enumeration
tags: bloodhound, opengraph, smb, network-shares, active-directory, enumeration, cypher, shareql, lateral-movement, ransomware, post-exploitation, port-445
images: 7 found (screenshots: 5, diagrams: 2) — recommend reviewing article for full context
---

## Disclaimer
This is an automated AI generated summary, it's accuracy has not been checked. Read the full article contained
in the url above. Never copy/paste code without first reviewing to ensure you understand what it does.

## Summary
ShareHound is an OpenGraph collector for BloodHound CE and BloodHound Enterprise that crawls all network shares
in a domain and maps their permissions as graph edges. It uses multithreading with per-host throttling and a
custom domain-specific language called ShareQL to control exploration depth and filter shares by rule. The
resulting JSON output is ingested into BloodHound, enabling attack path analysis over SMB share permissions.

## Key Learnings
- ShareHound discovers all computers via LDAP (`dNSHostName`), resolves them via DNS, then crawls each share
  using BFS, generating BloodHound-compatible OpenGraph data
- Uses a **thread-per-share** model with per-host concurrency limits to prevent server overload; more efficient
  than thread-per-host for domains with many shares
- **ShareQL** is a purpose-built DSL (firewall-style rule evaluation) for filtering share crawls — rules are
  evaluated sequentially and stop on first match; a VSCode syntax-highlighting extension is available
- Share permissions are modelled as typed edges: `CanWriteDacl`, `CanWriteOwner`, `CanDsWriteProperty`,
  `CanDsWriteExtendedProperties`, `CanDelete`, `CanReadControl`, etc.
- **Full Control** in ShareHound is represented by the intersection of 13 separate edge types (the "Full
  Control Onion" graph pattern)
- Key offensive use cases: finding writable shares for ransomware staging, finding low-privileged read access
  to sensitive files (e.g. VMDK files of domain controllers stored in forgotten shares)
- For time-sensitive assessments, limiting exploration depth to 1 or 2 is recommended to keep runtime
  manageable
- ShareQL rulesets can be generated using LLMs by providing the grammar URL and a natural-language prompt

## Tool Usage Examples

**Install ShareHound:**
```bash
pip install sharehound
```

**Basic collection against spen.local DC with rule files:**
```bash
sharehound -ai 192.168.0.9 -au "spenuser1" -ap "Password123!" -ns 192.168.0.9 \
  -rf "rules/skip_common_shares.shareql" -rf "rules/max_depth_2.shareql"
```
Output: a JSON file ready for ingestion into BloodHound CE/Enterprise.

**Find principals with Write access to any share (BloodHound Cypher):**
```cypher
MATCH x=(p)-[r:CanWriteDacl|CanWriteOwner|CanDsWriteProperty|CanDsWriteExtendedProperties]->(s:NetworkShareSMB)
RETURN x
```

**Find principals with Full Control on any share:**
```cypher
MATCH (p:Principal)-[r]->(s:NetworkShareSMB)
WHERE (p)-[:CanDelete]->(s)
  AND (p)-[:CanDsControlAccess]->(s)
  AND (p)-[:CanDsCreateChild]->(s)
  AND (p)-[:CanDsDeleteChild]->(s)
  AND (p)-[:CanDsDeleteTree]->(s)
  AND (p)-[:CanDsListContents]->(s)
  AND (p)-[:CanDsListObject]->(s)
  AND (p)-[:CanDsReadProperty]->(s)
  AND (p)-[:CanDsWriteExtendedProperties]->(s)
  AND (p)-[:CanDsWriteProperty]->(s)
  AND (p)-[:CanReadControl]->(s)
  AND (p)-[:CanWriteDacl]->(s)
  AND (p)-[:CanWriteOwner]->(s)
RETURN p,r,s
```

**Hunt for VMDK files in shares accessible to spenuser1 (high-value target: DC disk images):**
```cypher
MATCH p=(h:NetworkShareHost)-[:HasNetworkShare]->(s:NetworkShareSMB)-[:Contains*0..]->(f:File)
WHERE toLower(f.extension) = toLower(".vmdk")
RETURN p
```
In spen.local this would be particularly impactful if a VMDK of spendc09 were recoverable — it would
contain the NTDS.dit and allow offline credential extraction.

**Find files by name (e.g. hunting for credential files):**
```cypher
MATCH p=(h:NetworkShareHost)-[:HasNetworkShare]->(s:NetworkShareSMB)-[:Contains*0..]->(f:File)
WHERE toLower(f.name) = toLower("unattend.xml")
RETURN p
```

**Example ShareQL ruleset to skip common shares and limit depth:**
```
# skip_common_shares.shareql
deny share.name == "IPC$"
deny share.name == "ADMIN$"
deny share.name == "C$"
allow *
```

**LLM prompt to generate ShareQL rules:**
```
Read the following grammar: https://raw.githubusercontent.com/p0dalirius/shareql/refs/heads/main/shareql/grammar/grammar.txt
You will create ShareQL rule sets based on what I ask you each time, and you will respond in a markdown
code block with only the ShareQL rule set.
---
I want to explore only shares with backup in their names but not the other ones, and maximum depth 2
```

## CVEs Referenced
None.

## Notes
- Phase filed as **scanning-and-enumeration** due to primary function being share discovery and permission
  mapping; however the findings directly support post-exploitation (lateral movement, ransomware staging)
- Tool is Python-based and installable via `pip install sharehound`; source at https://github.com/p0dalirius/sharehound
- Author (Remi GASCOU / p0dalirius) is also author of Coercer, LDAPmonitor, FindUncommonShares, and smbclient-ng
- The VMDK scenario described in the article is realistic for spen.local — worth checking `spensmb2` and
  `spensmb31` for any forgotten VM disk images, especially given the older `spensmb2` (Server 2008) which may
  have inherited legacy share structures
- ShareQL VSCode extension: https://github.com/p0dalirius/shareql-vscode-ext
- All edge/node type names are defined in `sharehound/kinds.py` for writing custom Cypher queries
