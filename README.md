# MITRE ATT&CK Detection Rules

A collection of hand-built Sigma detection rules mapped to MITRE ATT&CK techniques, 
with full reasoning documented for each: why the behavior is suspicious, what it looks 
like in logs, and how an analyst should investigate it.

## Why this exists

Most rule repositories are copy-paste collections. This one focuses on depth: 
every rule includes the underlying attacker logic, not just detection syntax.

## Structure

rules/ → Sigma rule (.yml) + explanation (.md) for each technique

## Rules

| Technique | ATT&CK ID | Status |
|---|---|---|
| PowerShell spawning Rundll32 | T1218.011 | ✅ |

## Author

Maheen Hasan --- CEH certified
