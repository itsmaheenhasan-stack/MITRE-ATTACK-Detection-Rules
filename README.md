# MITRE ATT&CK Detection Rules

A collection of hand-built Sigma detection rules mapped to MITRE ATT&CK techniques. Each rule includes an explanation of why the behavior is suspicious, which logs detect it, possible false positives, investigation steps, and validation performed in a Windows 11 lab.

## Why this exists

Most public Sigma repositories focus primarily on detection logic. This project focuses on documenting the reasoning behind each rule, including why the behavior is suspicious, how it can be investigated, and how the rule was validated.

## Structure

rules/ → Sigma rule (.yml) + explanation (.md) for each technique

## Methodology

Each rule documents five things: what happened, why it's suspicious, which logs detect it, known false positives, and investigation steps. The goal of this project is not only to write Sigma rules, but also to document the reasoning an analyst would use when investigating each detection.

## Rules

| Technique | ATT&CK ID | Status | Validated |
|---|---|---|---|
| PowerShell spawning Rundll32 | T1218.011 | ✅ | Fully tested |
| Word spawning PowerShell | T1566.001 | ✅ | Telemetry confirmed |
| Discovery Commands (Non-Interactive Parent) | T1033 / T1082 | ✅ | Fully tested |
| LSASS Memory Access | T1003.001 | ✅ | Telemetry confirmed |

**Validation notes**

- **Fully tested** – The behavior was reproduced in a Windows 11 lab and the Sigma rule matched the generated Sysmon event.
- **Telemetry confirmed** – Sysmon was verified to collect the required event fields, but the full attack scenario was not reproduced. The reason is documented in the corresponding rule explanation.

## Author

Maheen Hasan --- CEH certified
