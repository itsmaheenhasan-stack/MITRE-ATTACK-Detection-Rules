# LSASS Memory Access via Suspicious Process

## What happened

A process accessed `lsass.exe` with GrantedAccess rights commonly associated with reading another process's memory. The rule excludes some common Windows system paths to reduce expected administrative activity.

## Why it's suspicious

LSASS stores sensitive authentication data such as cached credentials, NTLM hashes, Kerberos tickets, and other security secrets. Legitimate access is usually limited to Windows system components and security software. If an unexpected process reads LSASS memory using these access rights, it may indicate an attempt to dump credentials for privilege escalation or lateral movement.

## Which logs detect it

Sysmon Event ID 10 (ProcessAccess)

Fields used:

- TargetImage
- SourceImage
- GrantedAccess

## False positives

Windows Defender, enterprise EDR products, backup software, and other security tools may legitimately access LSASS. This rule reduces some expected activity by filtering common Windows system paths, but this is not a perfect approach because attackers can imitate trusted locations. A stronger detection would also verify process signatures, hashes, or reputation.

## Investigation steps

1. Check which process accessed LSASS (`SourceImage`).
2. Verify whether the process is digitally signed and whether its location is expected.
3. Look for a memory dump file created shortly afterward.
4. Investigate the parent process to understand how the accessing process was launched.
5. Review nearby events for suspicious process creation, network activity, or additional credential access attempts.

## Validation

I enabled Sysmon ProcessAccess logging (Event ID 10) and confirmed that my system was generating the telemetry required for this rule.

To verify this, I generated a benign ProcessAccess event and confirmed that Sysmon recorded the fields used by the detection, including `TargetImage`, `SourceImage`, and `GrantedAccess`.

I did not intentionally generate an LSASS memory access event because modern Windows 11 security features can restrict user-mode access to LSASS on fully patched systems. Instead, I verified that the required telemetry was available and confirmed that unrelated ProcessAccess events did **not** satisfy this rule's detection logic.

This validation confirmed that the Sigma rule is built on the correct Sysmon event and required fields, even though a real credential-dumping scenario was not reproduced in the test environment.
