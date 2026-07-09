# LSASS Memory Access via Suspicious Process

## What happened
A process outside the trusted system paths accessed lsass.exe's memory with 
GrantedAccess rights consistent with reading process memory (dump behavior).

## Why it's suspicious
LSASS holds cached credentials from Credential Manager, SAM, and CNG Key Isolation, 
three credential stores in one process. Legitimate access is almost entirely limited 
to Windows system processes and antivirus. Any outside process reading LSASS with 
these specific access flags is very likely attempting to extract credentials for 
lateral movement, either via known tools like procdump, or built-in abuse paths 
like comsvcs.dll or Task Manager's dump feature.

## Which logs detect it
Sysmon Event ID 10 (ProcessAccess), fields: TargetImage, SourceImage, GrantedAccess

## False positives
Windows Defender and other AV engines legitimately scan LSASS memory. The filter 
block excludes known system paths, but this is a weak defense, an attacker can 
spoof a process path string. A stronger version should also check process signing 
and hash reputation, not just path.

## Investigation steps
1. Check SourceImage, what process actually requested access, and where it's 
   located on disk
2. Check if the source process is signed and by whom
3. Check for a dump file being written to disk shortly after, common next step
4. Check parent process of the source, how did it get launched

## Validation

Sysmon Event ID 10 (ProcessAccess) logging was successfully enabled and verified on the test system.

A benign ProcessAccess event was observed, confirming that Sysmon was collecting Event ID 10 telemetry. However, a matching LSASS access event was not intentionally generated because modern Windows security features may prevent or restrict user-mode access to LSASS on fully patched systems.

The Sigma rule was therefore validated by confirming that the required telemetry (ProcessAccess events containing TargetImage, SourceImage, and GrantedAccess) was available and that unrelated ProcessAccess events did not match the detection logic.
