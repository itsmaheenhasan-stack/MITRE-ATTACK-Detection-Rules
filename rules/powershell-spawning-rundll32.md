# PowerShell Spawning Rundll32

## What happened
A PowerShell process launched rundll32.exe as a child process.

## Why it's suspicious
Rundll32 is normally launched by explorer.exe or svchost.exe, not PowerShell. 
Attackers abuse this parent-child relationship because rundll32 is Microsoft-signed 
and often trusted by security tools, letting malicious code execute under a 
legitimate-looking process.

## Which logs detect it
Sysmon Event ID 1 (Process Creation), fields: ParentImage, Image

## False positives
Some legitimate admin scripts or software installers may trigger this. 
Recommend checking CommandLine arguments to rule out known-benign scripts.

## Investigation steps
1. Check the CommandLine of the rundll32 process, what DLL and function was called
2. Check the parent PowerShell process's CommandLine, was it obfuscated or encoded
3. Check what rundll32 did next, network connections, file writes

## Validation

I tested this rule on Windows 11 Pro using Sysmon v15.21.

To generate the event, I opened PowerShell and ran:

Start-Process rundll32.exe

This created a Sysmon Event ID 1 (Process Creation).

The recorded event contained:

- Image: C:\Windows\System32\rundll32.exe
- ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

The event matched the rule because the child process was rundll32.exe and the parent process was powershell.exe.
