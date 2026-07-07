# Discovery Commands via Non-Interactive Parent

## What happened
whoami, net user, or systeminfo was executed with cmd.exe or powershell.exe as 
the parent process, and explorer.exe was not the grandparent.

## Why it's suspicious
These commands are common admin tools on their own, so alone they're weak signal. 
But when spawned by cmd or PowerShell instead of directly by a human (explorer.exe), 
it suggests an automated script or attacker is running situational awareness commands 
right after gaining a foothold, checking who they are, what privileges they have, 
and what the system looks like before deciding next steps.

## Which logs detect it
Sysmon Event ID 1 (Process Creation), fields: ParentImage, Image

## False positives
IT admin scripts and automation tools legitimately run these commands via 
cmd or PowerShell. This rule is best used as a supporting signal, not a 
standalone high-confidence alert.

## Limitation
A single rule firing once is weak evidence. Real detection value comes from 
seeing multiple discovery commands fire in rapid sequence from the same parent, 
which this rule alone cannot express. A future version should correlate multiple 
events within a short time window.

## Investigation steps
1. Check the parent process's CommandLine for how it was triggered
2. Check what ran immediately before and after, other discovery or network activity
3. Check if this is a known admin script or scheduled task
