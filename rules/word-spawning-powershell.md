# Microsoft Word Spawning PowerShell

## What happened
A Microsoft Word process (winword.exe) launched powershell.exe as a child process.

## Why it's suspicious
Word is a narrow-purpose application, its only job is opening and editing documents. 
Under normal circumstances, it has no legitimate reason to spawn PowerShell. This pattern is the signature 
of macro-based phishing: a victim opens a malicious document, enables macros, and 
the embedded VBA code shells out to PowerShell to download or execute the real 
payload. Because Word has no normal workflow that touches PowerShell, this detection 
carries very low noise, unlike detections built around general-purpose tools like 
PowerShell or cmd, which admins use constantly for legitimate work.

## Which logs detect it
Sysmon Event ID 1 (Process Creation), fields: ParentImage, Image

## False positives
Rare. Some enterprise macro-based automation tools exist but are uncommon. 
If seen in an environment with known legitimate macro workflows, cross-check 
against an approved script inventory before treating as benign.

## Investigation steps
1. Check the CommandLine of the PowerShell process, look for encoded (-EncodedCommand) 
   or obfuscated arguments, a strong sign of malicious intent
2. Identify the source document, file path, filename, where it came from (email 
   attachment, download, USB)
3. Check what PowerShell did next, network connections (likely payload download), 
   file writes, or further process spawns
4. Check if the user recalls enabling macros, correlate with email logs if available

## Validation

I verified that Sysmon was successfully logging Microsoft Word process creation events (Event ID 1).

To validate the required telemetry, I opened Microsoft Word, created and saved a test document, and confirmed that Sysmon recorded the following fields:

- Image: `WINWORD.EXE`
- ParentImage: `explorer.exe`

I did not intentionally generate a `winword.exe → powershell.exe` parent-child relationship because it typically requires Office automation or malicious macros, which were outside the scope of this defensive project.

This validation confirmed that the required telemetry for the detection rule is available and that Sysmon correctly records Word process creation events.
