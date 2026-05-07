\# Windows Security Log Triage Case: Suspicious PowerShell Execution



\## Summary



This case demonstrates basic SOC triage of Windows Security Event ID 4688, focused on suspicious process creation and command-line analysis.



During the investigation, several process creation events were reviewed, including normal user activity, discovery commands, and a suspicious PowerShell execution using bypass-related flags.



\## Environment



\- OS: Windows

\- Log source: Windows Security Logs

\- Event ID: 4688

\- Tool: PowerShell triage script

\- Project: windows-security-log-triage



\## Detection Focus



The triage focused on the following indicators:



\- PowerShell execution

\- ExecutionPolicy Bypass

\- NoProfile usage

\- Discovery commands

\- Suspicious parent-child process chains

\- Command-line arguments



\## Test Events



\### Normal Activity



Example:



```powershell

notepad.exe



Verdict:



NOISE



Reason:



Normal user application execution without suspicious command-line arguments.

Discovery Activity



Example:



cmd.exe /c whoami

cmd.exe /c hostname



Verdict:



SUSPICIOUS



Reason:



Discovery commands can be used by attackers to identify the current user and host after initial access.

Suspicious PowerShell Activity



Example:



powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Host SOC\_CASE\_TEST"



Verdict:



SUSPICIOUS



Reason:



PowerShell was executed with bypass-related flags. This behavior is commonly associated with script execution attempts that avoid default restrictions.

Triage Logic



The script parses Windows Security Event ID 4688 and extracts:



Time

User

Parent process

Process name

Command line

Indicators

Severity

Verdict

Reason

Triage note



The suspicious-only mode helps reduce noise and focus on events that require analyst attention.



Analyst Notes



The observed PowerShell command is classified as suspicious because it uses -NoProfile and -ExecutionPolicy Bypass.



In a real environment, the next investigation steps would include:



Check the parent process

Identify the user context

Review surrounding logon events

Search for network connections around the same timestamp

Check file creation events

Correlate with Sysmon logs if available

Determine whether the activity was authorized

Conclusion



This case shows how Windows Security Event ID 4688 can be used for basic endpoint triage.



The PowerShell triage script helps identify suspicious command-line patterns and provides a structured output that can be used by a SOC analyst during investigation.

