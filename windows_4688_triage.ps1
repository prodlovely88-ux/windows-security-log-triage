param (
    [int]$MaxEvents = 150,
    [string]$ReportPath = "$env:USERPROFILE\Desktop\soc_4688_triage_report.csv"
)


function Get-SocDecodedCommand {
    param (
        [string]$CommandLine
    )

    $cmdText = "$CommandLine"

    if ($cmdText -notmatch "(?i)-(encodedcommand|enc)\s+([A-Za-z0-9+/=]+)") {
        return ""
    }

    $encodedValue = $Matches[2]

    try {
        $bytes = [Convert]::FromBase64String($encodedValue)
        $decoded = [System.Text.Encoding]::Unicode.GetString($bytes)
        return $decoded
    }
    catch {
        return "DECODE_FAILED"
    }
}


function Get-SocIndicators {
    param (
        [string]$Process,
        [string]$Parent,
        [string]$CommandLine
    )

    $indicators = @()

    $processText = "$Process".ToLower()
    $parentText = "$Parent".ToLower()
    $cmdText = "$CommandLine".ToLower()

    if ($cmdText -match "encodedcommand|-enc") {
        $indicators += "HIGH_RISK_POWERSHELL_ENCODED"
    }

    if ($cmdText -match "windowstyle hidden") {
        $indicators += "HIGH_RISK_HIDDEN_POWERSHELL"
    }

    if ($cmdText -match "executionpolicy bypass") {
        $indicators += "SUSPICIOUS_POWERSHELL_BYPASS"
    }

    if ($cmdText -match "-noprofile") {
        $indicators += "SUSPICIOUS_POWERSHELL_NOPROFILE"
    }

    if (
        $processText -match "cmd.exe" -and
        $cmdText -match "/c" -and
        $cmdText -match "whoami|hostname|ipconfig|systeminfo|nltest|net "
    ) {
        $indicators += "CMD_DISCOVERY_CHAIN"
    }

    if (
        $parentText -match "cmd.exe" -and
        $processText -match "whoami.exe|hostname.exe|ipconfig.exe|systeminfo.exe|nltest.exe|net.exe"
    ) {
        $indicators += "CHILD_DISCOVERY_FROM_CMD"
    }

    if ($processText -match "whoami.exe|hostname.exe|ipconfig.exe|systeminfo.exe|nltest.exe|net.exe") {
        $indicators += "DISCOVERY_COMMAND"
    }

    if (
        $parentText -match "powershell.exe" -and
        $processText -match "cmd.exe"
    ) {
        $indicators += "POWERSHELL_TO_CMD"
    }

    if ($indicators.Count -eq 0) {
        $indicators += "OK_OR_CONTEXT_NEEDED"
    }

    return $indicators
}

function Get-SocSeverity {
    param (
        [string[]]$Indicators
    )

    if ($Indicators -match "HIGH_RISK") {
        return "High"
    }

    if ($Indicators -match "SUSPICIOUS|CMD_DISCOVERY_CHAIN|CHILD_DISCOVERY_FROM_CMD|POWERSHELL_TO_CMD") {
        return "Medium"
    }

    if ($Indicators -contains "DISCOVERY_COMMAND") {
        return "Low"
    }

    return "Info"
}

function Get-SocVerdict {
    param (
        [string[]]$Indicators
    )

    if ($Indicators -match "HIGH_RISK") {
        return "СРОЧНО"
    }

    if ($Indicators -match "SUSPICIOUS|DISCOVERY|POWERSHELL_TO_CMD") {
        return "ПОДОЗРИТЕЛЬНО"
    }

    return "ШУМ"
}

function Get-SocReason {
    param (
        [string[]]$Indicators
    )

    $reasons = @()

    foreach ($indicator in $Indicators) {
        switch ($indicator) {
            "HIGH_RISK_POWERSHELL_ENCODED" {
                $reasons += "PowerShell used encoded command execution"
            }

            "HIGH_RISK_HIDDEN_POWERSHELL" {
                $reasons += "PowerShell was launched with hidden window style"
            }

            "SUSPICIOUS_POWERSHELL_BYPASS" {
                $reasons += "PowerShell attempted to bypass execution policy"
            }

            "SUSPICIOUS_POWERSHELL_NOPROFILE" {
                $reasons += "PowerShell was launched without loading user profile"
            }

            "CMD_DISCOVERY_CHAIN" {
                $reasons += "cmd.exe executed a discovery command through /c"
            }

            "CHILD_DISCOVERY_FROM_CMD" {
                $reasons += "Discovery command was spawned by cmd.exe"
            }

            "POWERSHELL_TO_CMD" {
                $reasons += "PowerShell spawned cmd.exe"
            }

            "DISCOVERY_COMMAND" {
                $reasons += "Common discovery command was executed"
            }

            default {
                $reasons += "No specific suspicious pattern matched"
            }
        }
    }

    return ($reasons -join "; ")
}


function Get-SocTriageNote {
    param (
        [string]$Process,
        [string]$Parent,
        [string]$CommandLine,
        [string]$DecodedCommand,
        [string[]]$Indicators
    )

    $processText = "$Process".ToLower()
    $parentText = "$Parent".ToLower()
    $cmdText = "$CommandLine".ToLower()
    $decodedText = "$DecodedCommand".ToLower()
    $allText = "$Process $Parent $CommandLine $DecodedCommand".ToLower()

    if (
        $cmdText -match "soc_test" -or
        $decodedText -match "soc_test" -or
        $cmdText -match "write-host soc_test" -or
        $decodedText -match "write-host soc_test"
    ) {
    	return "EXPECTED_LAB_TEST_ACTIVITY - generated during SOC training"
    }

    if (
        $cmdText -match "soc-windows-triage" -and
        $cmdText -match "windows_4688_triage.ps1"
    ) {
        return "OWN_TRIAGE_SCRIPT_EXECUTION - expected lab script launch, verify only if unexpected"
    }

    if (
        (
            $allText -match "codesetup-stable" -or
            $allText -match "microsoft vs code" -or
            $allText -match "microsoft.visualstudiocode" -or
            $allText -match "code_x64\.appx"
        ) -and
        (
            $allText -match "appxpackage" -or
            $allText -match "visualstudiocode" -or
            $allText -match "vs code"
        )
    ) {
        return "LIKELY_LEGIT_VSCODE_INSTALLER_OR_UPDATE - verify if VS Code install/update was expected"
    }

    if (
        $parentText -match "\\temp\\" -and
        $processText -match "powershell.exe" -and
        $Indicators -match "HIGH_RISK|SUSPICIOUS"
    ) {
        return "TEMP_PARENT_WITH_SUSPICIOUS_POWERSHELL - review parent file, hash, signature and user activity"
    }

    if (
        $processText -match "powershell.exe" -and
        $Indicators -match "HIGH_RISK"
    ) {
        return "HIGH_RISK_POWERSHELL - investigate immediately"
    }

    if ($Indicators -match "DISCOVERY") {
        return "DISCOVERY_ACTIVITY - correlate with logon events and parent process"
    }

    return "NO_ADDITIONAL_CONTEXT"
}


$events = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4688
} -MaxEvents $MaxEvents

$parsed = foreach ($event in $events) {
    $xml = [xml]$event.ToXml()

    $data = @{}
    foreach ($item in $xml.Event.EventData.Data) {
        $data[$item.Name] = $item.'#text'
    }

    $process = $data['NewProcessName']
    $parent = $data['ParentProcessName']
    $commandLine = $data['CommandLine']
    $decodedCommand = Get-SocDecodedCommand -CommandLine $commandLine

    $indicators = Get-SocIndicators -Process $process -Parent $parent -CommandLine $commandLine
    $severity = Get-SocSeverity -Indicators $indicators
    $verdict = Get-SocVerdict -Indicators $indicators
    $reason = Get-SocReason -Indicators $indicators
    $triageNote = Get-SocTriageNote -Process $process -Parent $parent -CommandLine $commandLine -DecodedCommand $decodedCommand -Indicators $indicators
    [PSCustomObject]@{
        Time        = $event.TimeCreated
        User        = $data['SubjectUserName']
        Parent      = $parent
        Process     = $process
        CommandLine = $commandLine
        DecodedCommand = $decodedCommand
        Indicators  = ($indicators -join ", ")
        Severity    = $severity
        Verdict     = $verdict
        Reason      = $reason
	TriageNote  = $triageNote
    }
}

$suspicious = $parsed |
    Where-Object { $_.Verdict -ne "ШУМ" } |
    Sort-Object Time

Write-Host ""
Write-Host "=== Windows Security Event ID 4688 Triage Report ==="
Write-Host ""

$suspicious | ForEach-Object {
    Write-Host ""
    Write-Host "Time:        $($_.Time)"
    Write-Host "User:        $($_.User)"
    Write-Host "Parent:      $($_.Parent)"
    Write-Host "Process:     $($_.Process)"
    Write-Host "CommandLine: $($_.CommandLine)"

    if ($_.DecodedCommand) {
        Write-Host "DecodedCmd:  $($_.DecodedCommand)"
    }

    Write-Host "Indicators:  $($_.Indicators)"
    Write-Host "Severity:    $($_.Severity)"
    Write-Host "Verdict:     $($_.Verdict)"
    Write-Host "Reason:      $($_.Reason)"
    Write-Host "TriageNote:  $($_.TriageNote)"
    Write-Host "----------------------------------------"
}

$suspicious |
    Export-Csv -Path $ReportPath -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "=== Summary by Severity ==="
$suspicious |
    Group-Object Severity |
    Select-Object Name, Count |
    Sort-Object Name |
    Format-Table -AutoSize

Write-Host ""
Write-Host "=== Summary by Indicators ==="
$suspicious |
    Group-Object Indicators |
    Select-Object Count, Name |
    Sort-Object Count -Descending |
    Format-Table -AutoSize

Write-Host ""
Write-Host "Report saved to: $ReportPath"
