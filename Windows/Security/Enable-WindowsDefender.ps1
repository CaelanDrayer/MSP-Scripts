<#
.SYNOPSIS
    Enables Windows Defender. Designed for NinjaOne deployment.
.DESCRIPTION
    1. Clears Group Policy registry overrides that disable Defender
    2. Sets WinDefend service to Automatic and starts it
    3. Enables all core protections via Set-MpPreference
    4. Triggers a signature update
    Exit code 0 = all steps succeeded, 1 = one or more steps failed.
#>

$ErrorActionPreference = 'Stop'
$script:ExitCode = 0
$LogPath = "C:\Windows\Temp\Defender-Enable-$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$script:Colors = @{ PASS = 'Green'; FAIL = 'Red'; WARN = 'Yellow'; INFO = 'Cyan' }

function Log([string]$Level, [string]$Msg) {
    $line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Msg"
    Write-Host $line -ForegroundColor $script:Colors[$Level]
    $line | Out-File -Append -FilePath $LogPath -ErrorAction SilentlyContinue
    if ($Level -eq 'FAIL') { $script:ExitCode = 1 }
}

Log INFO "=== Enable Windows Defender ==="
Log INFO "Host: $env:COMPUTERNAME | OS: $([Environment]::OSVersion.VersionString) | Log: $LogPath"

# -- Step 1: Clear GP registry overrides --

$gpKeys = @(
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
)
$gpValues = @(
    'DisableAntiSpyware', 'DisableRealtimeMonitoring', 'DisableBehaviorMonitoring',
    'DisableIOAVProtection', 'DisableScriptScanning'
)

foreach ($key in $gpKeys) {
    if (-not (Test-Path $key)) { continue }
    foreach ($name in $gpValues) {
        $prop = Get-ItemProperty -Path $key -Name $name -ErrorAction SilentlyContinue
        if ($null -eq $prop) { continue }
        try {
            Remove-ItemProperty -Path $key -Name $name -Force -ErrorAction Stop
            Log WARN "Removed GP override $key\$name (value was $($prop.$name)). Will re-apply on next gpupdate if GP enforces it."
        } catch {
            Log FAIL "Failed to remove GP override $key\$name. Error: $($_.Exception.GetType().Name): $($_.Exception.Message)"
        }
    }
}

# -- Step 2: Enable and start WinDefend service --

$svc = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
if (-not $svc) {
    Log FAIL "WinDefend service not found. Windows Defender may not be installed. Check: Get-WindowsFeature Windows-Defender (Server) or Get-WindowsOptionalFeature -FeatureName Windows-Defender-Default-Definitions (Desktop)."
    Log INFO "=== Aborted. Exit code: $script:ExitCode ==="
    exit $script:ExitCode
}

Log INFO "WinDefend service: Status=$($svc.Status), StartType=$($svc.StartType)"

if ($svc.StartType -ne 'Automatic') {
    try {
        Set-Service -Name WinDefend -StartupType Automatic -ErrorAction Stop
        Log PASS "WinDefend startup type changed to Automatic (was $($svc.StartType))"
    } catch {
        Log FAIL "Could not set WinDefend to Automatic. Error: $($_.Exception.GetType().Name): $($_.Exception.Message). This may require disabling a GP that enforces the start type."
    }
}

if ($svc.Status -ne 'Running') {
    try {
        Start-Service -Name WinDefend -ErrorAction Stop
        Start-Sleep -Seconds 3
        $svc.Refresh()
        if ($svc.Status -eq 'Running') {
            Log PASS "WinDefend service started successfully"
        } else {
            Log FAIL "WinDefend service did not reach Running state after 3 seconds. Current status: $($svc.Status). Check Event Viewer > Applications and Services > Microsoft > Windows > Windows Defender > Operational for details."
        }
    } catch {
        Log FAIL "Failed to start WinDefend service. Error: $($_.Exception.GetType().Name): $($_.Exception.Message). Common causes: Tamper Protection by third-party AV, GP enforcement, or the service is disabled at the driver level."
    }
} else {
    Log PASS "WinDefend service already running"
}

# -- Step 3: Enable protections via Set-MpPreference --

if (-not (Get-Module -ListAvailable -Name Defender -ErrorAction SilentlyContinue)) {
    Log FAIL "Defender PowerShell module not found. Cannot configure protections. Verify Windows Defender is installed: Get-WindowsFeature Windows-Defender (Server) or check Add/Remove Windows Features (Desktop)."
} else {
    try {
        Set-MpPreference `
            -DisableRealtimeMonitoring $false `
            -DisableBehaviorMonitoring $false `
            -DisableBlockAtFirstSeen $false `
            -DisableIOAVProtection $false `
            -DisableScriptScanning $false `
            -DisableArchiveScanning $false `
            -DisableIntrusionPreventionSystem $false `
            -SignatureDisableUpdateOnStartupWithoutEngine $false `
            -MAPSReporting 2 `
            -SubmitSamplesConsent 1 `
            -ErrorAction Stop
        Log PASS "All core protections enabled (RealTime, Behavior, BlockAtFirstSeen, IOAV, ScriptScanning, ArchiveScanning, IPS, MAPS=Advanced)"
    } catch {
        Log FAIL "Set-MpPreference bulk call failed. Error: $($_.Exception.GetType().Name): $($_.Exception.Message). A Group Policy may be overriding these settings. Check: HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
    }

    try {
        Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction Stop
        Log PASS "Network Protection enabled"
    } catch {
        Log WARN "Network Protection failed. Error: $($_.Exception.GetType().Name): $($_.Exception.Message). Requires Windows 10 1709+ or Server 2019+."
    }
}

# -- Step 4: Signature update --

try {
    Update-MpSignature -ErrorAction Stop
    Log PASS "Signature update initiated successfully"
} catch {
    Log WARN "Signature update failed. Error: $($_.Exception.GetType().Name): $($_.Exception.Message). Will retry automatically on next scheduled update cycle."
}

# -- Summary --

if ($script:ExitCode -eq 0) {
    Log INFO "=== All steps passed. Exit code: 0 ==="
} else {
    Log INFO "=== One or more steps failed. Exit code: 1. Review FAIL entries above. ==="
}

exit $script:ExitCode
