<#
.SYNOPSIS
    Enables Windows Defender. Designed for NinjaOne deployment.
.DESCRIPTION
    1. Clears Group Policy and passive-mode registry overrides
    2. Installs Windows Defender feature if missing (Server 2016+)
    3. Sets WinDefend service to Automatic and starts it
    4. Enables all core protections via Set-MpPreference
    5. Triggers a signature update
    Supports Server 2016+ and Windows 10+.
    Server 2012 R2 requires Defender for Endpoint onboarding (not supported by this script).
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

function Abort {
    Log INFO "=== Aborted. Exit code: $script:ExitCode ==="
    exit $script:ExitCode
}

$os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
$isServer = $os.ProductType -ne 1
$osVersion = [Environment]::OSVersion.Version

Log INFO "=== Enable Windows Defender ==="
Log INFO "Host: $env:COMPUTERNAME | OS: $($os.Caption.Trim()) ($osVersion) | Server: $isServer | Log: $LogPath"

# -- Unsupported OS check --

if ($isServer -and $osVersion.Major -eq 6 -and $osVersion.Minor -le 3) {
    Log FAIL "Server 2012 R2 and older not supported. Requires Defender for Endpoint onboarding. See: https://learn.microsoft.com/en-us/defender-endpoint/onboard-server"
    Abort
}

# -- Step 1: Clear registry overrides --

$gpKeys = @(
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
)
$gpValues = @('DisableAntiSpyware', 'DisableRealtimeMonitoring', 'DisableBehaviorMonitoring', 'DisableIOAVProtection', 'DisableScriptScanning')

foreach ($key in $gpKeys) {
    if (-not (Test-Path $key)) { continue }
    foreach ($name in $gpValues) {
        $prop = Get-ItemProperty -Path $key -Name $name -ErrorAction SilentlyContinue
        if ($null -eq $prop) { continue }
        try {
            Remove-ItemProperty -Path $key -Name $name -Force -ErrorAction Stop
            Log WARN "Removed GP override $key\$name (was $($prop.$name)). May re-apply on next gpupdate."
        } catch {
            Log FAIL "Failed to remove $key\$name. $($_.Exception.GetType().Name): $($_.Exception.Message)"
        }
    }
}

# ForceDefenderPassiveMode: Defender stuck in passive mode after third-party AV uninstall
$passiveKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection'
if (Test-Path $passiveKey) {
    $passiveProp = Get-ItemProperty -Path $passiveKey -Name 'ForceDefenderPassiveMode' -ErrorAction SilentlyContinue
    if ($null -ne $passiveProp -and $passiveProp.ForceDefenderPassiveMode -eq 1) {
        try {
            Set-ItemProperty -Path $passiveKey -Name 'ForceDefenderPassiveMode' -Value 0 -ErrorAction Stop
            Log PASS "Cleared ForceDefenderPassiveMode (was 1). Defender will switch to active mode."
        } catch {
            Log WARN "Could not clear ForceDefenderPassiveMode. $($_.Exception.GetType().Name): $($_.Exception.Message)"
        }
    }
}

# -- Step 2: Ensure Windows Defender is installed (Server only) --

$svc = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
if (-not $svc) {
    if (-not $isServer) {
        Log FAIL "WinDefend service not found on desktop OS. May have been removed by third-party AV."
        Abort
    }

    if (-not (Get-Command Install-WindowsFeature -ErrorAction SilentlyContinue)) {
        Log FAIL "Install-WindowsFeature cmdlet not available."
        Abort
    }

    $feat = Get-WindowsFeature -Name Windows-Defender -ErrorAction SilentlyContinue
    if (-not $feat) {
        Log FAIL "Windows-Defender feature not found. Run 'Get-WindowsFeature *Defend*' to check."
        Abort
    }

    if ($feat.Installed) {
        Log WARN "Windows-Defender feature installed but WinDefend service missing. Reboot required."
        exit 1
    }

    try {
        Log INFO "Installing Windows-Defender feature (may take several minutes)."
        $result = Install-WindowsFeature -Name Windows-Defender -ErrorAction Stop
        if ($result.Success) {
            Log PASS "Windows-Defender feature installed."
            if ($result.RestartNeeded -eq 'Yes') {
                Log WARN "REBOOT REQUIRED. Re-run this script after reboot."
                exit 1
            }
        } else {
            Log FAIL "Install-WindowsFeature returned Success=False. Exit reason: $($result.ExitCode)."
            Abort
        }
    } catch {
        Log FAIL "Failed to install Windows-Defender. $($_.Exception.GetType().Name): $($_.Exception.Message)"
        Abort
    }

    Start-Sleep -Seconds 5
    $svc = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
    if (-not $svc) {
        Log FAIL "WinDefend service still not found after install. Reboot may be required."
        Abort
    }
    Log PASS "WinDefend service available after feature installation."
}

# -- Step 3: Enable and start WinDefend service --

Log INFO "WinDefend: Status=$($svc.Status), StartType=$($svc.StartType)"

if ($svc.StartType -ne 'Automatic') {
    try {
        Set-Service -Name WinDefend -StartupType Automatic -ErrorAction Stop
        Log PASS "WinDefend startup set to Automatic (was $($svc.StartType))"
    } catch {
        Log FAIL "Could not set WinDefend to Automatic. $($_.Exception.GetType().Name): $($_.Exception.Message)"
    }
}

if ($svc.Status -ne 'Running') {
    try {
        Start-Service -Name WinDefend -ErrorAction Stop
        Start-Sleep -Seconds 3
        $svc.Refresh()
        if ($svc.Status -eq 'Running') {
            Log PASS "WinDefend service started"
        } else {
            Log FAIL "WinDefend did not start (status: $($svc.Status)). Check Event Viewer > Windows Defender > Operational."
        }
    } catch {
        Log FAIL "Failed to start WinDefend. $($_.Exception.GetType().Name): $($_.Exception.Message)"
    }
} else {
    Log PASS "WinDefend already running"
}

# -- Step 4: Enable protections --

if (-not (Get-Module -ListAvailable -Name Defender -ErrorAction SilentlyContinue)) {
    Log FAIL "Defender PowerShell module not found."
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
            -MAPSReporting 2 `
            -SubmitSamplesConsent 1 `
            -ErrorAction Stop
        Log PASS "Core protections enabled (RealTime, Behavior, IOAV, ScriptScan, ArchiveScan, IPS, MAPS)"
    } catch {
        Log FAIL "Set-MpPreference failed. $($_.Exception.GetType().Name): $($_.Exception.Message). Check GP: HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
    }

    try {
        Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction Stop
        Log PASS "Network Protection enabled"
    } catch {
        Log WARN "Network Protection not available. Requires Server 2019+ or Win10 1709+."
    }
}

# -- Step 5: Signature update --

try {
    Update-MpSignature -ErrorAction Stop
    Log PASS "Signature update initiated"
} catch {
    Log WARN "Signature update failed. Will retry on next scheduled cycle."
}

# -- Summary --

if ($script:ExitCode -eq 0) {
    Log INFO "=== All steps passed. Exit code: 0 ==="
} else {
    Log INFO "=== One or more steps failed. Exit code: 1 ==="
}
exit $script:ExitCode
