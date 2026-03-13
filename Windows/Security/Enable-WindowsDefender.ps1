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

$os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
$isServer = $os.ProductType -ne 1
$osVersion = [Environment]::OSVersion.Version

Log INFO "=== Enable Windows Defender ==="
Log INFO "Host: $env:COMPUTERNAME | OS: $($os.Caption) ($osVersion) | Server: $isServer | Log: $LogPath"

# -- Check: Server 2012 R2 is not supported --

if ($isServer -and $osVersion.Major -eq 6 -and $osVersion.Minor -le 3) {
    Log FAIL "Server 2012 R2 and older are not supported. Windows Defender on Server 2012 R2 requires Microsoft Defender for Endpoint onboarding (modern unified solution). See: https://learn.microsoft.com/en-us/defender-endpoint/onboard-server"
    Log INFO "=== Aborted. Exit code: $script:ExitCode ==="
    exit $script:ExitCode
}

# -- Step 1: Clear registry overrides --

# GP overrides that disable Defender protections
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

# ForceDefenderPassiveMode: if a third-party AV was uninstalled, Defender may be stuck in passive mode
$passiveKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection'
if (Test-Path $passiveKey) {
    $passiveProp = Get-ItemProperty -Path $passiveKey -Name 'ForceDefenderPassiveMode' -ErrorAction SilentlyContinue
    if ($null -ne $passiveProp -and $passiveProp.ForceDefenderPassiveMode -eq 1) {
        try {
            Set-ItemProperty -Path $passiveKey -Name 'ForceDefenderPassiveMode' -Value 0 -ErrorAction Stop
            Log PASS "Cleared ForceDefenderPassiveMode (was 1, set to 0). Defender will switch to active mode."
        } catch {
            Log WARN "Could not clear ForceDefenderPassiveMode. Error: $($_.Exception.GetType().Name): $($_.Exception.Message). Defender may remain in passive mode."
        }
    }
}

# -- Step 2: Ensure Windows Defender is installed (Server only) --

$svc = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
if (-not $svc) {
    if ($isServer) {
        $installCmd = Get-Command Install-WindowsFeature -ErrorAction SilentlyContinue
        if (-not $installCmd) {
            Log FAIL "Install-WindowsFeature cmdlet not available. Cannot install Defender feature."
            Log INFO "=== Aborted. Exit code: $script:ExitCode ==="
            exit $script:ExitCode
        }

        # Check if feature exists before attempting install
        $feat = Get-WindowsFeature -Name Windows-Defender -ErrorAction SilentlyContinue
        if (-not $feat) {
            Log FAIL "Windows-Defender feature not found. This OS version may not support Defender. Run 'Get-WindowsFeature *Defend*' to check available features."
            Log INFO "=== Aborted. Exit code: $script:ExitCode ==="
            exit $script:ExitCode
        }

        if ($feat.Installed) {
            Log WARN "Windows-Defender feature is installed but WinDefend service is missing. A reboot may be required."
            Log INFO "=== Aborted. Exit code: 1 ==="
            exit 1
        }

        try {
            Log INFO "Installing Windows-Defender feature (this may take several minutes)."
            $result = Install-WindowsFeature -Name Windows-Defender -ErrorAction Stop
            if ($result.Success) {
                Log PASS "Windows-Defender feature installed."
                if ($result.RestartNeeded -eq 'Yes') {
                    Log WARN "REBOOT REQUIRED. Defender will not function until the server is restarted. Re-run this script after reboot."
                    Log INFO "=== Reboot required. Exit code: 1 ==="
                    exit 1
                }
            } else {
                Log FAIL "Install-WindowsFeature returned Success=False. Exit reason: $($result.ExitCode)."
                Log INFO "=== Aborted. Exit code: $script:ExitCode ==="
                exit $script:ExitCode
            }
        } catch {
            Log FAIL "Failed to install Windows-Defender feature. Error: $($_.Exception.GetType().Name): $($_.Exception.Message)"
            Log INFO "=== Aborted. Exit code: $script:ExitCode ==="
            exit $script:ExitCode
        }

        # Re-check for the service after installation
        Start-Sleep -Seconds 5
        $svc = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
        if (-not $svc) {
            Log FAIL "WinDefend service still not found after feature installation. A reboot may be required."
            Log INFO "=== Aborted. Exit code: $script:ExitCode ==="
            exit $script:ExitCode
        }
        Log PASS "WinDefend service now available after feature installation."
    } else {
        Log FAIL "WinDefend service not found on desktop OS. Defender may have been removed by third-party antivirus or system modification."
        Log INFO "=== Aborted. Exit code: $script:ExitCode ==="
        exit $script:ExitCode
    }
}

# -- Step 3: Enable and start WinDefend service --

Log INFO "WinDefend service: Status=$($svc.Status), StartType=$($svc.StartType)"

if ($svc.StartType -ne 'Automatic') {
    try {
        Set-Service -Name WinDefend -StartupType Automatic -ErrorAction Stop
        Log PASS "WinDefend startup type changed to Automatic (was $($svc.StartType))"
    } catch {
        Log FAIL "Could not set WinDefend to Automatic. Error: $($_.Exception.GetType().Name): $($_.Exception.Message). A GP may enforce the start type."
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
            Log FAIL "WinDefend did not reach Running state (status: $($svc.Status)). Check Event Viewer > Applications and Services > Microsoft > Windows > Windows Defender > Operational."
        }
    } catch {
        Log FAIL "Failed to start WinDefend. Error: $($_.Exception.GetType().Name): $($_.Exception.Message). Common causes: third-party AV tamper protection, GP enforcement, or service disabled at driver level."
    }
} else {
    Log PASS "WinDefend service already running"
}

# -- Step 4: Enable protections via Set-MpPreference --

if (-not (Get-Module -ListAvailable -Name Defender -ErrorAction SilentlyContinue)) {
    Log FAIL "Defender PowerShell module not found. Cannot configure protections."
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
        Log PASS "Core protections enabled (RealTime, Behavior, BlockAtFirstSeen, IOAV, ScriptScanning, ArchiveScanning, IPS, MAPS=Advanced)"
    } catch {
        Log FAIL "Set-MpPreference failed. Error: $($_.Exception.GetType().Name): $($_.Exception.Message). A GP may be overriding these settings. Check: HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
    }

    try {
        Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction Stop
        Log PASS "Network Protection enabled"
    } catch {
        Log WARN "Network Protection not available. Error: $($_.Exception.GetType().Name): $($_.Exception.Message). Requires Server 2019+ or Windows 10 1709+."
    }
}

# -- Step 5: Signature update --

try {
    Update-MpSignature -ErrorAction Stop
    Log PASS "Signature update initiated"
} catch {
    Log WARN "Signature update failed. Error: $($_.Exception.GetType().Name): $($_.Exception.Message). Will retry on next scheduled update cycle."
}

# -- Summary --

if ($script:ExitCode -eq 0) {
    Log INFO "=== All steps passed. Exit code: 0 ==="
} else {
    Log INFO "=== One or more steps failed. Exit code: 1. Review FAIL entries above. ==="
}

exit $script:ExitCode
