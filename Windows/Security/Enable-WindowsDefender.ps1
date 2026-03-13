<#
.SYNOPSIS
    Enables Windows Defender. Designed for NinjaOne deployment.
.DESCRIPTION
    1. Clears Group Policy registry overrides that disable Defender
    2. Installs Windows Defender feature if missing (Server OS)
    3. Sets WinDefend service to Automatic and starts it
    4. Enables all core protections via Set-MpPreference
    5. Triggers a signature update
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

# -- Step 2: Ensure Windows Defender is installed --

$svc = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
if (-not $svc) {
    Log WARN "WinDefend service not found. Attempting to install Windows Defender feature."

    # Detect OS type and attempt installation
    $isServer = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue).ProductType -ne 1
    if ($isServer) {
        # Server OS: use Install-WindowsFeature (available on 2012+)
        $installCmd = Get-Command Install-WindowsFeature -ErrorAction SilentlyContinue
        if (-not $installCmd) {
            Log FAIL "Install-WindowsFeature cmdlet not available. This server may be too old (requires Server 2012+)."
            Log INFO "=== Aborted. Exit code: $script:ExitCode ==="
            exit $script:ExitCode
        }

        # Feature name varies by OS version:
        #   Server 2016+    : Windows-Defender
        #   Server 2012 R2  : Windows-Defender-Features, Windows-Server-Antimalware
        #   Server 2012     : Windows-Server-Antimalware
        $featureNames = @('Windows-Defender', 'Windows-Defender-Features', 'Windows-Server-Antimalware')
        $targetFeature = $null

        foreach ($fname in $featureNames) {
            $feat = Get-WindowsFeature -Name $fname -ErrorAction SilentlyContinue
            if ($feat) {
                $targetFeature = $fname
                if ($feat.Installed) {
                    Log INFO "Feature '$fname' is already installed (state: $($feat.InstallState)). Service may need a reboot to appear."
                }
                break
            }
        }

        if (-not $targetFeature) {
            $available = Get-WindowsFeature -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '*Defend*' -or $_.Name -like '*Antimalware*' -or $_.Name -like '*Defender*' } | ForEach-Object { $_.Name }
            $hint = if ($available) { "Similar features found: $($available -join ', ')" } else { "No Defender-related features found on this OS" }
            Log FAIL "No known Defender feature name found. Tried: $($featureNames -join ', '). $hint. This OS may not support Windows Defender."
            Log INFO "=== Aborted. Exit code: $script:ExitCode ==="
            exit $script:ExitCode
        }

        try {
            Log INFO "Installing feature '$targetFeature' (this may take several minutes)."
            $result = Install-WindowsFeature -Name $targetFeature -ErrorAction Stop
            if ($result.Success) {
                Log PASS "Feature '$targetFeature' installed successfully."
                if ($result.RestartNeeded -eq 'Yes') {
                    Log WARN "REBOOT REQUIRED to complete installation. Defender will not function until the server is restarted. Re-run this script after reboot."
                    Log INFO "=== Reboot required. Exit code: 1 ==="
                    exit 1
                }
            } else {
                Log FAIL "Install-WindowsFeature '$targetFeature' returned Success=False. Exit reason: $($result.ExitCode). Feature may be blocked by policy or partially installed."
                Log INFO "=== Aborted. Exit code: $script:ExitCode ==="
                exit $script:ExitCode
            }
        } catch {
            Log FAIL "Failed to install feature '$targetFeature'. Error: $($_.Exception.GetType().Name): $($_.Exception.Message). Run 'Get-WindowsFeature *Defend*' to check available features."
            Log INFO "=== Aborted. Exit code: $script:ExitCode ==="
            exit $script:ExitCode
        }
    } else {
        # Desktop OS: Defender should always be present. If the service is missing, something is seriously wrong.
        Log FAIL "WinDefend service not found on desktop OS ($([Environment]::OSVersion.VersionString)). Defender may have been removed by third-party antivirus or system modification. Check: Get-WindowsOptionalFeature -Online -FeatureName Windows-Defender-Default-Definitions"
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
}

# -- Step 3: Enable and start WinDefend service --

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

# -- Step 4: Enable protections via Set-MpPreference --

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

# -- Step 5: Signature update --

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
