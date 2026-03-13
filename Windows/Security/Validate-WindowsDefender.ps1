<#
.SYNOPSIS
    Validates that Windows Defender is online and all protections are active.
.DESCRIPTION
    Checks WinDefend service, queries Get-MpComputerStatus for protection flags,
    signature freshness, running mode, and GP/passive-mode registry overrides.
    Outputs a color-coded status table.
    Designed for NinjaOne deployment (runs as SYSTEM).
    Exit code 0 = all checks pass, 1 = one or more failures, 2 = Defender unavailable.
#>

$ErrorActionPreference = 'SilentlyContinue'
$script:ExitCode = 0
$colors = @{ PASS = 'Green'; FAIL = 'Red'; WARN = 'Yellow'; INFO = 'Cyan' }

$results = [System.Collections.Generic.List[PSCustomObject]]::new()

function Check([string]$Name, [string]$Status, [string]$Value) {
    $results.Add([PSCustomObject]@{ Check = $Name; Status = $Status; Value = $Value })
    if ($Status -eq 'FAIL' -and $script:ExitCode -ne 2) { $script:ExitCode = 1 }
}

# -- Header --

$os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
$caption = if ($os) { $os.Caption.Trim() } else { 'Unknown' }

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " Windows Defender Validation - $env:COMPUTERNAME" -ForegroundColor Cyan
Write-Host " $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | OS: $caption" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

# -- Check 1: WinDefend service --

$svc = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
if (-not $svc) {
    Check "WinDefend Service" FAIL "Not found. Defender may not be installed."
    $script:ExitCode = 2
} else {
    $svcStatus = if ($svc.Status -eq 'Running') { 'PASS' } else { 'FAIL' }
    Check "WinDefend Service" $svcStatus "$($svc.Status)"

    $startStatus = if ($svc.StartType -eq 'Automatic') { 'PASS' } else { 'WARN' }
    $startNote = if ($svc.StartType -ne 'Automatic') { " (should be Automatic)" } else { "" }
    Check "WinDefend Start Type" $startStatus "$($svc.StartType)$startNote"
}

# -- Check 2: Protection flags via Get-MpComputerStatus --

$mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
if (-not $mp) {
    Check "Get-MpComputerStatus" FAIL "Unavailable. Defender module may be missing."
    $script:ExitCode = 2
} else {
    $protections = [ordered]@{
        "AM Service"           = "AMServiceEnabled"
        "Antispyware"          = "AntispywareEnabled"
        "Antivirus"            = "AntivirusEnabled"
        "Real-Time Protection" = "RealTimeProtectionEnabled"
        "On-Access Protection" = "OnAccessProtectionEnabled"
        "IOAV Protection"      = "IoavProtectionEnabled"
        "Network Inspection"   = "NISEnabled"
        "Behavior Monitor"     = "BehaviorMonitorEnabled"
    }

    foreach ($p in $protections.GetEnumerator()) {
        $val = $mp.$($p.Value)
        if ($null -eq $val) { Check $p.Key WARN "Not available on this OS" }
        elseif ($val)        { Check $p.Key PASS "Enabled" }
        else                 { Check $p.Key FAIL "DISABLED" }
    }

    # Versions
    $engineVer = $mp.AMEngineVersion; if (-not $engineVer) { $engineVer = "Unknown" }
    $productVer = $mp.AMProductVersion; if (-not $productVer) { $productVer = "Unknown" }
    Check "AM Engine Version"  INFO $engineVer
    Check "AM Product Version" INFO $productVer

    # Running mode
    if ($mp.AMRunningMode) {
        $modeStatus = if ($mp.AMRunningMode -eq 'Normal') { 'PASS' } else { 'WARN' }
        $modeNote = if ($mp.AMRunningMode -ne 'Normal') { " (expected: Normal)" } else { "" }
        Check "AM Running Mode" $modeStatus "$($mp.AMRunningMode)$modeNote"
    }

    # Tamper protection
    if ($null -ne $mp.IsTamperProtected) {
        if ($mp.IsTamperProtected) {
            Check "Tamper Protection" PASS "Enabled"
        } else {
            Check "Tamper Protection" WARN "Disabled"
        }
    }

    # Signature freshness
    $sigDate = $mp.AntivirusSignatureLastUpdated
    if ($sigDate) {
        $ageHours = [int]((Get-Date) - $sigDate).TotalHours
        $ageDays  = [math]::Round($ageHours / 24, 1)
        $sigStr   = "$($sigDate.ToString('yyyy-MM-dd HH:mm')) ($ageDays days old)"

        if ($ageHours -lt 168) {
            Check "Signature Age" PASS $sigStr
        } elseif ($ageHours -lt 336) {
            Check "Signature Age" WARN "$sigStr - stale"
        } else {
            Check "Signature Age" FAIL "$sigStr - critically stale"
        }

        $sigVer = $mp.AntivirusSignatureVersion; if (-not $sigVer) { $sigVer = "Unknown" }
        Check "Signature Version" INFO $sigVer
    } else {
        Check "Signature Age" WARN "Last update date unavailable"
    }
}

# -- Check 3: GP overrides --

$gpKeys = @(
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
)
$gpOverrides = @('DisableAntiSpyware', 'DisableRealtimeMonitoring', 'DisableBehaviorMonitoring', 'DisableIOAVProtection', 'DisableScriptScanning')
$foundGpOverrides = @()

foreach ($key in $gpKeys) {
    if (-not (Test-Path $key)) { continue }
    foreach ($name in $gpOverrides) {
        $prop = Get-ItemProperty -Path $key -Name $name -ErrorAction SilentlyContinue
        if ($null -ne $prop -and $prop.$name -eq 1) {
            $foundGpOverrides += "$key\$name=1"
        }
    }
}

if ($foundGpOverrides.Count -gt 0) {
    Check "GP Overrides" WARN "Found $($foundGpOverrides.Count): $($foundGpOverrides -join '; ')"
} else {
    Check "GP Overrides" PASS "None found"
}

# -- Check 4: ForceDefenderPassiveMode --

$passiveKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection'
if (Test-Path $passiveKey) {
    $passiveProp = Get-ItemProperty -Path $passiveKey -Name 'ForceDefenderPassiveMode' -ErrorAction SilentlyContinue
    if ($null -ne $passiveProp -and $passiveProp.ForceDefenderPassiveMode -eq 1) {
        Check "Passive Mode Override" WARN "ForceDefenderPassiveMode=1. Defender is in passive mode."
    } else {
        Check "Passive Mode Override" PASS "Not set"
    }
} else {
    Check "Passive Mode Override" PASS "Not set"
}

# -- Results table --

$passCount = @($results | Where-Object { $_.Status -eq 'PASS' }).Count
$warnCount = @($results | Where-Object { $_.Status -eq 'WARN' }).Count
$failCount = @($results | Where-Object { $_.Status -eq 'FAIL' }).Count
$infoCount = @($results | Where-Object { $_.Status -eq 'INFO' }).Count

Write-Host ""
Write-Host "--- Results ---" -ForegroundColor Cyan
Write-Host ""

$col1 = 24; $col2 = 7
Write-Host ("Check".PadRight($col1) + "Status".PadRight($col2) + "Value") -ForegroundColor Cyan
Write-Host ("-" * 90) -ForegroundColor Cyan

foreach ($r in $results) {
    $line = $r.Check.PadRight($col1) + $r.Status.PadRight($col2) + $r.Value
    Write-Host $line -ForegroundColor $colors[$r.Status]
}

Write-Host ("-" * 90) -ForegroundColor Cyan

if ($failCount -gt 0) { $summaryColor = 'Red' }
elseif ($warnCount -gt 0) { $summaryColor = 'Yellow' }
else { $summaryColor = 'Green' }

Write-Host "PASS: $passCount  WARN: $warnCount  FAIL: $failCount  INFO: $infoCount" -ForegroundColor $summaryColor
Write-Host ""

if ($script:ExitCode -eq 2) {
    Write-Host "RESULT: UNAVAILABLE - Defender is not installed or accessible." -ForegroundColor Red
} elseif ($failCount -gt 0) {
    Write-Host "RESULT: FAILED - Run Enable-WindowsDefender.ps1 to remediate." -ForegroundColor Red
} elseif ($warnCount -gt 0) {
    Write-Host "RESULT: WARNINGS - Review items above." -ForegroundColor Yellow
} else {
    Write-Host "RESULT: PASS - Defender is fully operational." -ForegroundColor Green
}

Write-Host ""
exit $script:ExitCode
