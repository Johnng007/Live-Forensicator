#Requires -Version 5.1
<#
.SYNOPSIS
    Benign detection-validation harness for the Live-Forensicator custom Sigma rules.

.DESCRIPTION
    Generates the *telemetry patterns* (process-creation command lines and PowerShell
    ScriptBlock text) that the Forensicator custom Sigma rules match on, WITHOUT
    performing any harmful action. This is an Atomic-Red-Team-style range test used to
    confirm that SigmaRuntime.ps1 actually fires each rule.

    Safety design — nothing destructive is ever performed:
      * Destructive LOLBINs (vssadmin/wbadmin/bcdedit/wevtutil) are invoked with a
        help flag ('/?'), an invalid target, or deliberately invalid syntax, so the
        keyword lands in the command line but the tool performs NO action.
      * The LSASS-dump test uses an INVALID process id, so comsvcs MiniDump errors
        out immediately — no process memory is ever read.
      * PowerShell "attack" strings (AMSI bypass, download cradle) are assigned to a
        string variable and never executed, so the text is logged (Event ID 4104)
        without any download or bypass taking place.
      * Registry / scheduled-task persistence tests write to a clearly-named test
        artifact and then remove it in the same run.

    Each test prints the rule_id it targets so you can cross-check SigmaRuntime output.

.PARAMETER Run
    Actually execute the tests. Without this switch the script only lists what it would do.

.PARAMETER Test
    Optional. Run only the named test(s). Use -List to see the names.

.PARAMETER List
    List the available tests and the rule each one targets, then exit.

.EXAMPLE
    .\Invoke-SigmaDetectionTests.ps1 -List

.EXAMPLE
    .\Invoke-SigmaDetectionTests.ps1 -Run

.EXAMPLE
    .\Invoke-SigmaDetectionTests.ps1 -Run -Test AmsiBypass,DownloadCradle

.NOTES
    Author : Forensicator detection-engineering
    Purpose: Authorized detection validation on a system you own/administer.
    PowerShell Script Block Logging (4104) and process auditing (Security 4688 or
    Sysmon 1) must be enabled for the corresponding rules to have data to match.
#>
[CmdletBinding()]
param(
    [switch]$Run,
    [string[]]$Test,
    [switch]$List
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# --- Test registry -----------------------------------------------------------
# Each entry: Name, Rule (rule_id it exercises), Desc, Action (scriptblock).
$Tests = [ordered]@{}

function Register-DetTest {
    param([string]$Name,[string]$Rule,[string]$Desc,[scriptblock]$Action)
    $script:Tests[$Name] = [pscustomobject]@{
        Name = $Name; Rule = $Rule; Desc = $Desc; Action = $Action
    }
}

function Write-Step {
    param([string]$Msg)
    Write-Host "    -> $Msg" -ForegroundColor DarkGray
}

# Temp working area for artifacts we create and immediately clean up.
$WorkDir = Join-Path $env:TEMP ('SigmaDetTest_' + $PID)

# =============================================================================
#  TESTS  (one per custom rule)
# =============================================================================

# 1) forensicator-custom-amsi-ps-bypass  (ps_script / ScriptBlockText)
Register-DetTest -Name 'AmsiBypass' `
    -Rule 'forensicator-custom-amsi-ps-bypass' `
    -Desc 'PowerShell ScriptBlock containing AMSI-bypass / exec-policy / logging-disable strings (logged, never executed).' `
    -Action {
        # The strings below are ASSIGNED to a variable and never run. Their presence
        # in the compiled script block is what Event ID 4104 records and the rule matches.
        Write-Step 'Emitting benign ScriptBlock containing AMSI/bypass indicator strings'
        $benignIndicators = @(
            "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')",
            'AmsiScanBuffer / amsiInitFailed reference',
            'System.Runtime.InteropServices + VirtualProtect + GetDelegateForFunctionPointer',
            'Set-ExecutionPolicy Bypass  /  -ExecutionPolicy Bypass  /  -ep bypass',
            'DisableScriptBlockLogging / EnableScriptBlockLogging'
        )
        $null = $benignIndicators   # no-op use
        # Also generate a real process-creation event with the exec-policy flag:
        Start-Process -FilePath 'powershell.exe' `
            -ArgumentList '-ExecutionPolicy','Bypass','-NoProfile','-Command','Start-Sleep -Milliseconds 50' `
            -WindowStyle Hidden -Wait
    }

# 2) forensicator-custom-ps-download-cradle  (ps_script / ScriptBlockText)
Register-DetTest -Name 'DownloadCradle' `
    -Rule 'forensicator-custom-ps-download-cradle' `
    -Desc 'PowerShell ScriptBlock containing IEX + download-cradle strings (logged, never executed).' `
    -Action {
        # Requires BOTH an IEX token AND a download token in the same block. We put both
        # in a single string literal so the block is logged but nothing is downloaded/run.
        Write-Step 'Emitting benign ScriptBlock containing IEX + WebClient.DownloadString cradle text'
        $cradleText = 'IEX (New-Object Net.WebClient).DownloadString("http://127.0.0.1/benign-detection-test")'
        $cradleText += ' ; Invoke-Expression Invoke-WebRequest Start-BitsTransfer Invoke-RestMethod'
        Write-Step "Captured (not executed): $cradleText"
    }

# 3) forensicator-custom-ad-recon  (process_creation)
Register-DetTest -Name 'AdRecon' `
    -Rule 'forensicator-custom-ad-recon' `
    -Desc 'Read-only AD/domain discovery via nltest, net, dsquery (no changes made).' `
    -Action {
        Write-Step 'nltest /domain_trusts (read-only)'
        & nltest.exe /domain_trusts 2>$null | Out-Null
        Write-Step 'net group "Domain Admins" /domain (read-only)'
        & net.exe group "Domain Admins" /domain 2>$null | Out-Null
        Write-Step 'dsquery * -limit 1  (read-only; may be absent on non-DC hosts)'
        if (Get-Command dsquery.exe -ErrorAction SilentlyContinue) {
            & dsquery.exe * -limit 1 2>$null | Out-Null
        } else { Write-Step 'dsquery.exe not present - skipped' }
    }

# 4) forensicator-custom-data-staging-compression  (process_creation)
Register-DetTest -Name 'DataStaging' `
    -Rule 'forensicator-custom-data-staging-compression' `
    -Desc 'Password-protected archive of a benign temp file via 7-Zip/WinRAR to a temp path.' `
    -Action {
        New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
        $sample = Join-Path $WorkDir 'benign_sample.txt'
        'benign detection test content' | Set-Content -Path $sample
        $archive = Join-Path $env:TEMP 'sigma_staging_test.7z'
        $sevenZip = Get-Command 7z.exe -ErrorAction SilentlyContinue
        $rar      = Get-Command rar.exe -ErrorAction SilentlyContinue
        if ($sevenZip) {
            Write-Step '7z a -p<pw> to %TEMP% (benign sample only)'
            & $sevenZip.Source a "-pDetTestPw123" $archive $sample 2>$null | Out-Null
            Remove-Item $archive -ErrorAction SilentlyContinue
        } elseif ($rar) {
            Write-Step 'rar a -hp<pw> to %TEMP% (benign sample only)'
            & $rar.Source a "-hpDetTestPw123" ($archive -replace '\.7z$','.rar') $sample 2>$null | Out-Null
        } else {
            Write-Step '7z.exe / rar.exe not installed - test skipped'
        }
        Remove-Item $WorkDir -Recurse -Force -ErrorAction SilentlyContinue
    }

# 5) forensicator-custom-event-log-cleared  (process_creation)
Register-DetTest -Name 'EventLogCleared' `
    -Rule 'forensicator-custom-event-log-cleared' `
    -Desc 'wevtutil "cl" against a NON-EXISTENT channel: matches the rule, clears nothing real.' `
    -Action {
        # 'cl' keyword is present in the command line; the target channel does not exist,
        # so wevtutil errors out and NO real log is cleared.
        Write-Step 'wevtutil cl "Forensicator-Nonexistent-Test-Channel"  (errors; deletes nothing)'
        & wevtutil.exe cl "Forensicator-Nonexistent-Test-Channel" 2>$null
    }

# 6) forensicator-custom-lsass-dump  (process_creation)
Register-DetTest -Name 'LsassDump' `
    -Rule 'forensicator-custom-lsass-dump' `
    -Desc 'rundll32 comsvcs.dll MiniDump against an INVALID pid: matches the rule, dumps nothing.' `
    -Action {
        # Uses PID 999999 (invalid). comsvcs MiniDump fails instantly; LSASS is never touched.
        $out = Join-Path $env:TEMP 'sigma_lsass_test.dmp'
        Write-Step 'rundll32.exe comsvcs.dll, MiniDump 999999 <out> full  (invalid pid - no dump)'
        & rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 999999 $out full 2>$null
        Remove-Item $out -ErrorAction SilentlyContinue
    }

# 7) forensicator-custom-persistence-run-keys  (process_creation + ScriptBlockText)
Register-DetTest -Name 'RunKeyPersistence' `
    -Rule 'forensicator-custom-persistence-run-keys' `
    -Desc 'Adds then removes a benign HKCU ...\Run value (self-cleaning) + logs the PS run-key path.' `
    -Action {
        $runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
        $valName = 'ForensicatorDetTest'
        Write-Step 'reg.exe add ...\CurrentVersion\Run  (benign value)'
        & reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v $valName /t REG_SZ /d "calc.exe" /f 2>$null | Out-Null
        # PS-based variant string (matches selection_ps_run_key); harmless assignment.
        $psRunKeyText = 'Set-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run detection test'
        Write-Step "Captured PS run-key text: $psRunKeyText"
        Write-Step 'Cleanup: removing the test Run value'
        & reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v $valName /f 2>$null | Out-Null
    }

# 8) forensicator-custom-schtask-persistence  (process_creation)
Register-DetTest -Name 'SchtaskPersistence' `
    -Rule 'forensicator-custom-schtask-persistence' `
    -Desc 'Creates then deletes a benign ONLOGON scheduled task pointing at a temp path (self-cleaning).' `
    -Action {
        $taskName = 'ForensicatorDetTest'
        $tempCmd  = "$env:TEMP\benign_task.cmd"
        Write-Step 'schtasks /create /sc ONLOGON pointing to %TEMP% (benign)'
        & schtasks.exe /create /tn $taskName /sc ONLOGON /tr "cmd /c $tempCmd" /f 2>$null | Out-Null
        Write-Step 'Cleanup: deleting the test task'
        & schtasks.exe /delete /tn $taskName /f 2>$null | Out-Null
    }

# 9) forensicator-custom-shadow-copy-deletion  (process_creation)
Register-DetTest -Name 'ShadowCopyDeletion' `
    -Rule 'forensicator-custom-shadow-copy-deletion' `
    -Desc 'vssadmin/wmic/bcdedit invoked with help/read-only/invalid-syntax: matches rule, deletes NOTHING.' `
    -Action {
        # vssadmin: help mode for the delete verb - the word "delete" is in the command
        # line, but "/?" makes it print help instead of deleting any shadow copy.
        Write-Step 'vssadmin delete shadows /?   (HELP ONLY - nothing deleted)'
        & vssadmin.exe delete shadows /? 2>$null | Out-Null
        # wmic: read-only list of shadow copies.
        Write-Step 'wmic shadowcopy list brief   (read-only)'
        & wmic.exe shadowcopy list brief 2>$null | Out-Null
        # bcdedit: deliberately invalid syntax so the keyword appears but no boot config changes.
        Write-Step 'bcdedit recoveryenabled   (invalid syntax - no change made)'
        & bcdedit.exe recoveryenabled 2>$null | Out-Null
    }

# 10) forensicator-custom-lateral-movement-tools  (process_creation)
Register-DetTest -Name 'LateralMovement' `
    -Rule 'forensicator-custom-lateral-movement-tools' `
    -Desc 'wmic /node read-only, winrs help, and impacket keyword echo (no remote execution).' `
    -Action {
        Write-Step 'wmic /node:127.0.0.1 process list brief   (read-only, local loopback)'
        & wmic.exe /node:127.0.0.1 process list brief 2>$null | Out-Null
        if (Get-Command winrs.exe -ErrorAction SilentlyContinue) {
            Write-Step 'winrs -?   (help only)'
            & winrs.exe -? 2>$null | Out-Null
        } else { Write-Step 'winrs.exe not present - skipped' }
        # selection_impacket matches on command line only (no image restriction); echo is inert.
        Write-Step 'cmd /c echo smbexec wmiexec atexec dcomexec   (inert echo)'
        & cmd.exe /c "echo smbexec wmiexec atexec dcomexec" | Out-Null
        # PsExec is not shipped with Windows; run only if present.
        if (Get-Command psexec.exe -ErrorAction SilentlyContinue) {
            Write-Step 'psexec -? (help only)'
            & psexec.exe -? 2>$null | Out-Null
        } else { Write-Step 'psexec.exe not present - skipped' }
    }

# =============================================================================
#  Runner
# =============================================================================

function Show-List {
    Write-Host ''
    Write-Host '  Available Sigma detection tests' -ForegroundColor Cyan
    Write-Host '  -------------------------------' -ForegroundColor Cyan
    foreach ($t in $Tests.Values) {
        Write-Host ("  {0,-20} {1}" -f $t.Name, $t.Rule) -ForegroundColor White
        Write-Host ("  {0,-20} {1}" -f '', $t.Desc) -ForegroundColor DarkGray
    }
    Write-Host ''
}

if ($List) { Show-List; return }

if (-not $Run) {
    Write-Host ''
    Write-Host '  DRY RUN - no activity generated.' -ForegroundColor Yellow
    Write-Host '  Re-run with -Run to execute the benign detection tests.' -ForegroundColor Yellow
    Show-List
    return
}

# Which tests to run
$selected = if ($Test) {
    $Test | ForEach-Object {
        if ($Tests.Contains($_)) { $Tests[$_] }
        else { Write-Warning "Unknown test '$_' - skipped." }
    }
} else { $Tests.Values }

Write-Host ''
Write-Host '  ============================================================' -ForegroundColor Cyan
Write-Host '   Forensicator Sigma Detection Validation  (benign / safe)'  -ForegroundColor Cyan
Write-Host ("   Host: {0}   User: {1}   Time: {2}" -f $env:COMPUTERNAME,$env:USERNAME,(Get-Date)) -ForegroundColor DarkCyan
Write-Host '  ============================================================' -ForegroundColor Cyan

$results = foreach ($t in $selected) {
    Write-Host ''
    Write-Host ("  [TEST] {0}" -f $t.Name) -ForegroundColor Green
    Write-Host ("         rule : {0}" -f $t.Rule) -ForegroundColor Gray
    Write-Host ("         desc : {0}" -f $t.Desc) -ForegroundColor Gray
    $status = 'OK'
    try { & $t.Action }
    catch { $status = "ERROR: $($_.Exception.Message)"; Write-Warning $status }
    [pscustomobject]@{ Test = $t.Name; Rule = $t.Rule; Status = $status }
}

Write-Host ''
Write-Host '  ---------------------------- Summary ----------------------------' -ForegroundColor Cyan
$results | Format-Table -AutoSize
Write-Host '  Now run SigmaRuntime.ps1 (or your Wazuh pipeline) and confirm each' -ForegroundColor Yellow
Write-Host '  rule_id above produced a detection.' -ForegroundColor Yellow
Write-Host ''
