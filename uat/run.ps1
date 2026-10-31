# Runs the whole UAT suite and exits non-zero if any check fails or a script does not finish.
#   powershell -ExecutionPolicy Bypass -File .\uat\run.ps1 -Exe <easm-agent.exe> [-PreviousExe <exe>] [-SkipService]
# Steps: scanning UAT on a fresh lab; evidence and corroboration UAT on a second fresh lab; the
# upgrade test from -PreviousExe; the Windows service test (needs an elevated prompt).
# The lab runs from this checkout's source (go test), the other steps from -Exe.
param([Parameter(Mandatory)][string]$Exe, [string]$PreviousExe, [switch]$SkipService)
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot
$out = if ($env:UAT_OUT) { $env:UAT_OUT } else { Join-Path $PSScriptRoot 'out' }
Remove-Item (Join-Path $out '*-results.csv') -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $out | Out-Null
$env:UAT_OUT = $out
$env:EASM_LAB_DIR = Join-Path $out 'lab'
New-Item -ItemType Directory -Force $env:EASM_LAB_DIR | Out-Null
$Exe = (Resolve-Path $Exe).Path

Write-Host "UAT of $((& $Exe -version) -join ' ')"
$labExe = Join-Path $out 'lab.test.exe'
Push-Location $repo
try { & go test -c -o $labExe . ; if ($LASTEXITCODE) { throw 'building the lab failed' } } finally { Pop-Location }

function Start-Lab {
    Remove-Item (Join-Path $env:EASM_LAB_DIR 'lab.*') -ErrorAction SilentlyContinue
    $env:EASM_LAB = '1'
    $p = Start-Process -FilePath $labExe -ArgumentList '-test.run', '^TestLab$', '-test.timeout', '60m' -WorkingDirectory $repo -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $out 'lab.log') -RedirectStandardError (Join-Path $out 'lab.err')
    Remove-Item Env:EASM_LAB
    for ($i = 0; $i -lt 120; $i++) { if (Test-Path (Join-Path $env:EASM_LAB_DIR 'lab.ready')) { return $p }; if ($p.HasExited) { break }; Start-Sleep 1 }
    throw 'the lab did not start'
}
function Stop-Lab($p) {
    Set-Content (Join-Path $env:EASM_LAB_DIR 'lab.stop') 'stop'
    if (-not $p.WaitForExit(30000)) { Stop-Process -Id $p.Id -Force }
}
function Step([string]$Script, [string[]]$ScriptArgs = @()) {
    Write-Host "== $Script"
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot $Script) @ScriptArgs | Out-Host
}

$expected = @('scan', 'evidence', 'trust')
$lab = Start-Lab; try { Step 'scan.ps1' } finally { Stop-Lab $lab }
$lab = Start-Lab; try { Step 'evidence.ps1'; Step 'trust.ps1' } finally { Stop-Lab $lab }
if ($PreviousExe) { $expected += 'upgrade'; Step 'upgrade.ps1' @('-OldExe', (Resolve-Path $PreviousExe).Path, '-NewExe', $Exe) }
if (-not $SkipService) { $expected += 'service'; Step 'service.ps1' @('-Exe', $Exe) }

# ---- summary
$rows = @(); $missing = @()
foreach ($n in $expected) {
    $f = Join-Path $out "$n-results.csv"
    if (Test-Path $f) { $rows += Import-Csv $f | ForEach-Object { $_ | Add-Member -NotePropertyName Suite -NotePropertyValue $n -PassThru } } else { $missing += $n }
}
$rows | Export-Csv (Join-Path $out 'uat-results.csv') -NoTypeInformation
$failed = @($rows | Where-Object Result -ne 'PASS')
Write-Host ''
Write-Host ("UAT: {0} passed, {1} failed{2}" -f ($rows.Count - $failed.Count), $failed.Count, $(if ($missing) { "; did not finish: $($missing -join ', ')" } else { '' }))
$failed | ForEach-Object { Write-Host ("FAIL {0} {1} {2}" -f $_.Suite, $_.Id, $(if ($_.Check) { $_.Check } else { $_.Name })) }
if ($failed -or $missing) { exit 1 }
