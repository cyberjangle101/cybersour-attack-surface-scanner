# End-to-end check of "easm-agent -service install" on this computer.
# Run from an ELEVATED PowerShell:  powershell -ExecutionPolicy Bypass -File .\uat\service.ps1 -Exe <path to easm-agent.exe>
# (GitHub's Windows runners are elevated, so the Release workflow runs it on every RC.)
# It installs the service on port 18557, checks it, then stops and uninstalls it and removes
# what it created (C:\Program Files\EASM Agent and C:\ProgramData\EASM Agent), unless -Keep is given.
param([Parameter(Mandatory)][string]$Exe, [switch]$Keep)
$ErrorActionPreference = 'Stop'
$results = @()
function Check($id, $name, $ok, $note = '') { $script:results += [pscustomobject]@{ Id = $id; Result = $(if ($ok) { 'PASS' } else { 'FAIL' }); Name = $name; Note = $note }; Write-Host ("{0} {1} {2} {3}" -f $(if ($ok) { 'PASS' } else { 'FAIL' }), $id, $name, $note) }

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this from an elevated (Run as administrator) PowerShell.' }
if (Get-Service easm-agent -ErrorAction SilentlyContinue) { throw 'An easm-agent service already exists; this test will not touch it.' }
$pd = Join-Path $env:ProgramData 'EASM Agent'; $pf = Join-Path $env:ProgramFiles 'EASM Agent'
if (Test-Path (Join-Path $pd 'easm.db')) { throw "$pd already holds data; this test will not touch it." }

& $Exe -service install -listen 127.0.0.1:18557 -plain-http | Out-Host
$svc = Get-CimInstance Win32_Service -Filter "Name='easm-agent'"
Check 'SVC-1' 'service installed, runs as NT SERVICE\easm-agent' ($svc.StartName -eq 'NT SERVICE\easm-agent') $svc.StartName
Check 'SVC-2' 'program copied to Program Files and run from there' ($svc.PathName -like "*$pf\easm-agent.exe*") $svc.PathName
Check 'SVC-3' 'data folder in ProgramData' ($svc.PathName -like "*$pd*")
Check 'SVC-4' 'automatic (delayed) start' ($svc.StartMode -eq 'Auto')
$acl = (icacls $pd) -join "`n"
$me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
Check 'SVC-5' 'data folder: only the service account, SYSTEM and Administrators (not the installer personally)' (($acl -match 'NT SERVICE\\easm-agent') -and ($acl -notmatch 'BUILTIN\\Users') -and ($acl -notmatch 'Everyone') -and ($acl -notmatch [regex]::Escape($me))) ($acl -replace "`n", ' | ')

& $Exe -service start | Out-Host
$up = $false; for ($i = 0; $i -lt 40; $i++) { Start-Sleep 1; try { if ((Invoke-WebRequest -UseBasicParsing http://127.0.0.1:18557/healthz -TimeoutSec 2).StatusCode -eq 200) { $up = $true; break } } catch {} }
$note = ''
if (-not $up) { # tell a scheme mismatch apart from a service that is down
    [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    try { if ((Invoke-WebRequest -UseBasicParsing https://127.0.0.1:18557/healthz -TimeoutSec 3).StatusCode -eq 200) { $note = 'answers on HTTPS instead: -plain-http was not applied' } } catch { $note = 'no answer on HTTP or HTTPS' }
}
Check 'SVC-6' 'service starts and serves the web interface over plain HTTP as installed' $up $note
$key = Get-Content (Join-Path $pd 'easm.key') -TotalCount 1 -ErrorAction SilentlyContinue
Check 'SVC-7' 'key created and protected with the service account (DPAPI), no passphrase' ($key -eq 'easm-key-v3-dpapi') $key
Check 'SVC-8' 'setup code written for the first administrator' (Test-Path (Join-Path $pd 'setup-code.txt'))
$page = try { (Invoke-WebRequest -UseBasicParsing http://127.0.0.1:18557/setup).Content } catch { '' }
Check 'SVC-9' 'setup page asks for the code' ($page -match 'name="code"')
$proc = Get-CimInstance Win32_Process -Filter "Name='easm-agent.exe'" | Where-Object { $_.ExecutablePath -like "$pf*" } | Select-Object -First 1
$owner = if ($proc) { Invoke-CimMethod -InputObject $proc -MethodName GetOwner } else { $null }
Check 'SVC-10' 'process runs as the virtual account' ($owner -and $owner.Domain -eq 'NT SERVICE' -and $owner.User -eq 'easm-agent') "$($owner.Domain)\$($owner.User)"

& $Exe -service stop | Out-Host
if (-not $Keep) {
    & $Exe -service uninstall | Out-Host
    Start-Sleep 2
    Remove-Item -Recurse -Force $pd, $pf -ErrorAction SilentlyContinue
    Check 'SVC-11' 'uninstalled and cleaned up' (-not (Get-Service easm-agent -ErrorAction SilentlyContinue))
}
$results | Export-Csv (Join-Path $(if ($env:UAT_OUT) { $env:UAT_OUT } else { $PSScriptRoot }) 'service-results.csv') -NoTypeInformation
"{0} passed, {1} failed" -f @($results | Where-Object Result -eq 'PASS').Count, @($results | Where-Object Result -eq 'FAIL').Count
