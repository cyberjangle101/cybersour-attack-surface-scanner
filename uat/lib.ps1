# Helpers for the UAT scripts (run.ps1 runs them all; the Release workflow runs it on every RC).
# Credentials are generated per run and written only to the output folder ($env:UAT_OUT,
# default uat\out), which is git-ignored and never uploaded.
$script:Results = New-Object System.Collections.Generic.List[object]
$script:OutDir = if ($env:UAT_OUT) { $env:UAT_OUT } else { Join-Path $PSScriptRoot 'out' }
New-Item -ItemType Directory -Force $script:OutDir | Out-Null

function OutPath([string]$Name) { Join-Path $script:OutDir $Name }

# The lab (EASM_LAB=1 go test -run ^TestLab$) writes its control files to $env:EASM_LAB_DIR (default /tmp, C:\tmp on Windows).
function Get-LabDir { if ($env:EASM_LAB_DIR) { $env:EASM_LAB_DIR } else { 'C:\tmp' } }
function Get-LabSetupCode { (Get-Content (Join-Path (Get-LabDir) 'lab.setup-code') -Raw).Trim() }

# The setup code an agent wrote to setup-code.txt in its data folder (the indented line), or '' before v1.9.6.
function Get-SetupCode([string]$DataDir) {
    $f = Join-Path $DataDir 'setup-code.txt'
    if (-not (Test-Path $f)) { return '' }
    $line = Get-Content $f | Where-Object { $_ -match '^\s{4}\S' } | Select-Object -First 1
    if ($line) { $line.Trim() } else { '' }
}

function New-Secret([int]$n = 24) { -join ((48..57) + (97..122) | Get-Random -Count $n | ForEach-Object { [char]$_ }) }

function Start-Agent([string]$Exe, [string]$DataDir, [int]$Port, [string]$Passphrase, [string[]]$Extra = @()) {
    $busy = $false; try { $null = Invoke-WebRequest -UseBasicParsing "http://127.0.0.1:$Port/healthz" -TimeoutSec 2; $busy = $true } catch {}
    if ($busy) { throw "port $Port is already serving an agent (left over from an earlier run?); stop it first" }
    $env:EASM_KEY_PASSPHRASE = $Passphrase
    $cfg = Join-Path (Split-Path $DataDir) ("agent-$Port.yaml")
    Set-Content -Path $cfg -Encoding ascii -Value ("logging:`r`n  level: info`r`n  file: " + (($DataDir -replace '\\', '/') + "/agent.log"))
    $args = @('-data-dir', $DataDir, '-listen', "127.0.0.1:$Port", '-plain-http', '-config', $cfg) + $Extra
    $p = Start-Process -FilePath $Exe -ArgumentList $args -PassThru -WindowStyle Hidden
    Remove-Item Env:EASM_KEY_PASSPHRASE
    for ($i = 0; $i -lt 60; $i++) {
        Start-Sleep -Milliseconds 500
        try { if ((Invoke-WebRequest -UseBasicParsing "http://127.0.0.1:$Port/healthz" -TimeoutSec 2).StatusCode -eq 200) { return $p } } catch {}
        if ($p.HasExited) { break }
    }
    throw "agent $Exe did not start on $Port (exited=$($p.HasExited))"
}

function Get-Csrf([string]$html) { if ($html -match 'name="csrf" value="([0-9a-f]+)"') { $Matches[1] } }

function Invoke-Page($Session, [string]$Base, [string]$Path, [hashtable]$Form = $null) {
    $p = @{ UseBasicParsing = $true; WebSession = $Session; Uri = "$Base$Path"; MaximumRedirection = 0; ErrorAction = 'Stop' }
    if ($Form) { $p.Method = 'Post'; $p.Body = $Form }
    try { $r = Invoke-WebRequest @p; return @{ c = [int]$r.StatusCode; b = $r.Content; l = $r.Headers.Location } }
    catch {
        $resp = $_.Exception.Response
        if (-not $resp) { throw }
        $sr = New-Object IO.StreamReader($resp.GetResponseStream())
        return @{ c = [int]$resp.StatusCode; b = $sr.ReadToEnd(); l = $resp.Headers['Location'] }
    }
}

function Connect-Agent([string]$Base, [string]$User, [string]$Password) {
    $s = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $lg = Invoke-Page $s $Base '/login'
    $r = Invoke-Page $s $Base '/login' @{ csrf = (Get-Csrf $lg.b); username = $User; password = $Password }
    if ($r.c -ne 303) { throw "sign-in as $User failed: $($r.c)" }
    return $s
}

function Check([string]$Id, [string]$Name, [bool]$Ok, [string]$Note = '') {
    $script:Results.Add([pscustomobject]@{ Id = $Id; Check = $Name; Result = $(if ($Ok) { 'PASS' } else { 'FAIL' }); Note = $Note })
    "{0} {1} {2}{3}" -f $(if ($Ok) { 'PASS' } else { 'FAIL' }), $Id, $Name, $(if ($Note) { "  ($Note)" } else { '' })
}

function Stop-Agent($Proc) { if ($Proc -and -not $Proc.HasExited) { Stop-Process -Id $Proc.Id -Confirm:$false; $Proc.WaitForExit(10000) | Out-Null } }
