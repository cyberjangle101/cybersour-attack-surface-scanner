# UP: data and a backup made by the previous release must open, unchanged and usable, in the new build.
#   powershell -ExecutionPolicy Bypass -File .\uat\upgrade.ps1 -OldExe <previous release exe> -NewExe <new exe>
# Uses throwaway data folders under the output folder and ports 18101-18103. The test domain is a
# reserved .test name, so a scan it triggers reaches no real organisation.
param([Parameter(Mandatory)][string]$OldExe, [Parameter(Mandatory)][string]$NewExe)
. "$PSScriptRoot\lib.ps1"
$pass = New-Secret 24; $adminPw = (New-Secret 20) + '-Aa1'; $anPw = (New-Secret 20) + '-Bb2'
Set-Content (OutPath 'upgrade-credentials.txt') -Encoding ascii -Value "key passphrase: $pass`r`nadmin: upadmin / $adminPw`r`nanalyst: upanalyst / $anPw"
$data = OutPath 'upgrade-data'; $rdata = OutPath 'upgrade-restored'; $backup = OutPath 'upgrade-backup.zip'
Remove-Item $data, $rdata, $backup -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory $data, $rdata | Out-Null
$oldVer = (& $OldExe -version) -join ' '; $newVer = (& $NewExe -version) -join ' '
$p = $null
try { # always stop the agent, so a failure cannot leave one holding a port

# ---- the previous release creates the data
$p = Start-Agent $OldExe $data 18101 $pass @('-no-browser')
$B = 'http://127.0.0.1:18101'
$a = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$code = Get-SetupCode $data
$r = Invoke-Page $a $B '/setup'
$null = Invoke-Page $a $B '/setup' @{ csrf = (Get-Csrf $r.b); code = $code; username = 'upadmin'; password = $adminPw; confirm = $adminPw }
$a = Connect-Agent $B 'upadmin' $adminPw
$d = Invoke-Page $a $B '/'; $null = Invoke-Page $a $B '/targets' @{ csrf = (Get-Csrf $d.b); domain = 'upgrade.example.test'; asns = 'AS64500'; keywords = 'EXAMPLE' }
$u = Invoke-Page $a $B '/users'; $null = Invoke-Page $a $B '/users' @{ csrf = (Get-Csrf $u.b); username = 'upanalyst'; password = $anPw; role = 'analyst' }
$st = Invoke-Page $a $B '/settings'
$null = Invoke-WebRequest -UseBasicParsing -WebSession $a "$B/settings/backup/download" -Method Post -Body @{ csrf = (Get-Csrf $st.b); include_key = 'on' } -OutFile $backup
Check 'UP-1.1' "previous release ($oldVer) set up an admin, an analyst and a domain" ((Invoke-Page $a $B '/targets').b -match 'upgrade\.example\.test')
Check 'UP-1.2' 'previous release downloaded a backup' ((Test-Path $backup) -and (Get-Item $backup).Length -gt 1000)
$auditBefore = ([regex]::Matches((Invoke-Page $a $B '/audit').b, '<tr')).Count
Stop-Agent $p

# ---- the new build opens the same data
$p = Start-Agent $NewExe $data 18102 $pass @('-no-browser')
$B = 'http://127.0.0.1:18102'
try { $a = Connect-Agent $B 'upadmin' $adminPw; $ok = $true } catch { $ok = $false }
Check 'UP-2.1' "new build ($newVer) starts on the previous release's data and the admin can sign in" $ok
try { $null = Connect-Agent $B 'upanalyst' $anPw; $ok = $true } catch { $ok = $false }
Check 'UP-2.2' 'analyst made by the previous release can sign in' $ok
Check 'UP-2.3' 'monitored domain survived the upgrade' ((Invoke-Page $a $B '/targets').b -match 'upgrade\.example\.test')
$auditAfter = ([regex]::Matches((Invoke-Page $a $B '/audit').b, '<tr')).Count
Check 'UP-2.4' 'audit trail kept every earlier entry' ($auditAfter -ge $auditBefore) "before=$auditBefore after=$auditAfter"
Check 'UP-2.5' 'Settings, Findings and System health pages load' (((Invoke-Page $a $B '/settings').c -eq 200) -and ((Invoke-Page $a $B '/findings').c -eq 200) -and ((Invoke-Page $a $B '/health').c -eq 200))
Stop-Agent $p
Check 'UP-2.6' 'no panic or database lock logged by the new build' (-not (Select-String -Path "$data\agent.log" -Pattern 'panic|database is locked' -Quiet))

# ---- the new build restores the previous release's backup into a fresh folder
$out = & $NewExe -data-dir $rdata -restore $backup 2>&1 | ForEach-Object { "$_" }
Check 'UP-3.1' 'new build restores the backup' ($LASTEXITCODE -eq 0) (($out -join ' ') -replace '\s+', ' ')
$p = Start-Agent $NewExe $rdata 18103 $pass @('-no-browser')
$B = 'http://127.0.0.1:18103'
try { $a = Connect-Agent $B 'upadmin' $adminPw; $ok = ((Invoke-Page $a $B '/targets').b -match 'upgrade\.example\.test') } catch { $ok = $false }
Check 'UP-3.2' 'restored data: the admin signs in and sees the domain' $ok
} finally { Stop-Agent $p }

$script:Results | Export-Csv (OutPath 'upgrade-results.csv') -NoTypeInformation
"{0} passed, {1} failed" -f @($script:Results | Where-Object Result -eq 'PASS').Count, @($script:Results | Where-Object Result -eq 'FAIL').Count
