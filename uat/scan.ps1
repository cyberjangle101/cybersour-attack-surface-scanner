# Scanning UAT against the acme-corp.test lab (EASM_LAB=1 go test -run TestLab) on 127.0.0.1:18100.
# Covers: scan now / refresh / active, progress, pause (idle and mid-scan), resume,
# active checks requested mid-scan, roles, and "Confirm via active scan" on findings.
. "$PSScriptRoot\lib.ps1"
$B = 'http://127.0.0.1:18100'
for ($i = 0; $i -lt 180; $i++) { try { if ((Invoke-WebRequest -UseBasicParsing "$B/healthz" -TimeoutSec 2).StatusCode -eq 200) { break } } catch {}; Start-Sleep 1 }
$pw = (New-Secret 20) + '-Dd4'
Set-Content (OutPath 'scan-credentials.txt') -Encoding ascii -Value "lab admin: uatadmin / $pw"

function Flash([string]$html) { ([regex]::Match($html, '(?s)class="flash[^"]*"[^>]*>(.*?)</div>').Groups[1].Value -replace '<[^>]+>', '').Trim() }
function Prog($s) { try { Invoke-RestMethod -WebSession $s "$B/progress.json" } catch { @() } }
function ProgFor($s, [string]$dom) { @(Prog $s) | Where-Object { $_.domain -eq $dom } }
function TargetId($s, [string]$dom) { $t = (Invoke-Page $s $B '/targets').b; if ($t -match "/targets/(\d+)`"><strong>$([regex]::Escape($dom))<") { $Matches[1] } }
function TargetPage($s, $id) { (Invoke-Page $s $B "/targets/$id").b }
function Post($s, [string]$path, [hashtable]$extra = @{}) {
    $pg = Invoke-Page $s $B '/'
    $f = @{ csrf = (Get-Csrf $pg.b) }; foreach ($k in $extra.Keys) { $f[$k] = $extra[$k] }
    Invoke-Page $s $B $path $f
}
function WaitIdle($s, [string]$dom, [int]$secs = 120) {
    for ($i = 0; $i -lt $secs; $i++) { if (-not (ProgFor $s $dom)) { $row = (Invoke-Page $s $B '/targets').b; if ($row -notmatch "(?s)$([regex]::Escape($dom))<.{0,400}Scanning") { return $true } }; Start-Sleep 1 }
    $false
}

# --- Setup
$a = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$r = Invoke-Page $a $B '/setup'
$null = Invoke-Page $a $B '/setup' @{ csrf = (Get-Csrf $r.b); code = (Get-LabSetupCode); username = 'uatadmin'; password = $pw; confirm = $pw }
$a = Connect-Agent $B 'uatadmin' $pw
$u = Invoke-Page $a $B '/users'
$null = Invoke-Page $a $B '/users' @{ csrf = (Get-Csrf $u.b); username = 'uatanalyst'; password = "${pw}an"; role = 'analyst' }
$an = Connect-Agent $B 'uatanalyst' "${pw}an"

# --- SCAN-1: first scan of a domain
$add = Post $a '/targets' @{ domain = 'acme-corp.test'; asns = 'AS64500'; keywords = 'ACME' }
$acme = TargetId $a 'acme-corp.test'
Check 'SCAN-1.1' 'domain added and queued' (($add.c -eq 303) -and $acme)
Check 'SCAN-1.2' 'first scan completes' (WaitIdle $a 'acme-corp.test')
$h = TargetPage $a $acme
Check 'SCAN-1.3' 'target page shows the finished scan in history' ($h -match '(?i)last scan')
$f = (Invoke-Page $a $B '/findings').b
Check 'SCAN-1.4' 'findings raised, including exposed services from exposure data' (($f -match 'port 445') -and ($f -match 'port 3389') -and ($f -match 'InternetDB'))

# --- SCAN-2: scan now variants on an idle domain
$s = Post $a "/targets/$acme/scan"
Check 'SCAN-2.1' 'Scan now queues a scan' (($s.c -eq 303) -and ((Flash (Invoke-Page $a $B "/targets/$acme").b) -match 'Scan queued'))
Check 'SCAN-2.2' 'queued scan finishes' (WaitIdle $a 'acme-corp.test')
$s = Post $a "/targets/$acme/scan" @{ refresh = '1' }
Check 'SCAN-2.3' 'Scan now and refresh exposure data queues a refresh' ((Flash (Invoke-Page $a $B "/targets/$acme").b) -match 'Saved exposure answers will be ignored')
$null = WaitIdle $a 'acme-corp.test'
$s = Post $a "/targets/$acme/scan" @{ active = '1' }
Check 'SCAN-2.4' 'Scan now with active checks queues an active scan' ((Flash (Invoke-Page $a $B "/targets/$acme").b) -match 'Scan queued with active checks')
Check 'SCAN-2.5' 'active scan finishes' (WaitIdle $a 'acme-corp.test')
Check 'SCAN-2.6' 'active scan request is audited' ((Invoke-Page $a $B '/audit').b -match 'scan\.active')

# --- SCAN-3: pause and resume an idle domain
$p = Post $a "/targets/$acme/pause"
$tp = (Invoke-Page $a $B "/targets/$acme").b
Check 'SCAN-3.1' 'idle pause: monitoring paused, Resume offered, no scan running' (((Flash $tp) -match '^Monitoring paused\.') -and ($tp -match '>Resume<') -and -not (ProgFor $a 'acme-corp.test'))
$sn = Post $a "/targets/$acme/scan"
Check 'SCAN-3.2' 'Scan now on a paused domain explains why nothing happens' ((Flash (Invoke-Page $a $B "/targets/$acme").b) -match 'paused')
$null = Post $a "/targets/$acme/resume"
Check 'SCAN-3.3' 'resume starts a scan that finishes' (WaitIdle $a 'acme-corp.test')

# --- SCAN-4: pause while a scan is running (defect 1)
$null = Post $a '/targets' @{ domain = 'slowco.test'; asns = 'AS64500'; keywords = '' }
$slow = TargetId $a 'slowco.test'
for ($i = 0; $i -lt 30 -and -not (ProgFor $a 'slowco.test'); $i++) { Start-Sleep 1 }
$pr = ProgFor $a 'slowco.test'
Check 'SCAN-4.1' 'slow scan is running with a live progress bar' ([bool]$pr) "$($pr.percent)% $($pr.stage)"
$p = Post $a "/targets/$slow/pause"
$tp = (Invoke-Page $a $B "/targets/$slow").b
Check 'SCAN-4.2' 'pausing mid-scan says the running scan was stopped' ((Flash $tp) -match 'running scan was stopped') (Flash $tp)
$stopped = $false; for ($i = 0; $i -lt 10; $i++) { if (-not (ProgFor $a 'slowco.test')) { $stopped = $true; break }; Start-Sleep 1 }
Check 'SCAN-4.3' 'the scan actually stops within 10 seconds' $stopped "after ${i}s"
$tp = (Invoke-Page $a $B "/targets/$slow").b
Check 'SCAN-4.4' 'scan history records it as stopped because monitoring was paused' ($tp -match 'stopped: monitoring was paused')
Start-Sleep 20
Check 'SCAN-4.5' 'a paused domain is not scanned again (20s later)' (-not (ProgFor $a 'slowco.test'))
$hp = (Invoke-Page $a $B '/health').b
Check 'SCAN-4.6' 'stopping the scan is not logged as a connector failure' ($hp -notmatch 'monitoring was paused')
$null = Post $a "/targets/$slow/resume"
$re = $false; for ($i = 0; $i -lt 30; $i++) { if (ProgFor $a 'slowco.test') { $re = $true; break }; Start-Sleep 1 }
Check 'SCAN-4.7' 'resume starts the scan again' $re

# --- SCAN-5: active checks requested while a passive scan runs (defect 2)
$pr = ProgFor $a 'slowco.test'
Check 'SCAN-5.1' 'running scan is passive (no Active checks marker)' ($pr -and -not $pr.active)
$ana = Post $an "/targets/$slow/scan" @{ active = '1' }
Check 'SCAN-5.2' 'analyst cannot request active checks (403) and the scan is untouched' (($ana.c -eq 403) -and (ProgFor $a 'slowco.test'))
$rs = Post $a "/targets/$slow/scan" @{ active = '1' }
$tp = (Invoke-Page $a $B "/targets/$slow").b
Check 'SCAN-5.3' 'admin request restarts the scan with active checks' ((Flash $tp) -match 'starting again with active checks') (Flash $tp)
$act = $false; for ($i = 0; $i -lt 30; $i++) { $pr = ProgFor $a 'slowco.test'; if ($pr -and $pr.active) { $act = $true; break }; Start-Sleep 1 }
Check 'SCAN-5.4' 'the new scan runs with active checks (progress.json active=true)' $act "after ${i}s"
$tp = (Invoke-Page $a $B "/targets/$slow").b
Check 'SCAN-5.5' 'progress bar on the page shows Active checks' ($tp -match 'data-p="mode">Active checks')
Check 'SCAN-5.6' 'history records the passive scan as restarted' ($tp -match 'stopped: restarted with active checks')
Check 'SCAN-5.7' 'restart is audited' ((Invoke-Page $a $B '/audit').b -match 'running scan restarted with active checks')
$pl = Post $a "/targets/$slow/scan"
Check 'SCAN-5.8' 'plain Scan now while scanning says a scan is already running' ((Flash (Invoke-Page $a $B "/targets/$slow").b) -match 'already running')
$null = Post $a "/targets/$slow/pause"   # stop the 90s scan; tidy up

# --- SCAN-6: Confirm via active scan on exposed-service findings (new)
function FindingRow([string]$html, [string]$needle) {
    foreach ($row in ($html -split '<tr')) { if ($row -match [regex]::Escape($needle) -and $row -match '/findings/(\d+)/verify') { return $Matches[1] } }
}
$fp = (Invoke-Page $a $B '/findings').b
$smb = FindingRow $fp 'port 445'; $rdp = FindingRow $fp 'port 3389'; $ssh = FindingRow $fp 'port 3306'
Check 'SCAN-6.1' 'admin sees Confirm via active scan on exposed-service findings' ($smb -and $rdp -and $ssh) "445=$smb 3389=$rdp 3306=$ssh"
Check 'SCAN-6.2' 'unverified findings say where the evidence came from' ($fp -match 'Not verified by an active scan \(from Shodan InternetDB\)')
$anf = (Invoke-Page $an $B '/findings').b
Check 'SCAN-6.3' 'analyst sees the status but not the button' (($anf -match 'Not verified by an active scan') -and ($anf -notmatch 'Confirm via active scan'))
Check 'SCAN-6.4' 'analyst cannot run the check (403)' ((Post $an "/findings/$smb/verify").c -eq 403)
$v = Post $a "/findings/$smb/verify" @{ next = '/findings' }
$fp = (Invoke-Page $a $B '/findings').b
Check 'SCAN-6.5' 'SMB 445: verified open, no banner explained' (((Flash $fp) -match 'Confirmed:.*sent no banner') -and ($fp -match 'Verified open by active scan')) (Flash $fp)
$v = Post $a "/findings/$rdp/verify" @{ next = '/findings' }
$fp = (Invoke-Page $a $B '/findings').b
Check 'SCAN-6.6' 'RDP 3389: reported closed' (((Flash $fp) -match 'refused the connection') -and ($fp -match 'Active scan: port closed')) (Flash $fp)
$v = Post $a "/findings/$ssh/verify" @{ next = '/findings' }
$fp = (Invoke-Page $a $B '/findings').b
Check 'SCAN-6.7' 'MySQL 3306 on a network outside expected ownership: not contacted by default' ((Flash $fp) -match 'was not contacted') (Flash $fp)
$au = (Invoke-Page $a $B '/audit').b
Check 'SCAN-6.8' 'checks are audited with their result' (($au -match 'finding\.verify') -and ($au -match '203\.0\.113\.20:445'))

$script:Results | Export-Csv (OutPath 'scan-results.csv') -NoTypeInformation
"{0} passed, {1} failed" -f @($script:Results | Where-Object Result -eq 'PASS').Count, @($script:Results | Where-Object Result -eq 'FAIL').Count
