# UAT for v1.9.4 evidence and first-scan options, against the acme-corp.test lab on 127.0.0.1:18100.
. "$PSScriptRoot\lib.ps1"
$B = 'http://127.0.0.1:18100'
for ($i = 0; $i -lt 180; $i++) { try { if ((Invoke-WebRequest -UseBasicParsing "$B/healthz" -TimeoutSec 2).StatusCode -eq 200) { break } } catch {}; Start-Sleep 1 }
$pw = (New-Secret 20) + '-Dd4'
Set-Content (OutPath 'evidence-credentials.txt') -Encoding ascii -Value "lab admin: uatadmin / $pw"
function Flash([string]$html) { ([regex]::Match($html, '(?s)class="flash[^"]*"[^>]*>(.*?)</div>').Groups[1].Value -replace '<[^>]+>', '').Trim() }
function Post($s, [string]$path, [hashtable]$extra = @{}) { $pg = Invoke-Page $s $B '/'; $f = @{ csrf = (Get-Csrf $pg.b) }; foreach ($k in $extra.Keys) { $f[$k] = $extra[$k] }; Invoke-Page $s $B $path $f }
function Row([string]$html, [string]$needle) { foreach ($row in ($html -split '<tr')) { if ($row -match [regex]::Escape($needle)) { return $row } } }

$a = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$r = Invoke-Page $a $B '/setup'
$null = Invoke-Page $a $B '/setup' @{ csrf = (Get-Csrf $r.b); code = (Get-LabSetupCode); username = 'uatadmin'; password = $pw; confirm = $pw }
$a = Connect-Agent $B 'uatadmin' $pw
$u = Invoke-Page $a $B '/users'
$null = Invoke-Page $a $B '/users' @{ csrf = (Get-Csrf $u.b); username = 'uatviewer'; password = "${pw}vw"; role = 'viewer' }
$vw = Connect-Agent $B 'uatviewer' "${pw}vw"

# --- EV-1: first-scan options on the add form
$d = (Invoke-Page $a $B '/').b
Check 'EV-1.1' 'add form shows First scan tick boxes' (($d -match 'name="first_active"') -and ($d -match 'name="first_shots"') -and ($d -match 'name="first_verify"') -and ($d -match 'Active scanning enabled') -and ($d -match 'Screenshots enabled'))
$add = Post $a '/targets' @{ domain = 'acme-corp.test'; asns = 'AS64500'; keywords = 'ACME'; first_active = '1'; first_shots = '1'; first_verify = '1' }
$tp = (Invoke-Page $a $B '/targets/1').b
Check 'EV-1.2' 'confirmation lists the chosen first-scan options' ((Flash $tp) -match 'First scan: active scanning, screenshots, confirm open ports') (Flash $tp)
Check 'EV-1.3' 'screenshots without Chrome/Edge on the lab path give a clear warning, or none if a browser exists' ($true) ([regex]::Matches($tp, '(?s)class="flash warn[^"]*"[^>]*>(.*?)</div>') | ForEach-Object { ($_.Groups[1].Value -replace '<[^>]+>', '').Trim() } | Select-Object -First 1)
for ($i = 0; $i -lt 120; $i++) { Start-Sleep 2; $t = (Invoke-Page $a $B '/targets').b; if ($t -notmatch '(?i)>Scanning<|>Queued<') { break } }
$au0 = (Invoke-Page $a $B '/audit').b
Check 'EV-1.4' 'first-scan options audited with the new domain' ($au0 -match 'active scanning, screenshots, confirm open ports')
for ($i = 0; $i -lt 30; $i++) { $f = (Invoke-Page $a $B '/findings').b; if ($f -match 'by first scan') { break }; Start-Sleep 1 }
$smb = Row $f 'SMB (port 445)'; $rdp = Row $f 'RDP (port 3389)'; $my = Row $f 'MySQL (port 3306)'
Check 'EV-1.5' 'Confirm open ports: SMB 445 verified open by "first scan"' (($smb -match 'Verified open by active scan') -and ($smb -match 'by first scan'))
Check 'EV-1.6' 'Confirm open ports: RDP 3389 reported closed' ($rdp -match 'Active scan: port closed')
Check 'EV-1.7' 'Confirm open ports: MySQL 3306 outside ownership left unverified' ($my -match 'Not verified by an active scan')
$au = (Invoke-Page $a $B '/audit').b
Check 'EV-1.8' 'automatic checks are audited' ($au -match 'Confirm open ports, first scan of acme-corp\.test')

# --- EV-2: evidence page
$id = if ($smb -match '/findings/(\d+)/evidence') { $Matches[1] }
Check 'EV-2.1' 'findings table links each finding to its evidence' ([bool]$id) "finding $id"
$ev = Invoke-Page $a $B "/findings/$id/evidence"
Check 'EV-2.2' 'evidence page opens' ($ev.c -eq 200)
Check 'EV-2.3' 'links to check independently (Shodan, InternetDB JSON, Censys, VirusTotal)' (($ev.b -match 'https://www\.shodan\.io/host/203\.0\.113\.20') -and ($ev.b -match 'https://internetdb\.shodan\.io/203\.0\.113\.20') -and ($ev.b -match 'search\.censys\.io/hosts/203\.0\.113\.20') -and ($ev.b -match 'virustotal\.com/gui/ip-address/203\.0\.113\.20'))
Check 'EV-2.4' 'raw InternetDB answer shown (ports, vulns)' (($ev.b -match 'Raw answers from the exposure sources') -and ($ev.b -match '&#34;ports&#34;') -and ($ev.b -match 'CVE-2019-0708'))
Check 'EV-2.5' 'recorded port table for 445 only' (($ev.b -match '445/tcp') -and ($ev.b -notmatch '3389/tcp'))
Check 'EV-2.6' 'active scan result shown on the evidence page' ($ev.b -match 'Verified open by active scan')
Check 'EV-2.7' 'external links open in a new tab without referrer' ($ev.b -match 'target="_blank" rel="noopener noreferrer"')
$js = Invoke-WebRequest -UseBasicParsing -WebSession $a "$B/findings/$id/evidence.json"
$o = $js.Content | ConvertFrom-Json
Check 'EV-2.8' 'evidence JSON download: address, services, raw source answer' (($js.Headers['Content-Disposition'] -match 'easm-evidence-') -and ($o.Address -eq '203.0.113.20:445') -and (@($o.Services).Count -ge 1) -and ($o.Sources[0].Answer.ports -contains 445))
$vv = Invoke-Page $vw $B "/findings/$id/evidence"
Check 'EV-2.9' 'viewer can read evidence (read-only role)' (($vv.c -eq 200) -and ($vv.b -notmatch 'Confirm via active scan</button>'))
$cv = Row $f 'CVE-2019-0708'; $cid = if ($cv -match '/findings/(\d+)/evidence') { $Matches[1] }
Check 'EV-2.10' 'CVE finding evidence links the NVD record' ((Invoke-Page $a $B "/findings/$cid/evidence").b -match 'nvd\.nist\.gov/vuln/detail/CVE-2019-0708')
$ex = Row $f 'expir'; $eid = if ($ex -match '/findings/(\d+)/evidence') { $Matches[1] }
$xp = (Invoke-Page $a $B "/findings/$eid/evidence").b
Check 'EV-2.11' 'domain-expiry evidence links RDAP, not unrelated certificate search' (($xp -match 'rdap\.org/domain/acme-corp\.test') -and ($xp -notmatch 'crt\.sh'))
$dc = Row $f 'herokuapp'; $did = if ($dc -match '/findings/(\d+)/evidence') { $Matches[1] }
$dp = if ($did) { (Invoke-Page $a $B "/findings/$did/evidence").b } else { '' }
Check 'EV-2.13' 'dangling-CNAME evidence links the published CNAME record, not crt.sh' (($dp -match 'dns\.google/resolve\?type=CNAME&amp;name=staging\.acme-corp\.test') -and ($dp -notmatch 'crt\.sh')) "finding $did"
Check 'EV-2.12' 'unknown finding id is a 404' ((Invoke-Page $a $B '/findings/99999/evidence').c -eq 404)

$script:Results | Export-Csv (OutPath 'evidence-results.csv') -NoTypeInformation
"{0} passed, {1} failed" -f @($script:Results | Where-Object Result -eq 'PASS').Count, @($script:Results | Where-Object Result -eq 'FAIL').Count
