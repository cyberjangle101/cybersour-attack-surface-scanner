# UAT for v1.9.5 corroboration (two sources before a finding is trusted), against the acme-corp.test lab.
# Run after uat-evidence.ps1 on the same lab instance: it reuses that script's accounts and first scan.
. "$PSScriptRoot\lib.ps1"
$B = 'http://127.0.0.1:18100'
$pw = ((Get-Content (OutPath 'evidence-credentials.txt')) -split ' / ')[1].Trim()
function Flash([string]$html) { ([regex]::Match($html, '(?s)class="flash[^"]*"[^>]*>(.*?)</div>').Groups[1].Value -replace '<[^>]+>', '').Trim() }
function Row([string]$html, [string]$needle) { foreach ($row in ($html -split '<tr')) { if ($row -match [regex]::Escape($needle)) { return $row } } }
function Post($s, [string]$path, [hashtable]$extra = @{}) { $pg = Invoke-Page $s $B '/'; $f = @{ csrf = (Get-Csrf $pg.b) }; foreach ($k in $extra.Keys) { $f[$k] = $extra[$k] }; Invoke-Page $s $B $path $f }

$a = Connect-Agent $B 'uatadmin' $pw
$vw = Connect-Agent $B 'uatviewer' "${pw}vw"
$f = (Invoke-Page $a $B '/findings').b
$smb = Row $f 'SMB (port 445)'; $rdp = Row $f 'RDP (port 3389)'; $my = Row $f 'MySQL (port 3306)'; $cv = Row $f 'CVE-2019-0708'
Check 'TR-1.1' 'SMB 445: InternetDB + active check agree, so Trusted' (($smb -match '>Trusted<') -and ($smb -match 'Shodan, Active check agree'))
Check 'TR-1.2' 'RDP 3389: only InternetDB and the port refused, so Disputed' (($rdp -match '>Disputed<') -and ($rdp -match 'own check got no connection'))
Check 'TR-1.3' 'MySQL 3306 outside ownership: not contacted, Unconfirmed' (($my -match '>Unconfirmed<') -and ($my -match 'only Shodan'))
Check 'TR-1.4' 'CVE list from InternetDB alone: Unconfirmed' ($cv -match '>Unconfirmed<')
$d = (Invoke-Page $a $B '/').b
$n = if ($d -match '\+ (\d+) unconfirmed') { [int]$Matches[1] } else { 0 }
Check 'TR-1.5' 'dashboard shows unconfirmed findings separately' ($n -ge 3) "$n unconfirmed"
$uf = (Invoke-Page $a $B '/findings?trust=unconfirmed').b
Check 'TR-1.6' 'Corroboration filter: unconfirmed view lists the CVE, not the trusted SMB finding' (($uf -match 'CVE-2019-0708') -and ($uf -notmatch 'SMB \(port 445\)'))
$tf = (Invoke-Page $a $B '/findings?trust=trusted').b
Check 'TR-1.7' 'Corroboration filter: trusted view lists SMB, not the CVE' (($tf -match 'SMB \(port 445\)') -and ($tf -notmatch 'CVE-2019-0708'))
$sid = if ($smb -match '/findings/(\d+)/evidence') { $Matches[1] }
$ev = (Invoke-Page $a $B "/findings/$sid/evidence").b
Check 'TR-1.8' 'evidence page explains the corroboration' (($ev -match 'Corroboration') -and ($ev -match 'two independent sources'))

# --- TR-2: analyst confirmation
$cid = if ($cv -match '/findings/(\d+)/evidence') { $Matches[1] }
$r = Post $vw "/findings/$cid/confirm" @{ note = 'viewer trying to confirm this finding' }
$after = Row (Invoke-Page $a $B '/findings').b 'CVE-2019-0708'
Check 'TR-2.1' 'viewer cannot confirm a finding' (($r.c -ne 303) -and ($after -match '>Unconfirmed<')) "HTTP $($r.c)"
$null = Post $a "/findings/$cid/confirm" @{ note = 'short' }
$pg = (Invoke-Page $a $B '/findings').b
Check 'TR-2.2' 'confirmation needs a note saying how' (((Flash $pg) -match 'Say how you confirmed it') -and ((Row $pg 'CVE-2019-0708') -match '>Unconfirmed<')) (Flash $pg)
$r = Post $a "/findings/$cid/confirm" @{ note = 'RDP service build checked on the host: unpatched for BlueKeep' }
$cv2 = Row (Invoke-Page $a $B '/findings').b 'CVE-2019-0708'
Check 'TR-2.3' 'analyst confirmation makes the CVE finding Trusted' (($cv2 -match '>Trusted<') -and ($cv2 -match 'Analyst \(uatadmin\)')) (Flash $r.b)
$au = (Invoke-Page $a $B '/audit').b
Check 'TR-2.4' 'confirmation is audited with the note' (($au -match 'finding\.confirm') -and ($au -match 'unpatched for BlueKeep'))
$d2 = (Invoke-Page $a $B '/').b
$n2 = if ($d2 -match '\+ (\d+) unconfirmed') { [int]$Matches[1] } else { 0 }
Check 'TR-2.5' 'a confirmed finding moves into the counted findings' ($n2 -eq $n - 1) "$n -> $n2"
$r = Post $a "/findings/$cid/confirm" @{ action = 'remove' }
$cv3 = Row (Invoke-Page $a $B '/findings').b 'CVE-2019-0708'
Check 'TR-2.6' 'confirmation can be removed' ($cv3 -match '>Unconfirmed<') (Flash $r.b)
$au2 = (Invoke-Page $a $B '/audit').b
Check 'TR-2.7' 'removal is audited' ($au2 -match 'finding\.unconfirm')

$script:Results | Export-Csv (OutPath 'trust-results.csv') -NoTypeInformation
"{0} passed, {1} failed" -f @($script:Results | Where-Object Result -eq 'PASS').Count, @($script:Results | Where-Object Result -eq 'FAIL').Count
