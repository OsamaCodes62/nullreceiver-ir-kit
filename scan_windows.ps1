<#
=============================================================================
 NullReceiver infostealer - Windows SCAN + REMEDY  (share freely)
 DPRK "Contagious Interview" npm supply-chain RAT + Python infostealer.
 Detects durable IoCs and (optionally) quarantines them. C2 IP is DYNAMIC.

 Usage (PowerShell):
   powershell -ExecutionPolicy Bypass -File .\scan_windows.ps1           # scan only
   powershell -ExecutionPolicy Bypass -File .\scan_windows.ps1 -Clean    # quarantine + kill + block IP
   Run elevated (Admin) for the -Clean firewall rule and all-user coverage.

 Quarantine = MOVE to a timestamped backup dir (never blind-delete).
 Exit: 0 clean / 1 indicators found.
 Test hook: -HomeOverride <path> scopes user paths to a fixture.
=============================================================================
#>
[CmdletBinding()]
param(
  [switch]$Clean,
  [string]$HomeOverride
)
$ErrorActionPreference = 'SilentlyContinue'
$script:Found = $false

$UserRoot = if ($HomeOverride) { $HomeOverride } else { $env:USERPROFILE }
$TempRoot = if ($HomeOverride) { Join-Path $HomeOverride 'Temp' } else { $env:TEMP }
$Quar     = Join-Path $UserRoot ("nullreceiver_quarantine_{0}" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

function Sect($t){ Write-Host "`n== $t ==" -ForegroundColor White }
function Hit($t){ $script:Found=$true; Write-Host "  [!] $t" -ForegroundColor Red }
function Ok($t){ Write-Host "  $t" -ForegroundColor Green }
function Warn($t){ Write-Host "  $t" -ForegroundColor Yellow }
function Quarantine($p){
  if (-not (Test-Path -LiteralPath $p)) { return }
  if ($Clean) {
    $dst = Join-Path $Quar ($p -replace '^[A-Za-z]:','' -replace '[:\\/]','_')
    New-Item -ItemType Directory -Force -Path (Split-Path $dst) | Out-Null
    try { Move-Item -LiteralPath $p -Destination $dst -Force; Warn "      -> quarantined to $dst" }
    catch { Write-Host "      -> FAILED (run as Admin): $p" -ForegroundColor Red }
  }
}

# LONGEVITY - the operator rotates the cheap indicators freely:
#   DISPOSABLE (refresh from threat-intel; expect change): C2 IP, Telegram
#     token/bot/operator (7870147428, file_1018_bot, magicmeta, 7699029999).
#   COSTLIER TO ROTATE but STILL REPLACEABLE (refresh, don't trust forever):
#     dead-drop wallets, tag A9-2896-1 - changing the wallet forces the attacker
#     to update/redistribute the loader, but it remains a swappable IoC.
# DURABLE backbone = STRUCTURAL detection below (*.inz.cjs sidecars, @vscode/
# deviceid tamper, .node_modules, get-pip.py, staging) - survives rotation.
$C2_IP = '166.88.134.62'   # DISPOSABLE - one snapshot; expect rotation
$Strings = @('A9-2896-1','.inz.cjs','file_1018_bot','magicmeta','7870147428','7699029999',
  '/verify-human/','/0x/clb','/0x/cls','Sec-V',
  '0xa322e5f3d311d3080e6f0121063e9adc2490ef1a','0xa658863ea658863e68656c6c6f6970626f742121',$C2_IP)
$StrRegex = ($Strings | ForEach-Object { [regex]::Escape($_) }) -join '|'

$Artifacts = @(
  (Join-Path (Join-Path $UserRoot '.node_modules') 'node_modules'),
  (Join-Path $TempRoot 'get-pip.py'),
  (Join-Path $TempRoot '.pip'),
  (Join-Path $TempRoot '.npm')
)
$IdeRoots = @(
  (Join-Path $env:LOCALAPPDATA 'Programs\Microsoft VS Code\resources\app'),
  (Join-Path $env:LOCALAPPDATA 'Programs\cursor\resources\app'),
  (Join-Path $env:LOCALAPPDATA 'Programs\Antigravity\resources\app'),
  'C:\Program Files\Microsoft VS Code\resources\app',
  (Join-Path $env:LOCALAPPDATA 'GitHubDesktop')
)
if ($HomeOverride) { $IdeRoots += (Join-Path $HomeOverride 'ide') }
$ScanDirs = @('Downloads','Desktop','Documents','Projects','source','repos','code','work','dev') |
  ForEach-Object { Join-Path $UserRoot $_ } | Where-Object { Test-Path $_ }
$ScanDirs += $TempRoot

Write-Host ("NullReceiver Windows {0} - {1} - {2}" -f ($(if($Clean){'REMEDY'}else{'scan'})),$env:COMPUTERNAME,(Get-Date -Format s))
if ($Clean) { Warn "CLEAN mode: artifacts will be MOVED to $Quar" }

# 1. Network
Sect "Live connections to known C2 ($C2_IP - dynamic)"
$conns = Get-NetTCPConnection -RemoteAddress $C2_IP 2>$null
if (-not $conns) { $conns = (netstat -ano | Select-String $C2_IP) }
if ($conns) {
  Hit "active C2 connection:"; $conns | Out-String | Write-Host
  if ($Clean) {
    try { New-NetFirewallRule -DisplayName "Block NullReceiver C2 $C2_IP" -Direction Outbound -RemoteAddress $C2_IP -Action Block | Out-Null; Warn "      -> outbound firewall block added for $C2_IP (dynamic IP; blocks one address)" }
    catch { Warn "      run elevated to add firewall rule, or: New-NetFirewallRule -DisplayName BlockNR -Direction Outbound -RemoteAddress $C2_IP -Action Block" }
  }
} else { Ok "none" }

# 2. Artifacts
Sect "Known malware artifacts"
$a=$false
foreach($p in $Artifacts){ if (Test-Path -LiteralPath $p){ Hit "present: $p"; $a=$true; Quarantine $p } }
Get-ChildItem -LiteralPath $TempRoot -Filter 'tmp*.tmp' -File 2>$null |
  Where-Object { $_.BaseName -match '^tmp[0-9A-Fa-f]{6,}$' } |
  ForEach-Object { Hit "infostealer mutex lock: $($_.FullName)"; $a=$true; Quarantine $_.FullName }
if (-not $a) { Ok "none" }

# 3. IDE injection
Sect "IDE persistence injection (*.inz.cjs / @vscode/deviceid tamper)"
$s=$false
foreach($root in $IdeRoots){
  if (-not (Test-Path $root)) { continue }
  Get-ChildItem -Path $root -Recurse -Filter '*.inz.cjs' -File 2>$null | ForEach-Object {
    Hit "injected loader sidecar: $($_.FullName)"; $s=$true; Quarantine $_.FullName }
  Get-ChildItem -Path $root -Recurse -File -Include 'index.js','main.js' 2>$null |
    Where-Object { ($_.FullName -match 'deviceid') -or ($_.Name -eq 'main.js') } |
    ForEach-Object {
      if (Select-String -LiteralPath $_.FullName -Pattern 'inz\.cjs',$C2_IP,'A9-2896-1','/verify-human/' -Quiet 2>$null) {
        Hit "tampered IDE file: $($_.FullName)"; $s=$true; Quarantine $_.FullName } }
}
if (-not $s) { Ok "no IDE injection markers" } elseif ($Clean) { Warn "  ACTION: uninstall & reinstall the editor from the vendor - do not just patch." }

# 4. String sweep (report only)
Sect "IoC string sweep (report only)"
$sw=$false
foreach($d in $ScanDirs){
  if (-not (Test-Path $d)) { continue }
  Get-ChildItem -Path $d -Recurse -File 2>$null | Where-Object { $_.Length -lt 5MB } |
    Select-String -Pattern $StrRegex -List 2>$null | ForEach-Object {
      Hit "IoC string in: $($_.Path)"; $sw=$true }
}
if (-not $sw) { Ok "no IoC strings found" }

# 5. Persistence
Sect "Persistence (Run keys / Startup / Scheduled Tasks)"
$p=$false
foreach($k in 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'){
  $vals = Get-ItemProperty -Path $k 2>$null
  if ($vals) { $vals.PSObject.Properties | Where-Object { $_.Value -match '\.node_modules|get-pip|166\.88\.134\.62|node .*\.js' } |
    ForEach-Object { Hit "Run key: $k\$($_.Name) = $($_.Value)"; $p=$true } }
}
$startup = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup'
Get-ChildItem $startup -File 2>$null | Where-Object { Select-String -LiteralPath $_.FullName -Pattern '\.node_modules','get-pip',$C2_IP -Quiet 2>$null } |
  ForEach-Object { Hit "startup item: $($_.FullName)"; $p=$true; Quarantine $_.FullName }
Get-ScheduledTask 2>$null | ForEach-Object {
  $act = ($_.Actions | Out-String)
  if ($act -match '\.node_modules|get-pip|166\.88\.134\.62') { Hit "scheduled task: $($_.TaskName)"; $p=$true } }
if (-not $p) { Ok "no persistence markers" }

# 6. Processes
Sect "Running processes matching malware pattern"
$procs = Get-CimInstance Win32_Process 2>$null | Where-Object { $_.CommandLine -match '\.node_modules|get-pip|\\.pip' }
if ($procs) {
  $procs | ForEach-Object { Hit "pid $($_.ProcessId): $($_.CommandLine)"; if ($Clean) { Stop-Process -Id $_.ProcessId -Force 2>$null; Warn "      -> killed pid $($_.ProcessId)" } }
} else { Ok "none" }

Write-Host ""
if ($script:Found) {
  Write-Host "RESULT: INDICATORS FOUND - treat this PC as COMPROMISED." -ForegroundColor Red
  Warn ("NEXT (see README.md): 1) disconnect network  2) {0}" -f ($(if($Clean){'quarantine done'}else{'rerun with -Clean'}))
  Warn "  3) ROTATE ALL credentials from a CLEAN device  4) MOVE CRYPTO to new wallets/seeds"
  Warn "  5) reinstall flagged editors  6) sign out & revoke browser + cloud sessions"
  exit 1
} else {
  Write-Host "RESULT: no NullReceiver indicators in scanned scope." -ForegroundColor Green
  Warn "Targeted hunt, not a full AV. If you executed the sample, rotate creds regardless."
  exit 0
}
