# Self-test for scan_windows.ps1. Builds a SYNTHETIC (fake) infected tree — no
# real malware — and asserts detection + quarantine + source preservation +
# no-false-positive on a clean tree, via -HomeOverride.
#
# NOTE: this exercises the CROSS-PLATFORM file-detection/quarantine logic (so it
# can run under PowerShell on Linux/macOS/Windows). The Windows-ONLY sections of
# scan_windows.ps1 (Get-NetTCPConnection, New-NetFirewallRule, registry Run keys,
# Get-ScheduledTask, Win32_Process) are inert off Windows and must be verified on
# a real Windows host.
$ErrorActionPreference = 'Stop'
$scan = Join-Path $PSScriptRoot 'scan_windows.ps1'
$pass = 0; $fail = 0
function Ok($m){ $script:pass++; Write-Host "  PASS $m" -ForegroundColor Green }
function Bad($m){ $script:fail++; Write-Host "  FAIL $m" -ForegroundColor Red }
function Has($s,$p){ return ($s -like "*$p*") }

function New-Infected($H){
  New-Item -ItemType Directory -Force -Path `
    "$H/.node_modules/node_modules/ws", "$H/Temp/.pip", "$H/Temp/.npm",
    "$H/ide/resources/app/node_modules/@vscode/deviceid/dist",
    "$H/ide/gh/resources/app", "$H/Projects" | Out-Null
  Set-Content "$H/Temp/get-pip.py" ''
  Set-Content "$H/Temp/tmpDEADBEEF12.tmp" ''
  Set-Content "$H/ide/resources/app/node_modules/@vscode/deviceid/dist/index.js"      "module.exports=require('./index.inz.cjs'); // 166.88.134.62"
  Set-Content "$H/ide/resources/app/node_modules/@vscode/deviceid/dist/index.inz.cjs" "fetch('http://x/verify-human/A9-2896-1')"
  Set-Content "$H/ide/gh/resources/app/main.js"                                        "// tampered entry A9-2896-1"
  Set-Content "$H/Projects/evil.js"  "const c2='166.88.134.62' // magicmeta"
  Set-Content "$H/Projects/legit.js" "clean project file"
}
function New-Clean($H){
  New-Item -ItemType Directory -Force -Path "$H/Projects","$H/Temp","$H/ide" | Out-Null
  Set-Content "$H/Projects/app.js" "hello world"
}
function Run-Scan($H, [switch]$DoClean){
  if ($DoClean) { $o = & pwsh -NoProfile -File $scan -Clean -HomeOverride $H 2>&1 | Out-String }
  else          { $o = & pwsh -NoProfile -File $scan       -HomeOverride $H 2>&1 | Out-String }
  return @{ Out = $o; Rc = $LASTEXITCODE }
}

$work = Join-Path ([System.IO.Path]::GetTempPath()) ("nrwin_" + [guid]::NewGuid().ToString('N'))

Write-Host "### scan_windows.ps1 - parse"
try { [System.Management.Automation.Language.Parser]::ParseFile($scan,[ref]$null,[ref]$null) | Out-Null; Ok "parses" }
catch { Bad "parse error: $_" }

Write-Host "### scan_windows.ps1 - DETECT (scan on infected tree)"
$inf = Join-Path $work 'inf'; New-Infected $inf
$r = Run-Scan $inf
if ($r.Rc -eq 1) { Ok "exit 1 on infection" } else { Bad "expected exit 1, got $($r.Rc)" }
if (Has $r.Out 'injected loader sidecar') { Ok "detect .inz.cjs sidecar" } else { Bad "missed sidecar" }
if (Has $r.Out 'tampered IDE file')       { Ok "detect deviceid/main.js tamper" } else { Bad "missed IDE tamper" }
if (Has $r.Out 'node_modules')            { Ok "detect runtime RAT deps dir" } else { Bad "missed .node_modules" }
if (Has $r.Out 'get-pip.py')              { Ok "detect get-pip.py artifact" } else { Bad "missed get-pip.py" }
if (Has $r.Out 'mutex lock')              { Ok "detect mutex .tmp lock" } else { Bad "missed mutex" }
if (Has $r.Out 'evil.js')                 { Ok "detect IoC string in source" } else { Bad "missed string sweep" }

Write-Host "### scan_windows.ps1 - REMEDY (-Clean quarantines, preserves source)"
$inf2 = Join-Path $work 'inf2'; New-Infected $inf2
$r = Run-Scan $inf2 -DoClean
if ($r.Rc -eq 1) { Ok "exit 1 (found+cleaned)" } else { Bad "expected exit 1, got $($r.Rc)" }
if (-not (Test-Path "$inf2/.node_modules/node_modules")) { Ok "RAT deps quarantined" } else { Bad "RAT deps NOT moved" }
if (-not (Test-Path "$inf2/Temp/get-pip.py")) { Ok "get-pip.py quarantined" } else { Bad "get-pip.py NOT moved" }
if (-not (Test-Path "$inf2/ide/resources/app/node_modules/@vscode/deviceid/dist/index.inz.cjs")) { Ok "sidecar quarantined" } else { Bad "sidecar NOT moved" }
if (Get-ChildItem -Path $inf2 -Directory -Filter 'nullreceiver_quarantine_*' 2>$null) { Ok "quarantine dir created" } else { Bad "no quarantine dir" }
if (Test-Path "$inf2/Projects/evil.js")  { Ok "source file PRESERVED (string sweep is report-only)" } else { Bad "DESTROYED user source!" }
if (Test-Path "$inf2/Projects/legit.js") { Ok "unrelated file untouched" } else { Bad "touched unrelated file" }

Write-Host "### scan_windows.ps1 - CLEAN tree (no false positives)"
$cln = Join-Path $work 'cln'; New-Clean $cln
$r = Run-Scan $cln
if ($r.Rc -eq 0) { Ok "exit 0 on clean tree" } else { Bad "false positive (exit $($r.Rc))" }
if (Has $r.Out 'no NullReceiver indicators') { Ok "reports clean" } else { Bad "did not report clean" }

Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
Write-Host "======================================================"
Write-Host ("RESULT: {0} passed, {1} failed" -f $pass,$fail)
if ($fail -eq 0) { Write-Host "ALL WINDOWS-LOGIC TESTS PASSED" -ForegroundColor Green; exit 0 }
else { Write-Host "SOME TESTS FAILED" -ForegroundColor Red; exit 1 }
