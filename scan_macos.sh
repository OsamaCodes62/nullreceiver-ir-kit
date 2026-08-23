#!/usr/bin/env bash
# =============================================================================
# NullReceiver infostealer — macOS SCAN + REMEDY  (share freely)
# DPRK "Contagious Interview" npm supply-chain RAT + Python infostealer.
# Detects durable IoCs and (optionally) quarantines them. C2 IP is DYNAMIC.
#
# Usage:
#   bash scan_macos.sh              # read-only scan (default)
#   bash scan_macos.sh --clean      # quarantine artifacts + kill procs (reversible)
#
# Quarantine = MOVE to a timestamped backup dir (never blind-delete).
# Exit: 0 clean / 1 indicators found.
# Test hooks (env): NR_HOME NR_TMP NR_IDE_EXTRA NR_QUARANTINE NR_NO_PROC NR_NO_NET
# =============================================================================
set -u

CLEAN=0
case "${1:-}" in
  --clean) CLEAN=1 ;;
  -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
  "") ;;
  *) echo "unknown arg: $1"; exit 2 ;;
esac

: "${NR_HOME:=$HOME}"
: "${NR_TMP:=${TMPDIR:-/tmp}}"
: "${NR_IDE_EXTRA:=}"
: "${NR_QUARANTINE:=$NR_HOME/nullreceiver_quarantine_$(date -u +%Y%m%d_%H%M%SZ)}"

FOUND=0
red(){ printf '\033[31m%s\033[0m\n' "$*"; }
grn(){ printf '\033[32m%s\033[0m\n' "$*"; }
ylw(){ printf '\033[33m%s\033[0m\n' "$*"; }
sect(){ printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
hit(){ FOUND=1; red "  [!] $*"; }
quarantine(){
  local src="$1"; [ -e "$src" ] || return 0
  if [ "$CLEAN" = 1 ]; then
    local dst="$NR_QUARANTINE/${src#/}"; mkdir -p "$(dirname "$dst")" 2>/dev/null
    if mv "$src" "$dst" 2>/dev/null; then ylw "      -> quarantined to $dst"
    else red "      -> FAILED (permission? sudo / grant Full Disk Access to Terminal): $src"; fi
  fi
}

# LONGEVITY — the operator rotates the cheap indicators freely:
#   DISPOSABLE (refresh from threat-intel; expect change): C2 IP, Telegram
#     token/bot/operator (7870147428, file_1018_bot, magicmeta, 7699029999).
#   COSTLIER TO ROTATE but STILL REPLACEABLE (refresh, don't trust forever):
#     dead-drop wallets, tag A9-2896-1 — changing the wallet forces the attacker
#     to update/redistribute the loader, but it remains a swappable IoC.
# DURABLE backbone = STRUCTURAL detection below (*.inz.cjs sidecars, @vscode/
# deviceid tamper, ~/.node_modules, get-pip.py, staging) — survives rotation.
C2_IP="166.88.134.62"                    # DISPOSABLE — one snapshot; expect rotation
STRINGS=(
  "A9-2896-1" ".inz.cjs" "file_1018_bot" "magicmeta" "7870147428" "7699029999"
  "/verify-human/" "/0x/clb" "/0x/cls" "Sec-V"
  "0xa322e5f3d311d3080e6f0121063e9adc2490ef1a"
  "0xa658863ea658863e68656c6c6f6970626f742121"
  "$C2_IP"
)
ARTIFACTS=(
  "$NR_HOME/.node_modules/node_modules"
  "$NR_TMP/get-pip.py" "$NR_TMP/.pip" "$NR_TMP/.npm" "/tmp/get-pip.py" "/tmp/.pip"
)
IDE_ROOTS=(
  "/Applications/Visual Studio Code.app/Contents/Resources/app"
  "/Applications/Cursor.app/Contents/Resources/app"
  "/Applications/Antigravity.app/Contents/Resources/app"
  "/Applications/GitHub Desktop.app/Contents/Resources/app"
  "$NR_HOME/Applications/Visual Studio Code.app/Contents/Resources/app"
  "$NR_HOME/Applications/Cursor.app/Contents/Resources/app"
  "$NR_HOME/.vscode" "$NR_HOME/.cursor"
)
IFS=':' read -r -a _extra <<< "$NR_IDE_EXTRA"; for e in "${_extra[@]:-}"; do [ -n "$e" ] && IDE_ROOTS+=("$e"); done
SCAN_DIRS=()
for d in Downloads Desktop Documents Projects projects src code repos work dev; do
  [ -d "$NR_HOME/$d" ] && SCAN_DIRS+=("$NR_HOME/$d")
done
SCAN_DIRS+=("$NR_TMP")

echo "NullReceiver macOS $( [ "$CLEAN" = 1 ] && echo REMEDY || echo scan ) — $(hostname 2>/dev/null) — $(date -u +%FT%TZ)"
[ "$CLEAN" = 1 ] && ylw "CLEAN mode: artifacts will be MOVED to $NR_QUARANTINE"

# ---- 1. Network -------------------------------------------------------------
if [ -z "${NR_NO_NET:-}" ]; then
  sect "Live connections to known C2 ($C2_IP — dynamic)"
  NET="$(lsof -nP -i 2>/dev/null | grep "$C2_IP" || true)"
  [ -z "$NET" ] && NET="$(netstat -an 2>/dev/null | grep "$C2_IP" || true)"
  if [ -n "$NET" ]; then
    hit "active C2 socket:"; echo "$NET"
    [ "$CLEAN" = 1 ] && ylw "      To block (dynamic IP — limited value): echo 'block drop out quick to $C2_IP' | sudo pfctl -ef -"
  else grn "  none"; fi
  grep -qs "$C2_IP" /etc/hosts && hit "C2 IP pinned in /etc/hosts"
fi

# ---- 2. Artifacts -----------------------------------------------------------
sect "Known malware artifacts"
A=0
for p in "${ARTIFACTS[@]}"; do [ -e "$p" ] && { hit "present: $p"; A=1; quarantine "$p"; }; done
for m in "$NR_TMP"/tmp[0-9A-Fa-f]*.tmp /tmp/tmp[0-9A-Fa-f]*.tmp; do
  [ -e "$m" ] && { hit "infostealer mutex lock: $m"; A=1; quarantine "$m"; }
done
[ "$A" = 0 ] && grn "  none"

# ---- 3. IDE injection -------------------------------------------------------
sect "IDE persistence injection (*.inz.cjs / @vscode/deviceid tamper)"
S=0
for root in "${IDE_ROOTS[@]}"; do
  [ -d "$root" ] || continue
  while IFS= read -r f; do hit "injected loader sidecar: $f"; S=1; quarantine "$f"; done \
    < <(find "$root" -type f -name '*.inz.cjs' 2>/dev/null)
  while IFS= read -r f; do
    grep -qsE "inz\.cjs|$C2_IP|A9-2896-1|/verify-human/" "$f" && { hit "tampered IDE file: $f"; S=1; quarantine "$f"; }
  done < <(find "$root" -type f \( -path '*@vscode/deviceid/dist/index.js' -o -name 'main.js' \) 2>/dev/null | head -80)
done
[ "$S" = 0 ] && grn "  no IDE injection markers" || { [ "$CLEAN" = 1 ] && ylw "  ACTION: delete the .app and reinstall the editor from the vendor (code-signed) — do not just patch."; }

# ---- 4. String sweep (report only) -----------------------------------------
sect "IoC string sweep (${#SCAN_DIRS[@]} dev locations, report only)"
PAT="$(IFS='|'; echo "${STRINGS[*]}")"
SW=0
for d in "${SCAN_DIRS[@]}"; do
  [ -d "$d" ] || continue
  while IFS= read -r f; do hit "IoC string in: $f"; SW=1; done \
    < <(grep -rlIE --exclude-dir='.git' -- "$PAT" "$d" 2>/dev/null | head -100)
done
[ "$SW" = 0 ] && grn "  no IoC strings found"

# ---- 5. Persistence (LaunchAgents/Daemons + shell rc) ----------------------
sect "Persistence (LaunchAgents / LaunchDaemons / shell rc)"
P=0
for d in "$NR_HOME/Library/LaunchAgents" "/Library/LaunchAgents" "/Library/LaunchDaemons"; do
  for pl in "$d"/*.plist; do
    [ -f "$pl" ] || continue
    grep -qsE '\.node_modules|/tmp/get-pip|166\.88\.134\.62|verify-human' "$pl" && { hit "malicious launch item: $pl"; P=1; quarantine "$pl"; }
  done
done
for rc in "$NR_HOME/.zshrc" "$NR_HOME/.bash_profile" "$NR_HOME/.profile" "$NR_HOME/.bashrc"; do
  [ -f "$rc" ] && grep -nE '\.node_modules|166\.88\.134\.62|/tmp/get-pip' "$rc" 2>/dev/null && { hit "suspicious line in $rc (review manually)"; P=1; }
done
[ "$P" = 0 ] && grn "  no persistence markers"

# ---- 6. Processes -----------------------------------------------------------
if [ -z "${NR_NO_PROC:-}" ]; then
  sect "Running processes matching malware pattern"
  MATCH="$(ps -eo pid,command 2>/dev/null | grep -iE '\.node_modules|/tmp/get-pip|/tmp/\.pip' | grep -v grep || true)"
  if [ -n "$MATCH" ]; then
    hit "suspicious processes:"; echo "$MATCH"
    [ "$CLEAN" = 1 ] && echo "$MATCH" | awk '{print $1}' | while read -r pid; do kill -9 "$pid" 2>/dev/null && ylw "      -> killed pid $pid"; done
  else grn "  none"; fi
fi

echo
if [ "$FOUND" = 1 ]; then
  red "RESULT: INDICATORS FOUND — treat this Mac as COMPROMISED."
  ylw "NEXT (see README.md): 1) disconnect network  2) $( [ "$CLEAN" = 1 ] && echo 'quarantine done' || echo 'rerun with --clean' )"
  ylw "  3) ROTATE ALL credentials from a CLEAN device  4) MOVE CRYPTO to new wallets/seeds"
  ylw "  5) reinstall flagged editors  6) also rotate anything in Keychain the stealer could read"
  exit 1
else
  grn "RESULT: no NullReceiver indicators in scanned scope."
  ylw "Targeted hunt, not a full AV. If you executed the sample, rotate creds regardless."
  exit 0
fi
