#!/usr/bin/env bash
# =============================================================================
# NullReceiver infostealer — Linux SCAN + REMEDY  (share freely)
# DPRK "Contagious Interview" npm supply-chain RAT + Python infostealer.
# Detects the durable IoCs recovered during controlled analysis and (optionally)
# quarantines them. The C2 IP is DYNAMIC — detection leans on file/behavioural
# indicators, not the IP.
#
# Usage:
#   bash scan_linux.sh              # read-only scan (default) — changes nothing
#   bash scan_linux.sh --clean      # quarantine artifacts, kill procs (reversible)
#   sudo bash scan_linux.sh --clean # also blocks current C2 IP + covers all users
#
# Quarantine = MOVE to a timestamped backup dir (never blind-delete), so a
# false positive can be restored. Exit: 0 clean / 1 indicators found.
#
# Test hooks (env, default to production values): NR_HOME NR_TMP NR_IDE_EXTRA
# NR_QUARANTINE NR_NO_PROC NR_NO_NET
# =============================================================================
set -u

# ---- mode -------------------------------------------------------------------
CLEAN=0
case "${1:-}" in
  --clean) CLEAN=1 ;;
  -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
  "") ;;
  *) echo "unknown arg: $1 (use --clean or --help)"; exit 2 ;;
esac

: "${NR_HOME:=$HOME}"
: "${NR_TMP:=/tmp}"
: "${NR_IDE_EXTRA:=}"                    # colon-separated extra IDE roots (tests)
: "${NR_QUARANTINE:=$NR_HOME/nullreceiver_quarantine_$(date -u +%Y%m%d_%H%M%SZ)}"

FOUND=0
red(){ printf '\033[31m%s\033[0m\n' "$*"; }
grn(){ printf '\033[32m%s\033[0m\n' "$*"; }
ylw(){ printf '\033[33m%s\033[0m\n' "$*"; }
sect(){ printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
hit(){ FOUND=1; red "  [!] $*"; }

quarantine(){ # $1 = path to move
  local src="$1"
  [ -e "$src" ] || return 0
  if [ "$CLEAN" = 1 ]; then
    local dst="$NR_QUARANTINE/${src#/}"
    mkdir -p "$(dirname "$dst")" 2>/dev/null
    if mv "$src" "$dst" 2>/dev/null; then ylw "      -> quarantined to $dst"
    else red "      -> FAILED to quarantine (permission? rerun with sudo): $src"; fi
  fi
}

# ---- IoCs -------------------------------------------------------------------
# LONGEVITY — the operator rotates the cheap indicators freely:
#   DISPOSABLE (refresh from threat-intel; expect change): C2 IP, Telegram
#     token/bot/operator (7870147428, file_1018_bot, magicmeta, 7699029999).
#   COSTLIER TO ROTATE but STILL REPLACEABLE (refresh, don't trust forever):
#     dead-drop wallets, tag A9-2896-1 — changing the wallet forces the attacker
#     to update/redistribute the loader, but it remains a swappable IoC.
# The DURABLE backbone is the STRUCTURAL detection below (*.inz.cjs sidecars,
# @vscode/deviceid tamper, ~/.node_modules, get-pip.py, staging, process chain) —
# those survive IP/token rotation. Do NOT rely on the strings alone.
C2_IP="166.88.134.62"                    # DISPOSABLE — one snapshot; expect rotation
STRINGS=(
  "A9-2896-1" ".inz.cjs" "file_1018_bot" "magicmeta" "7870147428" "7699029999"
  "/verify-human/" "/0x/clb" "/0x/cls" "Sec-V"
  "0xa322e5f3d311d3080e6f0121063e9adc2490ef1a"   # attacker dead-drop wallet
  "0xa658863ea658863e68656c6c6f6970626f742121"   # encoded C2 payload wallet
  "$C2_IP"
)
ARTIFACTS=(
  "$NR_HOME/.node_modules/node_modules"  # runtime RAT deps in a non-standard dir
  "$NR_TMP/get-pip.py" "$NR_TMP/.pip" "$NR_TMP/.npm"
)
IDE_ROOTS=(
  "/usr/share/code/resources/app" "/usr/share/cursor/resources/app"
  "/usr/share/antigravity/resources/app" "/usr/share/GitHub Desktop"
  "/opt/Visual Studio Code" "/opt/cursor"
  "$NR_HOME/.vscode" "$NR_HOME/.cursor"
  "$NR_HOME/.vscode-server" "$NR_HOME/.config/Code"
)
IFS=':' read -r -a _extra <<< "$NR_IDE_EXTRA"; for e in "${_extra[@]:-}"; do [ -n "$e" ] && IDE_ROOTS+=("$e"); done
SCAN_DIRS=()
for d in Downloads Desktop Documents Projects projects src code repos work dev; do
  [ -d "$NR_HOME/$d" ] && SCAN_DIRS+=("$NR_HOME/$d")
done
SCAN_DIRS+=("$NR_TMP")

echo "NullReceiver Linux $( [ "$CLEAN" = 1 ] && echo REMEDY || echo scan ) — $(hostname 2>/dev/null) — $(date -u +%FT%TZ)"
[ "$CLEAN" = 1 ] && ylw "CLEAN mode: artifacts will be MOVED to $NR_QUARANTINE"

# ---- 1. Network -------------------------------------------------------------
if [ -z "${NR_NO_NET:-}" ]; then
  sect "Live connections to known C2 ($C2_IP — dynamic)"
  NET=""
  command -v ss >/dev/null && NET="$(ss -tanp 2>/dev/null | grep "$C2_IP" || true)"
  [ -z "$NET" ] && command -v netstat >/dev/null && NET="$(netstat -tanp 2>/dev/null | grep "$C2_IP" || true)"
  if [ -n "$NET" ]; then
    hit "active C2 socket:"; echo "$NET"
    if [ "$CLEAN" = 1 ] && [ "$(id -u)" = 0 ]; then
      if command -v nft >/dev/null; then nft add table inet nrblock 2>/dev/null; nft add chain inet nrblock out '{ type filter hook output priority 0; }' 2>/dev/null; nft add rule inet nrblock out ip daddr "$C2_IP" drop 2>/dev/null && ylw "      -> nft drop rule added for $C2_IP";
      elif command -v iptables >/dev/null; then iptables -A OUTPUT -d "$C2_IP" -j DROP && ylw "      -> iptables OUTPUT DROP added for $C2_IP"; fi
      ylw "      NOTE: C2 IP is dynamic; this blocks one address only."
    elif [ "$CLEAN" = 1 ]; then ylw "      (run with sudo to auto-block; or: sudo iptables -A OUTPUT -d $C2_IP -j DROP)"; fi
  else grn "  none"; fi
  grep -qs "$C2_IP" /etc/hosts && hit "C2 IP pinned in /etc/hosts (review /etc/hosts)"
fi

# ---- 2. Malware artifacts ---------------------------------------------------
sect "Known malware artifacts"
A=0
for p in "${ARTIFACTS[@]}"; do [ -e "$p" ] && { hit "present: $p"; A=1; quarantine "$p"; }; done
while IFS= read -r m; do [ -n "$m" ] && { hit "infostealer mutex lock: $m"; A=1; quarantine "$m"; }; done \
  < <(ls "$NR_TMP"/tmp[0-9A-Fa-f]*.tmp 2>/dev/null)
[ "$A" = 0 ] && grn "  none"

# ---- 3. IDE injection (highest fidelity) -----------------------------------
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
[ "$S" = 0 ] && grn "  no IDE injection markers" || { [ "$CLEAN" = 1 ] && ylw "  ACTION: reinstall affected editors (VS Code/Cursor/Antigravity/GitHub Desktop) from vendor — quarantine only neutralises, reinstall restores integrity."; }

# ---- 4. IoC string sweep (report only — never quarantines your source) -----
sect "IoC string sweep (${#SCAN_DIRS[@]} dev locations, report only)"
PAT="$(IFS='|'; echo "${STRINGS[*]}")"
SW=0
for d in "${SCAN_DIRS[@]}"; do
  [ -d "$d" ] || continue
  while IFS= read -r f; do hit "IoC string in: $f"; SW=1; done \
    < <(grep -rlIE --exclude-dir='.git' -- "$PAT" "$d" 2>/dev/null | head -100)
done
[ "$SW" = 0 ] && grn "  no IoC strings found"

# ---- 5. Persistence ---------------------------------------------------------
sect "Persistence (cron / shell rc / autostart / systemd user)"
P=0
{ crontab -l 2>/dev/null; cat /etc/crontab 2>/dev/null; } | grep -nE '\.node_modules|/tmp/get-pip|166\.88\.134\.62' | grep -vE '^\s*#' \
  && { hit "malicious cron reference (edit crontab -e to remove)"; P=1; }
for rc in "$NR_HOME/.bashrc" "$NR_HOME/.zshrc" "$NR_HOME/.profile" "$NR_HOME/.bash_profile"; do
  [ -f "$rc" ] && grep -nE '\.node_modules|166\.88\.134\.62|/tmp/get-pip' "$rc" 2>/dev/null && { hit "suspicious line in $rc (review/remove manually)"; P=1; }
done
for u in "$NR_HOME/.config/systemd/user/"*.service; do
  [ -f "$u" ] || continue
  grep -qsE '\.node_modules|/tmp/get-pip|166\.88\.134\.62' "$u" && { hit "malicious systemd user unit: $u"; P=1; quarantine "$u"; }
done
[ "$P" = 0 ] && grn "  no persistence markers"

# ---- 6. Processes -----------------------------------------------------------
if [ -z "${NR_NO_PROC:-}" ]; then
  sect "Running processes matching malware pattern"
  MATCH="$(ps -eo pid,command 2>/dev/null | grep -iE '\.node_modules|/tmp/get-pip|/tmp/\.pip' | grep -v grep || true)"
  if [ -n "$MATCH" ]; then
    hit "suspicious processes:"; echo "$MATCH"
    if [ "$CLEAN" = 1 ]; then echo "$MATCH" | awk '{print $1}' | while read -r pid; do kill -9 "$pid" 2>/dev/null && ylw "      -> killed pid $pid"; done; fi
  else grn "  none"; fi
fi

# ---- verdict ----------------------------------------------------------------
echo
if [ "$FOUND" = 1 ]; then
  red "RESULT: INDICATORS FOUND — treat this host as COMPROMISED."
  ylw "NEXT (see README.md): 1) isolate host  2) $( [ "$CLEAN" = 1 ] && echo 'quarantine done above' || echo 'rerun with --clean' )"
  ylw "  3) ROTATE ALL credentials (cloud/API/git/npm/DB) from a CLEAN device"
  ylw "  4) MOVE CRYPTO to new wallets with new seed phrases (wallets are compromised)"
  ylw "  5) reinstall any editor flagged above"
  exit 1
else
  grn "RESULT: no NullReceiver indicators in scanned scope."
  ylw "Targeted hunt, not a full AV. If you ran malicious code earlier, rotate creds anyway."
  exit 0
fi
