#!/usr/bin/env bash
# Self-test for the POSIX scanners. Builds a SYNTHETIC (fake) infected tree —
# NO real malware — runs scan + --clean against it with env overrides, and
# asserts detection, safe quarantine, source preservation, and no false
# positives on a clean tree. Run from this folder:  bash selftest.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d 2>/dev/null || mktemp -d -t nrtest)"
trap 'rm -rf "$WORK"' EXIT
PASS=0; FAIL=0
ok(){ PASS=$((PASS+1)); printf '  \033[32mPASS\033[0m %s\n' "$*"; }
bad(){ FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s\n' "$*"; }
has(){ case "$1" in *"$2"*) return 0;; *) return 1;; esac; }

mk_infected(){ # $1 = dir
  local H="$1"
  mkdir -p "$H/.node_modules/node_modules/ws" "$H/tmp/.pip" "$H/tmp/.npm" \
           "$H/ide/resources/app/node_modules/@vscode/deviceid/dist" \
           "$H/ide/gh/resources/app" "$H/Projects" "$H/.config/systemd/user" \
           "$H/Library/LaunchAgents"
  : > "$H/tmp/get-pip.py"
  : > "$H/tmp/tmpDEADBEEF12.tmp"                       # mutex lock (hex .tmp)
  printf "module.exports=require('./index.inz.cjs'); // 166.88.134.62\n" \
        > "$H/ide/resources/app/node_modules/@vscode/deviceid/dist/index.js"
  printf "/* stage loader */ fetch('http://x/verify-human/A9-2896-1')\n" \
        > "$H/ide/resources/app/node_modules/@vscode/deviceid/dist/index.inz.cjs"
  printf "// tampered app entry — A9-2896-1\n" \
        > "$H/ide/gh/resources/app/main.js"
  printf "const c2='166.88.134.62'; // magicmeta\n" > "$H/Projects/evil.js"
  printf "clean project file\n"                      > "$H/Projects/legit.js"
  printf "[Service]\nExecStart=/usr/bin/node %s/.node_modules/node_modules/x\n" "$H" \
        > "$H/.config/systemd/user/evil.service"
  printf "<plist><dict><key>ProgramArguments</key><array><string>node</string><string>%s/.node_modules/boot</string></array></dict></plist>\n" "$H" \
        > "$H/Library/LaunchAgents/com.evil.agent.plist"
  printf "export PATH=\$PATH\nsource %s/.node_modules/boot\n" "$H" > "$H/.bashrc"
}
mk_clean(){ local H="$1"; mkdir -p "$H/Projects" "$H/tmp" "$H/ide"; printf "hello world\n" > "$H/Projects/app.js"; }

run(){ # $1 script  $2 home  rest: args   -> sets OUT, RC
  OUT="$(NR_HOME="$2" NR_TMP="$2/tmp" NR_IDE_EXTRA="$2/ide" NR_QUARANTINE="$2/quar" \
        NR_NO_NET=1 NR_NO_PROC=1 bash "$HERE/$1" "${@:3}" 2>&1)"; RC=$?
}

for S in scan_linux.sh scan_macos.sh; do
  echo "### $S — syntax"
  if bash -n "$HERE/$S"; then ok "$S parses"; else bad "$S syntax error"; continue; fi

  echo "### $S — DETECT (scan mode on infected tree)"
  INF="$WORK/${S%.sh}_inf"; mk_infected "$INF"
  run "$S" "$INF"
  [ "$RC" = 1 ] && ok "exit 1 on infection" || bad "expected exit 1, got $RC"
  has "$OUT" "injected loader sidecar"     && ok "detect .inz.cjs sidecar"      || bad "missed sidecar"
  has "$OUT" "tampered IDE file"           && ok "detect deviceid/main.js tamper" || bad "missed IDE tamper"
  has "$OUT" ".node_modules/node_modules"  && ok "detect runtime RAT deps dir"  || bad "missed .node_modules"
  has "$OUT" "get-pip.py"                  && ok "detect get-pip.py artifact"   || bad "missed get-pip.py"
  has "$OUT" "infostealer mutex lock"      && ok "detect mutex .tmp lock"       || bad "missed mutex"
  has "$OUT" "evil.js"                     && ok "detect IoC string in source"  || bad "missed string sweep"
  case "$S" in
    scan_linux.sh) has "$OUT" "systemd user unit" && ok "detect malicious systemd unit" || bad "missed systemd unit" ;;
    scan_macos.sh) has "$OUT" "launch item"       && ok "detect malicious LaunchAgent"  || bad "missed LaunchAgent" ;;
  esac
  has "$OUT" ".bashrc"                     && ok "detect suspicious shell rc"   || bad "missed shell rc"

  echo "### $S — REMEDY (--clean quarantines, preserves source)"
  INF2="$WORK/${S%.sh}_inf2"; mk_infected "$INF2"
  run "$S" "$INF2" --clean
  [ "$RC" = 1 ] && ok "exit 1 (found+cleaned)" || bad "expected exit 1, got $RC"
  [ ! -e "$INF2/.node_modules/node_modules" ] && ok "RAT deps quarantined (removed from origin)" || bad "RAT deps NOT moved"
  [ ! -e "$INF2/tmp/get-pip.py" ]             && ok "get-pip.py quarantined"                     || bad "get-pip.py NOT moved"
  [ -n "$(find "$INF2/quar" -name '*.inz.cjs' 2>/dev/null)" ] && ok "sidecar moved into quarantine" || bad "sidecar not in quarantine"
  case "$S" in
    scan_linux.sh) [ ! -e "$INF2/.config/systemd/user/evil.service" ] && ok "systemd unit quarantined" || bad "systemd unit NOT moved" ;;
    scan_macos.sh) [ ! -e "$INF2/Library/LaunchAgents/com.evil.agent.plist" ] && ok "LaunchAgent quarantined" || bad "LaunchAgent NOT moved" ;;
  esac
  [ -e "$INF2/Projects/evil.js" ]            && ok "source file PRESERVED (string sweep is report-only)" || bad "DESTROYED user source!"
  [ -e "$INF2/Projects/legit.js" ]           && ok "unrelated file untouched"          || bad "touched unrelated file"

  echo "### $S — CLEAN tree (no false positives)"
  CLN="$WORK/${S%.sh}_cln"; mk_clean "$CLN"
  run "$S" "$CLN"
  [ "$RC" = 0 ] && ok "exit 0 on clean tree" || bad "false positive (exit $RC)"
  has "$OUT" "no NullReceiver indicators" && ok "reports clean" || bad "did not report clean"
  echo
done

echo "======================================================"
echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ] && { echo "ALL TESTS PASSED"; exit 0; } || { echo "SOME TESTS FAILED"; exit 1; }
