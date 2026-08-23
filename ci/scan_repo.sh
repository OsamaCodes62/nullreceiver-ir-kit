#!/usr/bin/env bash
# =============================================================================
# Supply-chain / NullReceiver-family integrity scanner  (ruleset: RULESET.md)
#
# Two tiers:  HARD  -> block the PR (exit 1)      WARN -> annotate only (exit 0)
#
# Scope = GIT-TRACKED files only (git ls-files). This is deliberate: gitignored
# evidence/quarantine dirs (e.g. an IR toolkit, logs, sandbox captures) legitimately
# embed every IoC, and a filesystem scan would flag them. Tracked-only scoping
# also closes the "hide payload under a dir merely named dist/build" trick, since a
# committed file there is still tracked. Falls back to a pruned `find` outside git.
#
# Usage:   bash scan_repo.sh [repo-path]        (default .)
#   env    CI=1   -> emit ::error:: / ::warning:: GitHub annotations
# Exit:    0 = no HARD findings    1 = HARD finding(s)    2 = scanner error
#
# FP guards (see RULESET.md): bare process.env / https:// / require()/import are
# NOT flagged; *.md, vendored/minified bundles, and this scanner's own files are
# excluded from IoC-text rules; a line bearing `# nr-ioc-signature` is suppressed.
# =============================================================================
set -o pipefail   # NOT -u: bash 3.2 (macOS default) errors on empty "${arr[@]}"

ROOT="${1:-.}"
CI="${CI:-}"
# The scanner's own files, plus any indicator-definition file: a threat-intel
# IoC list legitimately contains every string the IoC-text rules hunt for, so
# scanning it is guaranteed self-trip. Keep your own indicator data under
# `iocs/` (or name it `iocs.json` / `iocs.csv`) and the gate will skip it.
SELF_RE='(^|/)(scan_repo\.sh|scan_linux\.sh|scan_macos\.sh|scan_windows\.ps1|selftest\.sh|selftest_windows\.ps1|test_ci_scan\.sh|RULESET\.md|supply-chain-integrity\.yml|iocs\.(json|csv|ya?ml))$|(^|/)iocs/'
VEND_RE='(\.min\.(js|cjs|mjs)$|/vendor/|/public/|/static/)'
JS_RE='\.(js|cjs|mjs|jsx|ts|cts|mts|tsx)$'
SRC_RE='(\.(js|cjs|mjs|jsx|ts|cts|mts|tsx|py|sh)$|(^|/)package\.json$|(^|/)package-lock\.json$|(^|/)\.npmrc$)'

hard=0; warn=0
cd "$ROOT" 2>/dev/null || { echo "scan_repo: cannot cd '$ROOT'"; exit 2; }

_ann(){ # level file line msg
  if [ -n "$CI" ]; then echo "::$1 file=$2,line=$3::$4"
  else local c=33; [ "$1" = error ] && c=31
       printf '\033[%sm[%-5s]\033[0m %s:%s  %s\n' "$c" "$1" "$2" "$3" "$4"; fi
}
err(){ hard=$((hard+1)); _ann error "$1" "${2:-1}" "$3"; }
wrn(){ warn=$((warn+1)); _ann warning "$1" "${2:-1}" "$3"; }

# ---- tracked file list (git index) or pruned find fallback ------------------
ALL=()   # populated via read-loop (portable to bash 3.2 which lacks mapfile)
if git rev-parse --is-inside-work-tree >/dev/null 2>&1 && [ -n "$(git ls-files 2>/dev/null | head -1)" ]; then
  MODE=git
  while IFS= read -r _l; do ALL+=("$_l"); done < <(git ls-files 2>/dev/null)
else
  MODE=find
  while IFS= read -r _l; do ALL+=("$_l"); done < <(find . -type d \( -name node_modules -o -name .git \
      -o -name .next -o -name dist -o -name build -o -name .venv -o -name venv \) -prune -o -type f -print \
      | sed 's#^\./##')
fi
[ "${#ALL[@]}" -eq 0 ] && echo "scan_repo: WARNING — no files enumerated (empty repo?)"
echo "scan_repo: scope=$MODE files=${#ALL[@]} root=$ROOT"

# print files from ALL whose path matches ERE $1, skipping self + optional skip ERE $2
pick(){ local re="$1" skip="${2:-}" f
  for f in "${ALL[@]}"; do
    [[ "$f" =~ $re ]] || continue
    [[ "$f" =~ $SELF_RE ]] && continue
    [ -n "$skip" ] && [[ "$f" =~ $skip ]] && continue
    printf '%s\n' "$f"
  done
}
# tier name file_ere skip_ere grepflags pattern  — one finding per matching file
run_rule(){ local tier="$1" name="$2" fre="$3" skip="$4" gf="$5" pat="$6" f res ln
  while IFS= read -r f; do
    [ -f "$f" ] || continue
    res="$(grep $gf -e "$pat" -- "$f" 2>/dev/null | grep -v 'nr-ioc-signature')"
    [ -n "$res" ] || continue
    ln="$(printf '%s\n' "$res" | head -1 | cut -d: -f1)"
    if [ "$tier" = HARD ]; then err "$f" "$ln" "$name"; else wrn "$f" "$ln" "$name"; fi
  done < <(pick "$fre" "$skip")
}

echo
# ===== HARD: campaign IoCs (durable; essentially never in legit source) ======
run_rule HARD "R1 C2 IP (166.88.134.62 / re-encoded)" "$SRC_RE" "" "-anE" \
  '166\.88\.134\.62|::ffff:166\.88\.134\.62|\b2790096446\b'
run_rule HARD "R1 dead-drop wallet" "$SRC_RE" "" "-anEi" \
  '0xa322e5f3d311d3080e6f0121063e9adc2490ef1a|0xa658863ea658863e68656c6c6f6970626f742121'
run_rule HARD "R1 C2 verify-human path" "$SRC_RE" "" "-anE" '/verify[-._]?human/'

# ===== HARD: IDE-injection loader sidecar (*.inz.cjs, broadened/case-ins) =====
while IFS= read -r f; do err "$f" 1 "R2 IDE-injection sidecar (*.inz.cjs)"; done \
  < <(pick '\.inz\.[cm]?jsx?$')

# ===== WARN: committed write under @vscode/deviceid/dist/ (tamper target) =====
while IFS= read -r f; do wrn "$f" 1 "R2 write under @vscode/deviceid/dist/"; done \
  < <(pick '@vscode/deviceid/dist/.+')

# ===== HARD: obfuscated eval() dropper — exec directly wrapping a decoder =====
run_rule HARD "R4 obfuscated eval()/Function() dropper" "$JS_RE" "$VEND_RE" "-anE" \
  '(\beval|\bFunction|new[[:space:]]+Function|\(0,[[:space:]]*eval[[:space:]]*\))[[:space:]]*\([[:space:]]*(atob|unescape|decodeURIComponent|String[[:space:]]*\.[[:space:]]*fromCharCode|Buffer[[:space:]]*\.[[:space:]]*from)[[:space:]]*\('

# ===== WARN: decode + execute co-occur in one file (split dropper) ===========
while IFS= read -r f; do
  [ -f "$f" ] || continue
  grep -qaE 'eval[[:space:]]*\(|\bFunction[[:space:]]*\(|new[[:space:]]+Function|\(0,[[:space:]]*eval\)' -- "$f" 2>/dev/null \
  && grep -qaE 'atob[[:space:]]*\(|Buffer[[:space:]]*\.[[:space:]]*from[[:space:]]*\([^)]*(base64|hex)|String[[:space:]]*\.[[:space:]]*fromCharCode|decodeURIComponent[[:space:]]*\(|unescape[[:space:]]*\(' -- "$f" 2>/dev/null \
  && wrn "$f" 1 "R4 decode+execute co-occur (possible split dropper)"
done < <(pick "$JS_RE" "$VEND_RE")

# ===== WARN: child_process / exec in source (legit build-id use is common) ===
run_rule WARN "R3 child_process/exec (review context)" "$JS_RE" "$VEND_RE" "-anE" \
  'child_process|execSync|spawnSync|execFileSync'

# ===== WARN: get-pip.py *runtime bootstrap* shape (not the bare pip URL) ======
while IFS= read -r f; do
  [ -f "$f" ] || continue
  grep -qaiE 'get[._-]?pip' -- "$f" 2>/dev/null \
  && grep -qaE '/tmp|--break-system-packages' -- "$f" 2>/dev/null \
  && wrn "$f" 1 "R-GETPIP runtime pip-bootstrap shape"
done < <(pick "$SRC_RE" '(Dockerfile|requirements|(^|/)\.github/)')

# ===== R5: package.json install-time lifecycle scripts =======================
if command -v jq >/dev/null 2>&1; then
  MAL='\|[[:space:]]*(sh|bash|zsh|dash|node|python[0-9.]*|perl|ruby)([[:space:]]|$)|;[[:space:]]*(sh|bash)([[:space:]]|$)|&&[[:space:]]*(sh|bash)([[:space:]]|$)|curl|wget|node(js)?[[:space:]]+(-e|--eval|-p|--print)|deno[[:space:]]+eval|bun[[:space:]]+(-e|eval)|ts-node[[:space:]]+-e|base64[[:space:]]+(-d|--decode)|xxd[[:space:]]+-r|openssl[[:space:]]+(base64|enc)|\$\(|`|\bget[._-]?pip\b'
  while IFS= read -r pj; do
    [ -f "$pj" ] || continue
    while IFS= read -r val; do
      [ -n "$val" ] || continue
      if printf '%s' "$val" | grep -qiE "$MAL"; then
        err "$pj" 1 "R5 install lifecycle script runs code/network: ${val:0:70}"
      else
        wrn "$pj" 1 "R5 install lifecycle script present (review): ${val:0:70}"
      fi
    done < <(jq -r '.scripts // {} | to_entries[]
              | select(.key|test("^(pre|post)?(install|prepare|prepublishOnly|prepack|postpack)$"))
              | .value' "$pj" 2>/dev/null)
  done < <(pick '(^|/)package\.json$')
else
  wrn "-" 1 "jq not installed; package.json lifecycle-script rule (R5) skipped"
fi

# ---- verdict ----------------------------------------------------------------
echo
echo "scan_repo: $hard HARD, $warn WARN"
if [ "$hard" -gt 0 ]; then
  echo "RESULT: FAIL — high-confidence supply-chain indicator(s) found"; exit 1
fi
echo "RESULT: PASS — no HARD indicators (WARN items are advisory)"; exit 0
