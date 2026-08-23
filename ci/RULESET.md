# Supply-Chain Integrity — Ruleset (provenance)

Detection spec produced by an adversarial rule-review workflow: a false-positive
lens, an evasion lens, and a CI-hardening lens, merged by a synthesis pass. The
shipped [`scan_repo.sh`](scan_repo.sh) implements the JS / config / lifecycle
core (marked ✅); the remaining rules are documented here for future coverage
(marked 📋 spec-only).

## Rules

| ID | Tier | Impl | Scope | What it catches |
|---|---|---|---|---|
| HARNESS | — | ✅ | tracked set (`git ls-files`) | Deterministic tracked-only scope; auto-excludes gitignored evidence/quarantine dirs; `grep -a` defeats binary/minified evasion; fail-closed on grep error |
| R1-IP | HARD | ✅ | source files | C2 IP `166.88.134.62` + decimal / IPv4-mapped re-encodings |
| R1-WALLET | HARD | ✅ | source files | Both dead-drop wallets (case-insensitive → EIP-55 checksum forms can't evade) |
| R1-PATH | HARD | ✅ | source files | C2 tamper path `/verify[-._]?human/` |
| R2-INZ | HARD | ✅ | tracked set | IDE-injection loader sidecar `*.inz.[cm]?jsx?` (broadened, case-insensitive) |
| R2-VSCODE-DIST | WARN | ✅ | tracked set | Committed write under `@vscode/deviceid/dist/` (the tamper target — not the bare package) |
| R4-WRAP | HARD | ✅ | `*.{js,ts,…}` (excl. min/vendor) | `eval`/`Function`/`(0,eval)` directly wrapping a decoder (`atob`/`Buffer.from`/`fromCharCode`/…) |
| R4-COOCCUR | WARN | ✅ | `*.{js,ts,…}` | Decode + execute split across statements in one file |
| R4-IMPORT | WARN | 📋 | `*.{js,ts,…}` | Dynamic `import()` of a `data:` / remote / concatenated specifier |
| R3-EXEC | WARN | ✅ | `*.{js,ts,…}` repo-wide | `child_process`/`execSync`/`spawnSync` — **WARN** (legit build-id/git-hash injection) |
| R3-COMPUTED | WARN | 📋 | `*.{js,ts,…}` + configs | Computed/split API assembly (`cp['exe'+'c']`, `[]['constructor']…`) |
| R5-LIFECYCLE-HARD | HARD | ✅ | `package.json` (jq) | Install-time lifecycle script that pipes to a shell / fetches+executes / `node -e` / decodes |
| R5-LIFECYCLE-WARN | WARN | ✅ | `package.json` | Any install-time lifecycle script present (review) |
| R6-MANIFESTS | WARN | 📋 | `.pnpmfile.cjs`, `.npmrc`, `.yarnrc.yml` | Package-manager hook/config carrying executable or network directives |
| R-GETPIP | WARN | ✅ | source (excl. Dockerfile/reqs/CI) | `get-pip` **with** `/tmp` or `--break-system-packages` runtime shape (not the bare pip URL) |
| R-WALLET-GENERIC | WARN | 📋 | source | Any 0x-address literal (crypto-clipper heuristic) |
| R-IP-GENERIC | WARN | 📋 | manifests/configs | Any public raw IPv4 literal in a manifest/config (private/loopback excluded) |
| R-ENCODED | WARN | 📋 | `*.{js,ts,…}`, json | Long base64/hex blob literal (obfuscated-payload heuristic) |
| R7-PY-HARD | HARD | 📋 | `*.py` | `exec`/`eval` on decoded bytes; `subprocess(..., shell=True)` with a fetched/decoded arg |
| R7-PY-WARN | WARN | 📋 | `*.py` | `os.system` / `subprocess` / `base64` decode (review) |
| R7-SH | WARN | 📋 | `*.sh` | `curl\|wget … \| sh`, `base64 -d \| sh` |

## Excludes

- `node_modules/`, `.git/`, `.next/`, `dist/`, `build/`, `.venv/`, `venv/` — auto-excluded because enumeration is driven by `git ls-files` (tracked set), not filesystem `find`. A payload committed under a dir merely *named* `dist/build` is still enumerated (it's tracked).
- `logs/`, `detonation_lab_v2/`, `Docker_to_test/`, `audit/`, `all-audits/`, `**/child_captured/**` — untracked forensic / IR evidence that legitimately embeds every IoC (the C2 IP alone was in 119 untracked files, 0 tracked). Dropped on every runner by tracked-only scope.
- `**/vendor/**`, `**/public/**`, `**/static/**`, `*.min.js` — vendored/minified bundles legitimately contain `eval(atob(...))` (source-map / asset-inliner libs). Applies to the content-code rules only.
- `*.md` and the scanner's own `scan_repo.sh` / `RULESET.md` / workflow file — so `SECURITY.md`, threat-intel blocklists, and the ruleset itself can carry the IoC strings.
- **Indicator-definition files**: anything under an `iocs/` directory, or named `iocs.json` / `iocs.csv` / `iocs.yml`. A threat-intel indicator list by definition contains every string the IoC-text rules hunt for, so scanning it is a guaranteed self-trip. Keep your own indicator data at one of those paths and the gate will skip it.
- **This kit's own detection logic and tests**: `scan_linux.sh`, `scan_macos.sh`, `scan_windows.ps1`, `selftest.sh`, `selftest_windows.ps1`, `test_ci_scan.sh`. These files *are* signature data — they enumerate the C2 IP, the dead-drop wallet and the C2 paths in order to hunt for them, and `selftest.sh` additionally writes synthetic infected fixtures. Excluding them is what lets this repository pass its own gate. It does not weaken the gate for a consumer repo, which copies only `scan_repo.sh` and the workflow file; and `test_ci_scan.sh` still proves the rules fire against a genuinely malicious tree.
- Any single line bearing the inline marker `# nr-ioc-signature` — a knowingly-carried defensive signature is suppressed line-by-line.
- `Dockerfile*`, `*requirements*.txt/in`, CI `*.yml` — excluded from R-GETPIP so the official pip bootstrap isn't flagged.

## Explicitly NOT flagged (false-positive guards)

- Bare `process.env`; bare `https://` URLs; ordinary `require()`/`import` of packages.
- `bootstrap.pypa.io/get-pip.py` as a standalone URL in a Dockerfile/requirements/CI file (official first-party bootstrap) — flagged only with the `/tmp` + `--break-system-packages` runtime shape.
- Bare `@vscode/deviceid` package name / lockfile entry / import (real Microsoft package) — only the `*.inz.cjs` sidecar or a `@vscode/deviceid/dist/` write is flagged.
- `Function('return this')` global-object polyfill (core-js/regenerator/UMD) — wraps `return this`, not a decoder.
- Regex `.exec()` method calls (`/re/.exec(str)`) — bare `.exec(` was dropped to avoid the collision.
- Private/loopback/example/link-local IPs (RFC1918, `127.0.0.1`, `0.0.0.0`, `169.254.x`).
- Known-safe lifecycle tools (`husky`, `patch-package`, `node-gyp`, `node-pre-gyp`, `prebuild-install`, `electron-builder`, `prisma generate`) stay WARN even when they fetch a platform binary.
- `child_process`/`execSync` in configs for git-hash/build-id injection — WARN only, HARD solely when co-located with a network fetch or `/tmp` write.

## CI policy

- **Static only** — checkout + grep/find. Never run `npm ci`/`install`/`build`/`node` over an untrusted PR tree (that executes the very lifecycle scripts you're screening for).
- **`on: pull_request`, never `pull_request_target`** — fork PRs run read-only with no secrets over the untrusted head. Pass no secrets to the scan job.
- **`permissions: contents: read`** at workflow and job level. Annotations + exit code need no write scope.
- **Pin actions to a full 40-char commit SHA** (`@<sha> # v4`), not `@main`.
- **Exit code from an explicit accumulator**, independent of annotation emission; HARD → `hard=1` + `::error::` → `exit 1`; WARN → `::warning::` only.
- Don't let `grep`'s exit status control the script — `grep` returns 1 on no-match (the clean case). Use presence tests; avoid `set -e` on the grep pipeline.
- Make the gate a **required status check** in branch protection for `main`/`develop`, and audit both caller and any reusable workflow for soft-fail escape hatches (`continue-on-error`, trailing `|| true`, `if: always()` reroutes).
- Emit `::error file=<repo-relative-path>,line=<n>::<msg>` — `file=` must be relative to `GITHUB_WORKSPACE`.
