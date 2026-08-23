# NullReceiver Incident-Response Kit

*For the DPRK npm supply-chain infostealer — OSV [MAL-2026-11136](https://osv.dev/vulnerability/MAL-2026-11136) / [MAL-2026-11132](https://osv.dev/vulnerability/MAL-2026-11132), GHSA [4w4v-pw3v-q85q](https://github.com/advisories/GHSA-4w4v-pw3v-q85q)*

[![selftest](https://img.shields.io/badge/selftest-38%2F38%20passing-brightgreen)](selftest.sh)
[![CI gate tests](https://img.shields.io/badge/CI%20gate%20tests-15%2F15%20passing-brightgreen)](ci/test_ci_scan.sh)

A **shareable** scan → remove → prevent kit for the DPRK-linked "NullReceiver"
infostealer (a "Contagious Interview" npm supply-chain sample: a Node/JS RAT +
a Python credential/wallet stealer). Give this whole folder to anyone who may
have run the malicious package; they can scan their machine, quarantine what it
finds, and harden against re-infection.

> **The C2 IP is dynamic.** Detection here is built on *durable* indicators —
> the IDE-injection loader files, tampered editor binaries, the blockchain
> dead-drop wallet addresses, the Telegram exfil bot, and behavioural markers.
> The IP (`166.88.134.62`) is treated as one disposable indicator, not the
> basis of detection.

---

## ⚠️ If you may be affected — do this NOW (in order)

1. **Disconnect from the network** (Wi-Fi off / cable out). This stops any
   ongoing exfiltration immediately.
2. **Run the scanner for your OS** (read-only — see below). If it reports *any*
   indicator, treat the machine as **fully compromised** — the infostealer runs
   in seconds and exfiltrates before you'd notice.
3. **From a *different*, known-clean device, rotate every credential** — see the
   [rotation checklist](#credential-rotation-checklist). Assume everything the
   account could reach is exposed.
4. **Move all cryptocurrency** to brand-new wallets with **new seed phrases**
   generated on a clean device / hardware wallet. The stealer targets wallet
   files, browser wallet extensions, and the clipboard. Old wallets = burned.
5. **Quarantine** with the scanner's `--clean`/`-Clean` mode, then **reinstall
   any flagged editor** (VS Code / Cursor / Antigravity / GitHub Desktop) from
   the vendor — patching is not enough; their app files were rewritten.
6. **Preferred for a confirmed infection:** back up your data, then **wipe and
   reinstall the OS**. A stealer may have dropped more than this kit hunts for.

---

## Running the scanner

Scan first (changes nothing), review the output, then re-run with the clean flag.

**Linux**
```bash
bash scan_linux.sh            # read-only scan
bash scan_linux.sh --clean    # quarantine + kill procs (sudo also blocks the IP)
```
**macOS**
```bash
bash scan_macos.sh            # read-only scan
bash scan_macos.sh --clean    # quarantine + kill procs
```
(If macOS blocks file access, grant Terminal **Full Disk Access** in System
Settings → Privacy & Security, or run with `sudo`.)

**Windows** (PowerShell)
```powershell
powershell -ExecutionPolicy Bypass -File .\scan_windows.ps1           # scan
powershell -ExecutionPolicy Bypass -File .\scan_windows.ps1 -Clean    # remedy (run as Admin)
```

`--clean`/`-Clean` **moves** artifacts into a timestamped
`nullreceiver_quarantine_*` folder in your home dir — nothing is blind-deleted,
so a false positive can be restored. Exit code `1` = indicators found, `0` = none.

---

## What it detects and quarantines

| Check | Indicator | On `--clean` |
|---|---|---|
| IDE injection | `*.inz.cjs` loader sidecars; `@vscode/deviceid/dist/index.js` or GitHub Desktop `main.js` rewritten to load them / contain C2 strings | quarantine + advise reinstall |
| Runtime RAT deps | `~/.node_modules/node_modules/` (socket.io-client, ws, axios dropped at runtime in a non-standard dir) | quarantine |
| Python stealer | `get-pip.py`, `.pip`, `.npm` in temp; `tmp<hex>.tmp` single-instance mutex lock | quarantine |
| C2 network | live connection to `166.88.134.62`; IP pinned in hosts file | firewall block (IP is dynamic — limited value) |
| Persistence | cron / shell rc / systemd-user (Linux); LaunchAgents-Daemons (macOS); Run keys / Startup / Scheduled Tasks (Windows) referencing the malware paths | quarantine the unit / flag for manual removal |
| IoC strings | files under dev dirs containing any known IoC | **report only** (never touches your source) |
| Processes | `node`/`python3` running from `.node_modules` / temp | kill |

---

## The C2 IP is dynamic — how we compensate

`166.88.134.62` is resolved by the loader from an **Ethereum blockchain
dead-drop**, so the operator can rotate it at will. The kit therefore keys on a
spread of indicators, ordered here by how much it costs the operator to change
them — with the structural artifacts, not the network indicators, as the real
anchor:

- **Structural / behavioural (most durable)** — the `*.inz.cjs` sidecar +
  `@vscode/deviceid` (or GitHub Desktop `main.js`) tamper, `~/.node_modules`
  runtime deps, `get-pip.py` bootstrap, staging dirs. These reflect the
  malware's *technique*, not a value it can swap out.
- **Costlier to rotate, but still replaceable** — the dead-drop resolver wallet
  `0xa322e5f3…` / encoded-payload wallet `0xa658…`, and the campaign/build tag
  `A9-2896-1`. Changing the wallet forces the operator to update or redistribute
  the loader, so it's stickier than an IP — but it is **still an IoC that can be
  replaced**, so refresh it, don't trust it forever.
- **Cheap to rotate (refresh from threat-intel)** — the C2 IP, the C2 paths
  (`/snv`, `/verify-human/`, `/$/1`, `/u/e`, `/u/f`, `/0x/…`), and the Telegram
  exfil bot `@file_1018_bot` (`7870147428`) → operator `@magicmeta`
  (`7699029999`). The operator can change any of these in seconds.

---

## Credential rotation checklist

The stealer harvests process env vars, browser-stored logins, OS keychain/keyring
secrets, and crypto wallets. Rotate **all** of these from a clean device:

- **Cloud / API:** AWS access keys, OpenAI, Stripe, SendGrid, Twilio, Supabase
  **service-role** key, any `*_API_KEY`/`*_TOKEN` in your shell/`.env`.
- **Source / packages:** GitHub token (+ revoke sessions, check for new SSH keys
  / OAuth apps you didn't add), `~/.npmrc` `NPM_TOKEN`, `~/.git-credentials`.
- **Data stores:** `DATABASE_URL` (Mongo/Postgres creds), `REDIS_URL` password.
- **Browsers:** every saved password (assume all exported); sign out everywhere.
- **OS secrets:** anything in macOS Keychain / GNOME Keyring / Windows Credential
  Manager the logged-in user could read.
- **Crypto:** move funds to new wallets/seed phrases; treat MetaMask & other
  wallet-extension data as exfiltrated.
- **Everywhere:** rotate, then enable/re-enroll MFA and revoke active sessions.

---

## Prevention / hardening (so it doesn't recur)

- **Initial vector = fake recruiter "coding challenge" repos.** Never run
  interview / take-home / unfamiliar code on your main machine. Use a
  **disposable VM or container with no credentials, no wallets, no logins**.
- **npm supply-chain hygiene:** `npm config set ignore-scripts true` globally;
  install with `npm ci` against a committed lockfile; vet dependencies (e.g.
  Socket.dev / `npm audit`); be suspicious of packages with obfuscated
  `postinstall` scripts or runtime `npm install`/`get-pip.py` behaviour.
- **CI integrity gate ([`ci/`](ci/)):** a ready-to-use GitHub Actions gate that
  statically hunts this campaign's IoCs + npm lifecycle-script abuse and
  **HARD-fails the PR** on high-confidence hits (WARN-annotates the rest).
  Activate by copying [`ci/supply-chain-integrity.yml`](ci/supply-chain-integrity.yml)
  into `.github/workflows/` and [`ci/scan_repo.sh`](ci/scan_repo.sh) to
  `.github/scan_repo.sh`, then make it a **required status check**. It scans the
  **git-tracked set only** (so gitignored evidence/quarantine dirs never
  self-trip) and is tuned for near-zero false positives — bare `process.env`,
  `https://`, config-level `child_process`, and the official `get-pip.py` URL are
  deliberately **not** flagged. Ruleset + rationale: [`ci/RULESET.md`](ci/RULESET.md);
  logic validated by [`ci/test_ci_scan.sh`](ci/test_ci_scan.sh).
- **Secrets:** don't keep long-lived secrets in shell env / `.env` on dev
  machines. Use a secret manager and short-lived, per-project scoped tokens.
- **Crypto:** hardware wallet; seed phrases offline only; a dedicated clean
  device for signing; a separate browser profile for wallets.
- **Editor integrity:** install editors only from the vendor; watch their app
  dirs for changes (file-integrity monitoring); review extensions.
- **Network egress:** on dev machines / servers, alert on or block outbound
  connections to raw IP literals and to the Telegram Bot API when not needed;
  monitor DNS.
- **Endpoint:** run EDR/AV, work as a non-admin user, keep OS/editors patched.

---

## Defenses that survive indicator rotation

The C2 IP and the Telegram token/bot are the *cheapest* things for the operator
to change. Don't build your defense on them — build it on the durable behaviour
("Pyramid of Pain": the higher up you detect, the more it costs them to evade).

| Cheap to rotate — refresh, don't rely on | Expensive to change — build defenses here (technique / behaviour) |
|---|---|
| C2 IP `166.88.134.62` | Delivery vector: fake "coding-challenge" repo — run untrusted code only in a throwaway VM |
| Telegram token / bot / operator | Runtime installs: `npm install` at runtime, `get-pip.py` bootstrap |
| Payload hashes, npm package names | IDE injection: `@vscode/deviceid` overwrite + `*.inz.cjs` sidecar |
| Dead-drop resolver wallet `0xa322e5f3…` — *costlier* (attacker must update/redistribute the loader), but still replaceable | Kill-chain: `node`→`python3`→`pip`; `node` from `~/.node_modules`; harvest→beacon |

**Controls that defeat IP *and* token rotation at once:**
- **Egress control** — default-deny outbound; alert on connections to raw IP
  literals (the blockchain-resolved C2 is always a bare IP) and to
  `api.telegram.org` from machines that don't need it (catches *any* token, and
  the separate `/u/f` HTTP-upload path too).
- **Behavioural EDR** — key on the kill-chain (node→python→pip, node running from
  `~/.node_modules`, "read browser Login Data / keychain then connect"), not on
  hashes or IPs.
- **File-integrity monitoring** on editor app dirs — the `*.inz.cjs` sidecar
  pattern is structural and survives payload changes.
- **Kill the vector** — interview/eval/unfamiliar code runs only in a disposable
  VM with no creds/wallets/logins. Rotation-proof: it never relies on
  recognising the attacker.

**Assume-breach** (theft completes in ~6 s — faster than any human response):
short-lived, scoped secrets via a secret manager (no long-lived tokens in
env/`.env`), phishing-resistant MFA (passkeys/FIDO2), hardware wallet with an
offline seed phrase, and no browser-stored passwords for sensitive accounts —
so a successful grab yields as little usable material as possible.

**Keep indicators fresh:** the IP / token / wallet strings the scanners search
for are a *refreshable* list, **not** the backbone — the structural checks
(`*.inz.cjs`, `@vscode/deviceid` tamper, `~/.node_modules`, `get-pip.py`,
staging dirs, process chain) are what survive rotation. Pull updated indicators
from threat-intel for this cluster (overlaps with the tracked *BeaverTail /
InvisibleFerret / OtterCookie* families), and report each rotation: new IP →
hosting provider; new token → Telegram abuse; resolver wallet →
chain-analytics/exchanges.

---

## Limitations

This is a **targeted hunt** for one malware family, not a general antivirus. A
clean result does **not** prove the machine is safe if you already executed the
sample — rotate credentials regardless. For a confirmed infection, OS reinstall
is the only high-confidence remedy.

## Testing / coverage

**Unit (synthetic):** `selftest.sh` builds a fake infected tree (no real
malware) and verifies each scanner **detects** every indicator category,
**quarantines** artifacts without deleting user source (string-sweep is
report-only), and produces **no false positives** on a clean tree. Last run:
**`scan_linux.sh` and `scan_macos.sh` — 38/38 assertions pass.**

**End-to-end (real detonation):** `scan_linux.sh` was run inside a container
that had actually been infected by the live sample. It detected the real
artifacts — the live C2 socket, `~/.node_modules`, `/tmp/get-pip.py|.pip|.npm`,
the real `/tmp/tmp<hex>.tmp` mutex, all four IDE injections
(`code`/`cursor`/`antigravity` `index.inz.cjs` + GitHub Desktop `main.inz.cjs`),
and the real `/tmp/.npm/...$jtaller.../_info.json` staging dir — then `--clean`
quarantined them and a re-scan returned **clean (exit 0)**. This confirms the
scanner's paths match where the malware actually writes.

**Persisted evidence (survives container removal):** the end-to-end image
(`sandbox/Dockerfile.irtest` in the [analysis repository](https://github.com/OsamaCodes62/nullreceiver-analysis)) bind-mounts a host dir and `tee`s all output to it
continuously, so logs and the quarantine tree remain on the drive even though
the container runs `--rm`. On disk:
- `evidence/irtest_persisted_run/` in the [analysis repository](https://github.com/OsamaCodes62/nullreceiver-analysis) — `irtest_console.log` and
  `app_capture/` (analysis logs, pcap — the whole `/app`). The full
  `nullreceiver_quarantine_*/` tree of moved artifacts stayed in the working
  set rather than the published evidence, since it is duplicate copies of the
  same implant files already published in that repo's samples archive.
- `evidence/irtest_run1_console_only/` — the first run's console log only (that
  run predated the bind mount, so its container FS was not captured).

**Windows:** `scan_windows.ps1` mirrors the tested POSIX scanners' IoC set and
control flow, and its script **parses cleanly under PowerShell** (AST parse
verified). Full functional testing could **not** be completed on the build host
— it is Apple-Silicon macOS with no native PowerShell, and Docker emulation of
pwsh proved unreliable (the 32-bit `arm/v7` image segfaults; `amd64` emulation
crashed spawning nested pwsh and otherwise produced masked output/exit codes).
A ready-to-run harness, `selftest_windows.ps1`, is included — run it on a **real
Windows host** (or any machine with native PowerShell):

```powershell
pwsh -File selftest_windows.ps1
```

It performs the same detect / quarantine / source-preservation / clean-tree
assertions that the POSIX `selftest.sh` does (which passes 38/38 and is backed
by the real-detonation end-to-end run above). Until it is run on Windows, treat
`scan_windows.ps1` as **logic-validated by parity, not yet machine-tested**.

## Author

Osama Ehsaan — <usama.ehsaan@gmail.com> · [@OsamaCodes62](https://github.com/OsamaCodes62)

## Provenance

Every indicator in this kit was derived from controlled sandbox detonations,
documented in full in the [analysis repository](https://github.com/OsamaCodes62/nullreceiver-analysis):

| Document | Establishes |
|---|---|
| `docs/01-full-technical-report.md` | The consolidated attack chain and IoC set |
| `docs/03-detonation-report.md` | What the malware did when it ran, per pass |
| `docs/05-static-analysis-findings.md` | Static verification of each behavioural claim |
| `docs/09-blockchain-deaddrop-decoding.md` | Why the C2 IP rotates, and the wallet that drives it |
| `docs/12-telegram-abuse-report.md` | The Telegram exfil channel and its takedown package |

That repository also carries the machine-readable indicator set, the sandbox
harness, the raw evidence (logs and pcaps), and the samples themselves.

**Structured indicators** are duplicated into this kit so it works offline and
standalone: [`iocs/iocs.json`](iocs/iocs.json) and
[`iocs/iocs.csv`](iocs/iocs.csv), each row tagged with how durable the
indicator is (`structural` / `sticky` / `volatile`) so you know which ones to
build detections on and which to refresh.
