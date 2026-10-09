# Changelog

All notable changes to **autopwn** are documented here.

## [0.5.0] — 2026-10-09

Severity-rated findings and danger highlighting across the engine + dashboard.

### Added

- **Findings model**: `analyze.severity_of()` rates every vector/lead
  critical/high/medium/low (sudo→root, SUID/cap shell, writable passwd,
  PwnKit/docker = critical; lateral sudo, writable root cron, readable shadow,
  LD_PRELOAD = high; custom SUID, readable keys, groups = medium; kernel = low).
- detpwn writes a structured `## Findings` section — each entry
  `[severity][status] title :: user`, status ∈ exploited / attempted / identified
  (deduped, strongest status wins). LLM-advisor root successes are now recorded
  as critical/exploited findings.
- Dashboard parses findings (with a keyword-derived fallback for older reports),
  adds **Critical / High / Exploited** KPI tiles, a red **"⚠ Dangerous activity"**
  panel (exploited critical/high findings, exposed flags, and full root
  compromises across all runs), a per-card severity-count strip + **"⚠ Exploited"**
  box, and a severity-badged **Findings** list in the drill-down. Severity uses
  the reserved status palette with a text label on every badge (never color-alone).

## [0.4.0] — 2026-10-09

Added a **local results dashboard** and hardened the detpwn chaining.

### Added — `autopwn-dash`

- `autopwn/dashboard/parse.py` — discovers every `engagements/*/REPORT.md`
  (recursively, skipping `.venv`/site-packages), classifies each run as
  root / flags / none, and extracts flags, attempts (+/−), escalation chain
  (users traversed), analysis, and the raw report.
- `autopwn/dashboard/server.py` — zero-dependency stdlib `http.server`
  dashboard bound to `127.0.0.1`. KPI stat tiles (engagements, roots, with-flags,
  unique flags, targets), filterable engagement cards (tool / status / host
  search), and a drill-down dialog (result, chain, flag chips, full attempt
  timeline, rendered analysis, raw report). Dark theme using the validated
  reserved **status palette** (good/warning/critical) with icon+label on every
  badge so state is never color-alone. `autopwn-dash` console script.

### Changed — detpwn lateral movement & SSH

- Replaced the fragile SSH-key-plant lateral mechanism with **runner-based
  chaining**: each hop runs through the escalation primitive itself
  (`sudo -u <user> <bin> …`), base64-piping arbitrary commands (and the whole
  enumeration) so quoting never breaks and hops nest recursively. Verified
  offline for find / shell / interpreter runners.
- Per-identity wrappers now use **unique filenames** (`ssh_<user>.sh`) instead of
  clobbering the shared `ssh.sh`.
- Key wrappers force `BatchMode=yes` / publickey-only so a not-yet-authorized key
  fails fast instead of prompting for a password on the operator's terminal.
- `run_remote` retries transient SSH failures (connection reset / rate-limit)
  with backoff; `enum.flags` set-math bug fixed.

## [0.3.0] — 2026-10-09

Major expansion of **detpwn** after a live Debian run captured no flags and no
root. Root-caused four gaps and broadened the deterministic surface area.

### Fixed (the four gaps from the failed run)

- **Flags were found but never read.** Enumeration now reads the contents of
  every `user.txt` / `root.txt` / `flag*.txt` / `proof.txt` it finds (new
  `FLAGDATA` section) and scrapes `flag{...}` / 32-hex at every hop, so readable
  flags are captured even without root. (The failed run's `flag{user1_...}` is
  now captured.)
- **Single-hop, root-only.** Added multi-hop lateral movement: a sudo entry that
  runs as another user (e.g. `(role002) NOPASSWD: /usr/bin/find`) is now an
  `exec` vector that plants an ephemeral ed25519 key into that user's
  `authorized_keys`, reconnects as them, re-enumerates, and recurses toward root
  (`--chain-depth`, default 6; loop-guarded by a visited-user set).
- **Custom SUID binaries were dropped.** Non-standard SUID/SGID binaries
  (e.g. `/usr/local/bin/backup`) are now surfaced as leads and their
  `file` + `strings` output is fed to the LLM advisor.
- **Writable root cron ignored.** Enumeration extracts scripts referenced by
  root crontab/`cron.d`/`cron.*` and tests writability; a writable one becomes a
  high-confidence `tick` vector that appends a root-key-plant payload and polls
  for the cron to fire (`--cron-wait`, default 120s).

### Added (broader coverage)

- Expanded GTFOBins tables: more sudo/SUID interpreters and utilities
  (`xargs`, `flock`, `stdbuf`, `timeout`, `nice`, `ftp`, `gdb`, `make`, `ssh`,
  `git`, …); **file-read** vectors (`sudo`/SUID `cat`/`tac`/`head`/`tail`/
  `strings`/`nl`/`grep`/`sort`) that capture flags without a shell; **file-write**
  vectors (`sudo chmod` → SUID bash).
- Capabilities: `cap_setuid` (python/perl/ruby/node/php) and
  `cap_dac_read_search` / `cap_dac_override` (read any file → root flag).
- Dangerous group memberships: `docker` (auto container-escape), plus
  `lxd`/`lxc`/`disk`/`adm`/`shadow` as leads.
- `sudo` `env_keep` `LD_PRELOAD` / `LD_LIBRARY_PATH` detection (lead).
- `pkexec` → PwnKit (CVE-2021-4034) and kernel-version exploit leads;
  readable private keys surfaced as lateral/root leads.
- `Vector` gained an `effect` (`exec`/`read`/`tick`/`lead`) and `runas`;
  ranking prioritises root exec/read, then lateral exec, then ticks, then leads.

### Changed

- `det/engine.py` rewritten around an `Engine` class with the recursive
  `escalate()` loop, ephemeral chain key, key-plant become, flag/attempt/visited
  tracking, cron polling, and advisor enrichment.
- `det/cli.py` passes `host`/`port`/`user` and adds `--chain-depth` /
  `--cron-wait`. Exit code is 0 if root OR any flag was captured.

### Verified

- Replayed the real failed Debian enumeration: now captures the user flag,
  emits the `sudo find -> role002` lateral vector (with correct become command),
  the `/opt/ceo-report.sh` writable-cron tick, and the custom-SUID / PwnKit /
  kernel leads. Full package imports; `ssh-keygen` present; new CLI flags wired.
- Not yet re-run against the live box.

## [0.2.0] — 2026-10-09

Added **detpwn**, a second, deterministic agent that complements `autopwn`.
Where `autopwn` hands the whole engagement to an LLM, detpwn drives the
kill-chain in Python and treats the LLM as an optional, scoped advisor of last
resort — "code does the heavy lifting; spin up an agent only if necessary."

### Added — `detpwn` command (`autopwn.det`)

- `det/engine.py` — orchestrator: upload a root-proof script → one batched
  enumeration pass → deterministic analysis → execute high-confidence vectors and
  verify root (`uid=0`) → if still stuck and enabled, consult the LLM advisor and
  execute its candidates → write `REPORT.md`. The code drives everything.
- `det/enumerate.py` — `run_remote()` over the shared `ssh.sh` wrapper, plus a
  single batched enumeration script (id, sudo -l, SUID/SGID, capabilities, weak
  perms on passwd/shadow, cron, world-writable files, homes, flags, ports)
  parsed into structured sections by `===NAME===` markers.
- `det/gtfobins.py` — escalation templates for sudo / SUID / `cap_setuid`
  vectors, plus the uploaded proof script (`/tmp/.ap_proof.sh`) that prints
  `uid=0(root)` and the root flag so success is verifiable without nested quoting.
- `det/analyze.py` — rule engine turning enumeration into ranked `Vector`s:
  unrestricted sudo, GTFOBins sudo/SUID matches, `cap_setuid` binaries, writable
  `/etc/passwd`, readable `/etc/shadow` (lead). Auto-executable high-confidence
  vectors are ranked ahead of manual leads.
- `det/advisor.py` — scoped LLM advisor via the Claude Agent SDK, **reasoning
  only** (`allowed_tools=[]`): given the enumeration output it returns candidate
  non-interactive commands in fenced blocks; the engine executes and verifies
  them. Best-effort — a missing SDK/key degrades gracefully.
- `det/cli.py` — `detpwn run` CLI reusing the SSH preflight, with `--no-advisor`
  (pure deterministic) and `--advisor-rounds N`.
- Registered the `detpwn` console-script entry point in `pyproject.toml`.

### Verified

- Rule engine unit-tested against simulated enumeration: correctly emits the
  `sudo find` (NOPASSWD→high), `SUID bash -p`, and `cap_setuid` python vectors
  with correct payloads, and the readable-shadow lead.
- Unrestricted-sudo detection, flag extraction (`HTB{...}` and 32-hex), CLI
  parsing, and the required `--authorized` gate all verified.
- Not yet exercised against a live box (needs an authorized target).

### Design note

- `autopwn` = adaptive, LLM-first (full agent). `detpwn` = deterministic,
  code-first (LLM optional). Both share `ssh.py` (key→0600, wrapper, preflight)
  and the authorized-use `--authorized` gate.

## [0.1.0] — 2026-10-09

Initial build: `autopwn`, an autonomous, **authorized-use-only** CTF/SSH
exploitation agent that productizes the `pentester` sub-agent idea. Point it at a
target you are authorized to test and it runs the full offensive kill-chain
(recon → analysis → exploitation → privilege escalation) via the Claude Agent
SDK until it captures the root flag, writing a live `REPORT.md` as it works.

### Background

- Started from the existing `pentester` sub-agent (`~/.claude/agents/pentester.md`).
- Confirmed the agent definition is well-formed and improved its Exploit-DB
  research: it now self-provisions `searchsploit` (brew/apt/git-clone fallback),
  searches from multiple perspectives, cross-checks web sources (NVD, GitHub,
  GTFOBins/LOLBAS, advisories), and treats a failed/misaligned exploit as a
  signal to try other angles rather than a dead end.
- Installed `exploitdb`/`searchsploit` locally and verified the database is
  populated (e.g. `searchsploit sudo` returns results).

### Product decisions (confirmed with the user)

- **Engine:** Claude Agent SDK — the LLM reasons and adapts live.
- **Interface:** CLI tool.
- **Targets:** SSH boxes / CTF (key or password auth).
- **Autonomy:** run full exploitation until the root flag; no per-command
  approval friction. Authorization is asserted via a required `--authorized` flag.

### Added

- `autopwn/cli.py` — `argparse` entry point (`autopwn run`), required
  `--authorized` gate, workdir setup, preflight orchestration, console banner.
- `autopwn/ssh.py` — SSH preflight:
  - copies the private key into the engagement dir with safe `0600` perms
    (the supplied `.pem` is often `0777`, which SSH refuses);
  - generates a reusable `ssh.sh` wrapper — plain `ssh -i` for key auth, an
    `expect` wrapper for password auth so one password answers both SSH and
    `sudo`;
  - tests connectivity with `id; hostname; uname -a` before launching the agent.
- `autopwn/prompt.py` — system + task prompts adapted from `pentester.md`, tuned
  for a single autonomous run that drives to the root flag; instructs the agent
  to drive all remote commands through `./ssh.sh` and keep `REPORT.md` current.
- `autopwn/agent.py` — Claude Agent SDK runner:
  - `ClaudeAgentOptions` with `system_prompt`, `model`, `allowed_tools`
    (`Bash, Read, Write, Edit, Grep, Glob, WebFetch, TodoWrite`),
    `permission_mode="bypassPermissions"` (hands-off autonomy),
    `max_turns`, `cwd`, and `setting_sources=[]` for deterministic runs;
  - streams the agent's reasoning and a one-line trace of each tool call;
  - reports final status, result subtype, and cost; surfaces the `REPORT.md`
    path on completion.
- `autopwn/__init__.py` — package marker (`__version__ = "0.1.0"`).
- `pyproject.toml` — package metadata, `claude-agent-sdk` dependency,
  `autopwn` console-script entry point, `requires-python >=3.10`.
- `README.md` — authorization notice, requirements, install, usage, and flag
  reference.

### CLI flags

| flag | meaning |
|------|---------|
| `--target user@host` | authorized target (required) |
| `--key PATH` / `--password PW` | auth method (exactly one required) |
| `--port N` | SSH port (default 22) |
| `--authorized` | required authorization assertion |
| `--model ID` | Claude model or alias (default: `opus`) |
| `--max-turns N` | agent turn cap (default 200) |
| `--workdir DIR` | override engagement directory |

### Engagement layout

Each run creates `engagements/<host>-<timestamp>/` containing a locked-down key
copy (`id_key`, `0600`), the generated `ssh.sh` wrapper, and the live
`REPORT.md`.

### Environment & verification

- Target machine: macOS; system Python is 3.9 (too old for the SDK), so the
  project uses Homebrew **Python 3.12** in a local `.venv`.
- The `claude` CLI (v2.1) is logged in, so the SDK can use its auth;
  `ANTHROPIC_API_KEY` is also supported.
- `claude-agent-sdk` **0.2.165** installed; all imports resolve.
- CLI parsing verified; the `--authorized` gate is enforced.
- Preflight verified against an unreachable host: fails cleanly with `rc=2`
  (key copied to `0600`, wrapper and workdir generated) instead of crashing.
- **Not yet exercised:** the live agent loop against a real box (requires an
  authorized target).

### Security notes

- Authorized-use only. `--authorized` is a deliberate assertion that the
  operator has permission to test the target.
- `permission_mode="bypassPermissions"` gives true hands-off autonomy (arbitrary
  SSH/Bash with no per-command approval) — appropriate for an authorized
  engagement; a future `--interactive` mode could gate destructive commands.
- Authorization is currently a single flag (no scope allowlist yet).

### Known limitations / possible next steps

- No live SDK-loop smoke test (against a mock target) yet.
- No `--interactive` approval mode for destructive commands.
- No scope allowlist to constrain targets for demo-safe use.
