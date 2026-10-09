# autopwn

Autonomous, **authorized-use-only** CTF/SSH exploitation agent, built on the
Claude Agent SDK. Point it at a target you are authorized to test and it runs the
full offensive kill-chain — recon → analysis → exploitation → privilege
escalation — adapting as it goes, until it captures the **root flag**. It writes
a full `REPORT.md` for the engagement as it works.

It reuses the operating method of the `pentester` sub-agent: breadth-first
enumeration, GTFOBins / SUID / cron / PATH-hijack vectors, and multi-angle
`searchsploit` + web vulnerability research with fallbacks.

## ⚠️ Authorization

Only run this against systems you own or have explicit written permission to
test (your own labs, sanctioned CTF boxes, engagements with a signed scope).
Unauthorized access to computer systems is illegal. The `--authorized` flag is a
required, deliberate assertion that you have that permission.

## Requirements

- Python ≥ 3.10 (this machine has 3.12/3.13 via Homebrew; the system 3.9 is too old)
- The `claude` CLI, logged in (the SDK uses its auth) — or `ANTHROPIC_API_KEY`
- `ssh`, and `expect` for password targets; `searchsploit`, `nmap` recommended

## Install

```bash
cd autopwn
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e .
```

## Usage

```bash
# key auth (e.g. an AWS-style .pem)
autopwn run --target ubuntu@10.0.0.5 --key ~/keys/hackathon.pem --authorized

# password auth, custom port, bounded turns
autopwn run --target ctf@target.box --password 'hunter2' --port 2222 \
    --authorized --max-turns 150
```

Each run creates `engagements/<host>-<timestamp>/` containing a locked-down copy
of the key (`id_key`, 0600), the generated `ssh.sh` wrapper, and the live
`REPORT.md`.

## How it works

1. **Preflight** — copies your key to `0600`, generates an `ssh.sh` wrapper
   (plain `ssh -i` for keys, an `expect` wrapper for passwords so one password
   also answers `sudo`), and verifies connectivity with `id`.
2. **Agent loop** — launches the Claude Agent SDK with the Bash tool enabled and
   permissions set to run autonomously. The model enumerates and exploits the box
   by calling `./ssh.sh '<command>'`, iterating as each new identity unlocks
   fresh vectors.
3. **Report** — the agent keeps `REPORT.md` current (flag table + per-step
   reasoning) and prints a final summary with the escalation chain.

## Flags

| flag | meaning |
|------|---------|
| `--target user@host` | authorized target (required) |
| `--key PATH` / `--password PW` | auth method (one required) |
| `--port N` | SSH port (default 22) |
| `--authorized` | required authorization assertion |
| `--model ID` | Claude model (default `opus`) |
| `--max-turns N` | agent turn cap (default 200) |
| `--workdir DIR` | override engagement directory |

---

# detpwn — the deterministic sibling

`detpwn` is a second agent for the same job with the opposite philosophy:
**the Python code does the heavy lifting**, and an LLM is only consulted as a
scoped advisor when the deterministic vectors run out.

How it works:

1. **Upload** a tiny root-proof script to the target.
2. **Enumerate** in one batched SSH pass (sudo -l, SUID/SGID, capabilities, weak
   perms, cron, world-writable files, flags, ports).
3. **Analyze** with a rule engine: unrestricted sudo, GTFOBins sudo/SUID matches,
   `cap_setuid` binaries, writable `/etc/passwd`, readable `/etc/shadow`.
4. **Execute** high-confidence vectors in ranked order and verify `uid=0(root)`.
5. **Advisor (optional)** — if still not root, a reasoning-only Claude call
   proposes non-interactive commands which the code executes and verifies.
6. **Report** — writes `REPORT.md` (result, flags, every attempt, leads, raw enum).

```bash
# deterministic + LLM advisor fallback (default)
detpwn run --target ubuntu@<HOST> --key ../hackathon.pem --authorized

# pure deterministic, never call the LLM
detpwn run --target ubuntu@<HOST> --key ../hackathon.pem --authorized --no-advisor
```

| flag | meaning |
|------|---------|
| `--no-advisor` | pure deterministic; never spin up the LLM |
| `--advisor-rounds N` | advisor rounds if deterministic vectors fail (default 1) |
| `--model ID` | advisor model (default `opus`) |

Choose `autopwn` for maximum adaptability on unusual boxes; choose `detpwn` for
fast, repeatable, mostly-offline runs on the common vector classes.
