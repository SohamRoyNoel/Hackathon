"""Remote command execution + a fixed, batched enumeration pass."""
from __future__ import annotations

import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

# sshd often rate-limits rapid short-lived connections; these are transient.
_TRANSIENT = ("connection reset by peer", "kex_exchange_identification",
              "connection closed by", "connection timed out",
              "connection refused", "broken pipe")

# One batched enumeration script. Sections are delimited by ===NAME=== markers.
ENUM_SCRIPT = r"""
echo ===ID===; id
echo ===WHOAMI===; whoami
echo ===KERNEL===; uname -r
echo ===UNAME===; uname -a
echo ===OS===; cat /etc/os-release 2>/dev/null | grep -E 'PRETTY_NAME|VERSION_ID'
echo ===SUDO===; sudo -n -l 2>/dev/null || sudo -l 2>/dev/null
echo ===SUID===; find / -perm -4000 -type f 2>/dev/null
echo ===SGID===; find / -perm -2000 -type f 2>/dev/null
echo ===CAPS===; getcap -r / 2>/dev/null
echo ===PASSWD_W===; test -w /etc/passwd && echo WRITABLE || echo no
echo ===SHADOW_R===; test -r /etc/shadow && echo READABLE || echo no
echo ===CRON===; cat /etc/crontab 2>/dev/null; ls -la /etc/cron.d/ 2>/dev/null
echo ===ROOTCRON===; grep -rhE 'root' /etc/crontab /etc/cron.d/ 2>/dev/null | grep -vE '^\s*#'
echo ===WRITABLE_ROOT_SCRIPTS===; for f in $(grep -rhoE '/[A-Za-z0-9_./-]+\.(sh|py|pl|rb)' /etc/crontab /etc/cron.d/ /etc/cron.hourly/ /etc/cron.daily/ 2>/dev/null | sort -u); do [ -w "$f" ] && echo "$f"; done
echo ===WWRITE===; find / -writable -type f -not -path '/proc/*' -not -path '/sys/*' -not -path '/dev/*' -not -path '/run/*' 2>/dev/null | head -120
echo ===HOMES===; ls -la /home/ 2>/dev/null
echo ===FLAGFILES===; find / \( -name user.txt -o -name root.txt -o -name 'flag*.txt' -o -name proof.txt \) 2>/dev/null
echo ===FLAGDATA===; for f in $(find / \( -name user.txt -o -name root.txt -o -name 'flag*.txt' -o -name proof.txt \) 2>/dev/null); do if [ -r "$f" ]; then echo "## $f"; cat "$f" 2>/dev/null; fi; done
echo ===READKEYS===; for k in $(find /home /root -name 'id_*' -not -name '*.pub' 2>/dev/null); do [ -r "$k" ] && echo "$k"; done
echo ===PORTS===; (ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null) | head -40
echo ===END===
"""

FLAG_RE = re.compile(r"(?:[A-Za-z0-9_]+\{[^}]{2,}\}|\b[0-9a-f]{32}\b)")


@dataclass
class EnumResult:
    sections: dict[str, str] = field(default_factory=dict)
    raw: str = ""

    def get(self, name: str) -> str:
        return self.sections.get(name, "").strip()

    @property
    def whoami(self) -> str:
        w = self.get("WHOAMI")
        return w.splitlines()[0] if w else ""

    @property
    def is_root(self) -> bool:
        return "uid=0(root)" in self.get("ID")

    @property
    def groups(self) -> list[str]:
        m = re.search(r"groups=(\S+)", self.get("ID"))
        if not m:
            return []
        return [g.split("(")[-1].rstrip(")") for g in m.group(1).split(",")]

    @property
    def flags(self) -> list[str]:
        return sorted(set(FLAG_RE.findall(self.get("FLAGDATA"))))


def run_remote(wrapper: Path, command: str, timeout: int = 120,
               retries: int = 3) -> tuple[int, str]:
    """Run one command on the target through the generated ssh wrapper.

    Retries on transient SSH failures (connection reset / rate-limit) with a
    short backoff, since the engine makes many short-lived connections.
    """
    rc, out = 1, ""
    for attempt in range(retries + 1):
        try:
            proc = subprocess.run(
                [str(wrapper), command],
                capture_output=True, text=True, timeout=timeout,
                cwd=str(wrapper.parent),
            )
            rc, out = proc.returncode, (proc.stdout + proc.stderr)
        except subprocess.TimeoutExpired:
            rc, out = 124, "<timed out>"
        except Exception as exc:  # noqa: BLE001
            rc, out = 1, f"<error: {type(exc).__name__}: {exc}>"
        low = out.lower()
        if attempt < retries and any(t in low for t in _TRANSIENT):
            time.sleep(3 + 2 * attempt)  # 3s, 5s, 7s backoff
            continue
        break
    return rc, out


def parse(raw: str) -> EnumResult:
    sections: dict[str, str] = {}
    current = None
    buf: list[str] = []
    for line in raw.splitlines():
        s = line.strip()
        if s.startswith("===") and s.endswith("===") and len(s) > 6:
            if current is not None:
                sections[current] = "\n".join(buf).strip()
            current = s.strip("=")
            buf = []
        elif current is not None:
            buf.append(line)
    if current is not None:
        sections[current] = "\n".join(buf).strip()
    return EnumResult(sections=sections, raw=raw)


def enumerate_target(wrapper: Path, timeout: int = 240) -> EnumResult:
    _, out = run_remote(wrapper, ENUM_SCRIPT, timeout=timeout)
    return parse(out)
