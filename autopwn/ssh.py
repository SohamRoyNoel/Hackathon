"""SSH preflight: fix key permissions, build a reusable wrapper, test connectivity."""
from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

SSH_OPTS = [
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "LogLevel=ERROR",
    "-o", "ConnectTimeout=15",
]


def prepare_key(key_path: str, workdir: Path) -> Path:
    """Copy the private key into the engagement dir with safe 0600 perms.

    SSH refuses to use a key that is group/world readable; the supplied .pem is
    often 0777, so we always work from a locked-down copy.
    """
    src = Path(key_path).expanduser().resolve()
    if not src.is_file():
        raise FileNotFoundError(f"SSH key not found: {src}")
    dst = workdir / "id_key"
    shutil.copyfile(src, dst)
    os.chmod(dst, stat.S_IRUSR | stat.S_IWUSR)  # 0600
    return dst


def write_wrapper(workdir: Path, host: str, user: str, port: int,
                  key: Path | None, password: str | None,
                  name: str = "ssh.sh") -> Path:
    """Write a wrapper script that runs one remote command non-interactively.

    Key auth uses plain `ssh -i`. Password auth uses an expect wrapper so the
    same password answers both the SSH and any sudo prompt. `name` lets callers
    keep distinct per-identity wrappers side by side (so they don't clobber).
    """
    opts = " ".join(SSH_OPTS)
    wrapper = workdir / name
    if key is not None:
        # Key wrappers must NEVER fall back to an interactive password prompt
        # (BatchMode); otherwise a not-yet-authorized key hangs on a tty.
        wrapper.write_text(
            "#!/usr/bin/env bash\n"
            "# autopwn SSH wrapper (key auth). Usage: ./ssh.sh '<remote command>'\n"
            f'exec ssh {opts} -o BatchMode=yes -o PasswordAuthentication=no '
            f'-o NumberOfPasswordPrompts=0 -o PreferredAuthentications=publickey '
            f'-i "{key}" -p {port} {user}@{host} "$@"\n'
        )
    else:
        esc = (password or "").replace("\\", "\\\\").replace('"', '\\"')
        wrapper.write_text(
            "#!/usr/bin/env expect -f\n"
            "# autopwn SSH wrapper (password auth). Usage: ./ssh.sh '<remote command>'\n"
            "set timeout 120\n"
            f'set pass "{esc}"\n'
            "set cmd [lindex $argv 0]\n"
            f'spawn ssh {opts} -p {port} {user}@{host} $cmd\n'
            "expect {\n"
            '  -re "(?i)assword:" { send "$pass\\r"; exp_continue }\n'
            '  -re "(?i)permission denied" { puts \"\\nAUTH_FAILED\"; exit 1 }\n'
            "  eof\n"
            "}\n"
        )
    os.chmod(wrapper, 0o755)
    return wrapper


def test_connection(wrapper: Path) -> tuple[bool, str]:
    """Run `id` through the wrapper to confirm we can reach and auth to the box."""
    try:
        proc = subprocess.run(
            [str(wrapper), "id; hostname; uname -a"],
            capture_output=True, text=True, timeout=60, cwd=str(wrapper.parent),
        )
        out = (proc.stdout + proc.stderr).strip()
        ok = proc.returncode == 0 and "uid=" in out
        return ok, out
    except subprocess.TimeoutExpired:
        return False, "connection timed out"
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"
