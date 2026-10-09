"""autopwn — autonomous CTF/SSH exploitation agent (authorized use only).

Usage:
    autopwn run --target user@host --key path/to.pem --authorized
    autopwn run --target user@host --password 'pw' --authorized --port 2222
"""
from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import re
import sys
from pathlib import Path

from . import ssh
from .prompt import SYSTEM_PROMPT, build_task_prompt

BANNER = r"""
   ___       _        ___
  / _ |__ __/ /____  / _ \_    _____
 / __ / // / __/ _ \/ ___/ |/|/ / _ \
/_/ |_\_,_/\__/\___/_/   |__,__/_//_/   autonomous exploitation agent
"""

TARGET_RE = re.compile(r"^(?P<user>[^@]+)@(?P<host>[^@:]+)$")


def parse_target(value: str) -> tuple[str, str]:
    m = TARGET_RE.match(value.strip())
    if not m:
        raise argparse.ArgumentTypeError("target must look like user@host")
    return m.group("user"), m.group("host")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="autopwn", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run an engagement against one target")
    run.add_argument("--target", required=True, type=parse_target,
                     help="user@host of the authorized target")
    run.add_argument("--port", type=int, default=22, help="SSH port (default 22)")
    auth = run.add_mutually_exclusive_group(required=True)
    auth.add_argument("--key", help="path to SSH private key (.pem)")
    auth.add_argument("--password", help="SSH password (also used for sudo)")
    run.add_argument("--authorized", action="store_true", required=True,
                     help="REQUIRED: assert you are authorized to test this target")
    run.add_argument("--model", default="opus",
                     help="Claude model id or alias (default: opus)")
    run.add_argument("--max-turns", type=int, default=200,
                     help="max agent turns before stopping (default 200)")
    run.add_argument("--workdir", default=None,
                     help="engagement working dir (default ./engagements/<ts>)")
    return p


def cmd_run(args: argparse.Namespace) -> int:
    user, host = args.target
    print(BANNER)
    print(f"[*] Target     : {user}@{host}:{args.port}")
    print(f"[*] Auth       : {'key' if args.key else 'password'}")
    print(f"[*] Model      : {args.model}")
    print("[!] AUTHORIZED-USE ONLY. You asserted authorization for this target.\n")

    ts = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    workdir = Path(args.workdir) if args.workdir else Path("engagements") / f"{host}-{ts}"
    workdir.mkdir(parents=True, exist_ok=True)
    workdir = workdir.resolve()
    print(f"[*] Workdir    : {workdir}")

    key = None
    if args.key:
        key = ssh.prepare_key(args.key, workdir)
        print(f"[*] Key copied : {key} (0600)")
    wrapper = ssh.write_wrapper(workdir, host, user, args.port, key, args.password)
    print(f"[*] SSH wrapper: {wrapper}")

    print("[*] Preflight  : testing connectivity ...")
    ok, out = ssh.test_connection(wrapper)
    if not ok:
        print(f"[x] Could not reach/auth to target:\n{out}", file=sys.stderr)
        return 2
    print(f"[+] Connected  : {out.splitlines()[0] if out else 'ok'}\n")

    task = build_task_prompt(host, user, args.port, str(workdir),
                             has_password=bool(args.password))

    from . import agent  # imported late so SSH-only preflight needs no SDK
    return asyncio.run(agent.run_engagement(
        system_prompt=SYSTEM_PROMPT, task_prompt=task, workdir=workdir,
        model=args.model, max_turns=args.max_turns,
    ))


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "run":
        if not args.authorized:
            print("Refusing to run without --authorized.", file=sys.stderr)
            return 1
        return cmd_run(args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
