"""detpwn — deterministic, code-driven privesc engine (authorized use only).

Usage:
    detpwn run --target user@host --key path/to.pem --authorized
    detpwn run --target user@host --password 'pw' --authorized --no-advisor
"""
from __future__ import annotations

import argparse
import datetime as dt
import sys
from pathlib import Path

from .. import ssh
from ..cli import parse_target

BANNER = r"""
   __     __
  / /__  / /____  _    ______
 / / -_)/ __/ _ \| |/|/ / _ \   detpwn — deterministic privesc engine
/_/\__/ \__/ .__/|__,__/_//_/   (code-driven; LLM only when stuck)
          /_/
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="detpwn", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="run a deterministic engagement")
    run.add_argument("--target", required=True, type=parse_target,
                     help="user@host of the authorized target")
    run.add_argument("--port", type=int, default=22, help="SSH port (default 22)")
    auth = run.add_mutually_exclusive_group(required=True)
    auth.add_argument("--key", help="path to SSH private key (.pem)")
    auth.add_argument("--password", help="SSH password (also used for sudo)")
    run.add_argument("--authorized", action="store_true", required=True,
                     help="REQUIRED: assert you are authorized to test this target")
    run.add_argument("--no-advisor", action="store_true",
                     help="pure deterministic run; never spin up the LLM advisor")
    run.add_argument("--advisor-rounds", type=int, default=1,
                     help="LLM advisor rounds if deterministic vectors fail (default 1)")
    run.add_argument("--model", default="opus", help="advisor model (default: opus)")
    run.add_argument("--chain-depth", type=int, default=6,
                     help="max lateral-movement hops to chain (default 6)")
    run.add_argument("--cron-wait", type=int, default=120,
                     help="seconds to wait for a writable root cron to fire (default 120)")
    run.add_argument("--workdir", default=None, help="engagement working dir")
    return p


def cmd_run(args: argparse.Namespace) -> int:
    user, host = args.target
    print(BANNER)
    print(f"[*] Target : {user}@{host}:{args.port}  ({'key' if args.key else 'password'} auth)")
    print(f"[*] Advisor: {'disabled' if args.no_advisor else f'{args.model}, {args.advisor_rounds} round(s)'}")
    print("[!] AUTHORIZED-USE ONLY.\n")

    ts = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    workdir = Path(args.workdir) if args.workdir else Path("engagements") / f"det-{host}-{ts}"
    workdir.mkdir(parents=True, exist_ok=True)
    workdir = workdir.resolve()

    key = ssh.prepare_key(args.key, workdir) if args.key else None
    wrapper = ssh.write_wrapper(workdir, host, user, args.port, key, args.password)
    print(f"[*] Workdir: {workdir}")
    print("[*] Preflight: testing connectivity ...")
    ok, out = ssh.test_connection(wrapper)
    if not ok:
        print(f"[x] Could not reach/auth to target:\n{out}", file=sys.stderr)
        return 2
    print(f"[+] Connected: {out.splitlines()[0] if out else 'ok'}\n")

    from .engine import run_engagement
    return run_engagement(
        wrapper=wrapper, workdir=workdir, host=host, port=args.port, user=user,
        model=args.model, use_advisor=not args.no_advisor,
        advisor_rounds=args.advisor_rounds, cron_wait=args.cron_wait,
        chain_depth=args.chain_depth,
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "run":
        return cmd_run(args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
