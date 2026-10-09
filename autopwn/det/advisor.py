"""Scoped LLM advisor — invoked only when deterministic vectors are exhausted.

The code stays in control: the advisor only *reasons* (no tools) over the
enumeration output and any artifacts the engine fetched, and returns candidate
shell commands. The engine executes them and verifies root itself.
"""
from __future__ import annotations

import re

from . import gtfobins as g

ADVISOR_SYSTEM = f"""\
You are a Linux privilege-escalation advisor embedded in a deterministic tool.
You are given enumeration output from an AUTHORIZED target where the automated
GTFOBins/SUID/capability/weak-perm checks did NOT yield root. Propose concrete,
NON-INTERACTIVE shell commands (runnable over a plain SSH exec, no tty) that
attempt privilege escalation.

A proof script already exists on the target at {g.PROOF_PATH}; running it as root
prints `uid=0(root)` and the root flag. Prefer commands that end by executing
`{g.PROOF_PATH}` as root, or that `cat /root/root.txt`.

Output ONLY the commands, each in its own ```sh fenced block, most promising
first, at most 4. No prose outside the blocks. If you truly see no vector, output
one block containing exactly: NO_VECTOR
"""

_FENCE_RE = re.compile(r"```(?:sh|bash)?\s*(.*?)```", re.DOTALL)


def _extract(text: str) -> list[str]:
    cmds: list[str] = []
    for block in _FENCE_RE.findall(text):
        c = block.strip()
        if c and c != "NO_VECTOR":
            cmds.append(c)
    return cmds


async def _ask(context: str, model: str) -> list[str]:
    from claude_agent_sdk import (
        query, ClaudeAgentOptions, AssistantMessage, TextBlock,
    )
    options = ClaudeAgentOptions(
        system_prompt=ADVISOR_SYSTEM,
        model=model,
        allowed_tools=[],           # reasoning only; the engine executes
        permission_mode="default",
        max_turns=1,
        setting_sources=[],
    )
    text = ""
    async for message in query(prompt=context, options=options):
        if isinstance(message, AssistantMessage):
            for block in message.content:
                if isinstance(block, TextBlock):
                    text += block.text
    return _extract(text)


def advise(context: str, model: str = "opus") -> list[str]:
    """Synchronous wrapper; returns candidate commands (possibly empty)."""
    import asyncio
    try:
        return asyncio.run(_ask(context, model))
    except Exception as exc:  # noqa: BLE001  (advisor is best-effort)
        print(f"[!] advisor unavailable: {type(exc).__name__}: {exc}")
        return []


def build_context(enum) -> str:
    keep = ["ID", "UNAME", "OS", "SUDO", "SUID", "SGID", "CAPS",
            "PASSWD_W", "SHADOW_R", "CRON", "WWRITE"]
    parts = [f"## {k}\n{enum.get(k) or '(none)'}" for k in keep]
    return "Enumeration output:\n\n" + "\n\n".join(parts)
