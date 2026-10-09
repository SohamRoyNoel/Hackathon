"""Claude Agent SDK runner — drives the autonomous engagement loop."""
from __future__ import annotations

import sys
from pathlib import Path

# Tools the operator agent may use. Bash is what actually drives ./ssh.sh.
ALLOWED_TOOLS = ["Bash", "Read", "Write", "Edit", "Grep", "Glob", "WebFetch", "TodoWrite"]

ROOT_FLAG_HINTS = ("root flag", "/root/", "root.txt", "flag captured")


def _summarize_tool(name: str, tool_input: dict) -> str:
    """One-line, readable trace of a tool call for live console output."""
    if name == "Bash":
        cmd = (tool_input or {}).get("command", "")
        cmd = " ".join(cmd.split())
        return f"$ {cmd[:160]}" + ("…" if len(cmd) > 160 else "")
    if name in ("Write", "Edit", "Read"):
        return f"{name} {(tool_input or {}).get('file_path', '')}"
    if name == "WebFetch":
        return f"WebFetch {(tool_input or {}).get('url', '')}"
    return name


async def run_engagement(*, system_prompt: str, task_prompt: str, workdir: Path,
                         model: str, max_turns: int) -> int:
    try:
        from claude_agent_sdk import (
            query, ClaudeAgentOptions, AssistantMessage, ResultMessage,
            TextBlock, ToolUseBlock,
        )
    except ImportError:
        print("[x] claude-agent-sdk is not installed. Run: pip install -e .",
              file=sys.stderr)
        return 3

    options = ClaudeAgentOptions(
        system_prompt=system_prompt,
        model=model,
        allowed_tools=ALLOWED_TOOLS,
        permission_mode="bypassPermissions",  # autonomous: no interactive approval
        max_turns=max_turns,
        cwd=str(workdir),
        setting_sources=[],  # deterministic: ignore ambient .claude settings
    )

    print("[*] Launching autonomous engagement (Ctrl-C to abort)\n" + "-" * 60)
    rc = 1
    try:
        async for message in query(prompt=task_prompt, options=options):
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock):
                        text = block.text.strip()
                        if text:
                            print(text)
                    elif isinstance(block, ToolUseBlock):
                        print(f"  → {_summarize_tool(block.name, block.input)}")
            elif isinstance(message, ResultMessage):
                print("-" * 60)
                if getattr(message, "is_error", False):
                    print(f"[x] Ended with error ({getattr(message, 'subtype', '?')}): "
                          f"{message.result}")
                    rc = 4
                else:
                    print(f"[+] Engagement complete ({getattr(message, 'subtype', 'ok')})")
                    rc = 0
                cost = getattr(message, "total_cost_usd", None)
                if cost is not None:
                    print(f"[*] Cost       : ${cost:.2f}")
    except KeyboardInterrupt:
        print("\n[!] Aborted by operator.", file=sys.stderr)
        rc = 130

    report = workdir / "REPORT.md"
    if report.is_file():
        print(f"[*] Report     : {report}")
    print(f"[*] Workdir    : {workdir}")
    return rc
