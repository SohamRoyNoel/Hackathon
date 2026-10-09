"""Discover and parse autopwn / detpwn engagement REPORT.md files."""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

FLAG_RE = re.compile(r"(?:[A-Za-z0-9_]+\{[^}]{2,}\}|\b[0-9a-f]{32}\b)")
DIR_RE = re.compile(r"^(?P<tool>det-)?(?P<host>.+?)-(?P<ts>\d{8}-\d{6})$")
_SKIP = ("/.venv/", "/site-packages/", "/node_modules/")


def _section(md: str, name: str) -> str:
    m = re.search(rf"^##\s+{re.escape(name)}\s*$(.*?)(?=^##\s|\Z)", md,
                  re.MULTILINE | re.DOTALL)
    return m.group(1).strip() if m else ""


def _header_val(md: str, key: str) -> str:
    m = re.search(rf"^{re.escape(key)}:\s*(.+)$", md, re.MULTILINE)
    return m.group(1).strip() if m else ""


SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
STATUS_RANK = {"exploited": 0, "attempted": 1, "identified": 2}
_FINDING_RE = re.compile(r"^-\s*\[(\w+)\]\[(\w+)\]\s*(.*?)\s*::\s*(.*)$")


def _severity_kw(text: str) -> str:
    t = text.lower()
    if any(w in t for w in ("pwnkit", "pkexec", "unrestricted sudo", "writable passwd",
                            "-> root", "suid", "cap_setuid", "docker")):
        return "critical"
    if any(w in t for w in ("cron", "shadow", "preload", "env_keep", "-> role",
                            "became", "read root", "lateral")):
        return "high"
    if any(w in t for w in ("custom suid", "private key", "group", "sgid")):
        return "medium"
    if "kernel" in t:
        return "low"
    return "medium"


def extract_findings(md: str, attempts: list[dict], analysis: str) -> list[dict]:
    sec = _section(md, "Findings")
    out: list[dict] = []
    if sec and sec.strip() not in ("- (none)", ""):
        for line in sec.splitlines():
            m = _FINDING_RE.match(line.strip())
            if m:
                out.append({"severity": m.group(1), "status": m.group(2),
                            "title": m.group(3), "user": m.group(4)})
    if out:
        return _rank_findings(out)
    # fallback: derive from attempts + analysis leads (older reports)
    seen = set()
    for a in attempts:
        title = a["text"]
        if title in seen:
            continue
        seen.add(title)
        out.append({"severity": _severity_kw(title),
                    "status": "exploited" if a["ok"] else "attempted",
                    "title": title, "user": ""})
    for line in analysis.splitlines():
        mm = re.match(r"-\s+(.*)", line.strip())
        if mm and ":" in mm.group(1):
            title = mm.group(1)
            if title not in seen:
                seen.add(title)
                out.append({"severity": _severity_kw(title), "status": "identified",
                            "title": title, "user": ""})
    return _rank_findings(out)


def _rank_findings(fs: list[dict]) -> list[dict]:
    return sorted(fs, key=lambda f: (STATUS_RANK.get(f["status"], 3),
                                     SEV_RANK.get(f["severity"], 2)))


def sev_counts(findings: list[dict]) -> dict:
    c = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        c[f["severity"]] = c.get(f["severity"], 0) + 1
    return c


def classify(result_text: str, flags: list[str]) -> str:
    low = result_text.lower()
    if "root shell achieved" in low or ("root" in low and "not" not in low and "no root" not in low):
        return "root"
    if flags:
        return "flags"
    return "none"


def parse_report(path: Path) -> dict:
    md = path.read_text(errors="replace")
    d = path.parent
    m = DIR_RE.match(d.name)
    tool = "detpwn" if (m and m.group("tool")) else ("detpwn" if md.startswith("# detpwn") else "autopwn")
    host = m.group("host") if m else d.name
    try:
        ts = datetime.strptime(m.group("ts"), "%Y%m%d-%H%M%S") if m else \
             datetime.fromtimestamp(path.stat().st_mtime)
    except Exception:  # noqa: BLE001
        ts = datetime.fromtimestamp(path.stat().st_mtime)

    result_text = _section(md, "Result") or "unknown"
    flags = sorted(set(FLAG_RE.findall(_section(md, "Flags") or md)))

    attempts = []
    for line in (_section(md, "Attempts")).splitlines():
        line = line.strip()
        mm = re.match(r"\[([+\-])\]\s*(.*)", line)
        if mm:
            attempts.append({"ok": mm.group(1) == "+", "text": mm.group(2)})

    users = [u.strip() for u in _header_val(md, "Users traversed").split(",") if u.strip() and u.strip() != "-"]

    analysis = _section(md, "Analysis")
    findings = extract_findings(md, attempts, analysis)
    status = classify(result_text, flags)
    return {
        "findings": findings,
        "sev_counts": sev_counts(findings),
        "exploited": [f for f in findings if f["status"] == "exploited"],
        "id": str(d),
        "name": d.name,
        "tool": tool,
        "host": host,
        "timestamp": ts.isoformat(timespec="seconds"),
        "ts_epoch": ts.timestamp(),
        "status": status,
        "result": result_text,
        "flags": flags,
        "flag_count": len(flags),
        "attempts": attempts,
        "attempt_count": len(attempts),
        "users": users,
        "start_user": _header_val(md, "Start user"),
        "analysis": analysis,
        "raw": md,
    }


def discover(root: Path) -> list[dict]:
    out = []
    for p in root.rglob("REPORT.md"):
        sp = str(p)
        if any(s in sp for s in _SKIP):
            continue
        try:
            out.append(parse_report(p))
        except Exception:  # noqa: BLE001
            continue
    out.sort(key=lambda e: e["ts_epoch"], reverse=True)
    return out


def summarize(engagements: list[dict]) -> dict:
    all_flags = {f for e in engagements for f in e["flags"]}
    crit = sum(e["sev_counts"].get("critical", 0) for e in engagements)
    high = sum(e["sev_counts"].get("high", 0) for e in engagements)
    exploited = sum(len(e["exploited"]) for e in engagements)
    return {
        "total": len(engagements),
        "roots": sum(1 for e in engagements if e["status"] == "root"),
        "with_flags": sum(1 for e in engagements if e["flags"]),
        "unique_flags": len(all_flags),
        "targets": len({e["host"] for e in engagements}),
        "critical": crit,
        "high": high,
        "exploited": exploited,
    }
