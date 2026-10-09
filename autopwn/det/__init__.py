"""detpwn — deterministic, code-driven privilege-escalation engine.

Unlike `autopwn` (which hands the whole engagement to an LLM agent), detpwn runs
a fixed kill-chain in Python: it enumerates the target, matches findings against
known escalation vectors (GTFOBins / SUID / capabilities / weak perms), executes
the high-confidence ones, and verifies root. It only spins up a scoped LLM
advisor when the deterministic vectors are exhausted.
"""
