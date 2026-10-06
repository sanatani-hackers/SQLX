"""
sqlx/sqlmap/options.py
~~~~~~~~~~~~~~~~~~~~~~
SQLMap argument validation and safety helpers.
Ensures safe defaults and prevents accidentally dangerous flag combinations.
"""
from __future__ import annotations
from typing import Dict, List, Set

# Flags considered destructive — need explicit user approval
DESTRUCTIVE_FLAGS: Set[str] = {
    "--dump", "--dump-all", "--all",
    "--os-cmd", "--os-shell", "--os-pwn",
    "--sql-shell", "--sql-query",
    "--file-write", "--file-dest",
}

# Flags that break automated/batch mode
INTERACTIVE_FLAGS: Set[str] = {"--wizard", "-z"}


def validate_args(args: List[str]) -> Dict:
    """
    Validate a list of SQLMap args.

    Returns::

        {
          'valid':       bool,
          'is_safe':     bool,
          'destructive': list[str],
          'interactive': list[str],
          'warnings':    list[str],
        }
    """
    destructive = [a for a in args if a in DESTRUCTIVE_FLAGS]
    interactive = [a for a in args if a in INTERACTIVE_FLAGS]
    warnings: List[str] = []

    if "--level" in args:
        try:
            lvl = int(args[args.index("--level") + 1])
            if lvl > 3:
                warnings.append(f"Level {lvl} generates heavy traffic — consider level ≤3 first")
        except (IndexError, ValueError):
            pass

    if "--risk" in args:
        try:
            risk = int(args[args.index("--risk") + 1])
            if risk > 2:
                warnings.append(f"Risk {risk} may cause data modification — use with care")
        except (IndexError, ValueError):
            pass

    return {
        "valid":       not interactive,
        "is_safe":     not destructive and not interactive,
        "destructive": destructive,
        "interactive": interactive,
        "warnings":    warnings,
    }


def ensure_safe_defaults(args: List[str]) -> List[str]:
    """Add --batch if missing; remove interactive flags."""
    result = [a for a in args if a not in INTERACTIVE_FLAGS]
    if "--batch" not in result:
        result.append("--batch")
    return result


def describe_args(args: List[str]) -> str:
    """Return a one-line human description of what these args will do."""
    parts: List[str] = []
    try:
        idx = args.index("-u") if "-u" in args else args.index("--url")
        parts.append(f"Target: {args[idx + 1]}")
    except (ValueError, IndexError):
        pass
    if "--dbs" in args:
        parts.append("Enumerate databases")
    if "--tables" in args:
        parts.append("Enumerate tables")
    if "--dump" in args:
        parts.append("DUMP DATA (destructive read)")
    if "--dump-all" in args or "--all" in args:
        parts.append("DUMP ALL DATA (very destructive)")
    for flag, label in [("--level", "Level"), ("--risk", "Risk"), ("--tamper", "Tamper")]:
        if flag in args:
            try:
                parts.append(f"{label}: {args[args.index(flag) + 1]}")
            except (IndexError, ValueError):
                pass
    return " | ".join(parts) if parts else "Standard injection scan"
