from __future__ import annotations

import shlex
import subprocess
import time
from typing import Any

from config_loader import load_config
from validation import (
    ValidationError,
    compose,
    log_validation_failures,
    one_of,
    require_non_empty,
    forbid_url_or_path,
    validate_inputs,
)


CONFIG = load_config()


def normalize_target(value: str) -> str:
    return value.strip().lower()


def require_allowed_domain(allowed: set[str] | frozenset[str]):
    normalized_allowed = frozenset(normalize_target(x) for x in allowed)
    allowed_list = ", ".join(sorted(normalized_allowed))

    def validator(value: str) -> None:
        if normalize_target(value) not in normalized_allowed:
            raise ValidationError(f"must be one of: {allowed_list}")

    return validator


validate_target = compose(
    require_non_empty,
    forbid_url_or_path,
    require_allowed_domain(CONFIG.valid_domains),
)

allowed_modes = (
    CONFIG.tools.get("nmap_scan").allowed_modes
    if "nmap_scan" in CONFIG.tools
    else ("safe",)
)


def _build_nmap_command(target: str, mode: str) -> list[str]:
    normalized_target = normalize_target(target)

    if mode == "safe":
        return ["nmap", "-Pn", "--top-ports", "20", normalized_target]

    if mode == "passive":
        return ["nmap", "-sn", normalized_target]

    raise ValidationError(f"unsupported mode: {mode}")


@log_validation_failures(log_dir=CONFIG.logging.run_dir)
@validate_inputs(
    target=validate_target,
    mode=one_of(*allowed_modes),
)
def nmap_scan(
    target: str,
    mode: str = "safe",
    execute: bool = False,
    timeout_seconds: int = 60,
) -> dict[str, Any]:
    command = _build_nmap_command(target, mode)
    started = time.perf_counter()

    result: dict[str, Any] = {
        "tool": "nmap_scan",
        "target": normalize_target(target),
        "mode": mode,
        "command": shlex.join(command),
        "execute": execute,
        "timeout_seconds": timeout_seconds,
    }

    if not execute:
        result["status"] = "accepted_dry_run"
        result["duration_ms"] = round((time.perf_counter() - started) * 1000, 3)
        return result

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_seconds,
        )
    except FileNotFoundError as exc:
        raise ValidationError("nmap is not installed or not available in PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise ValidationError(f"nmap execution exceeded timeout of {timeout_seconds}s") from exc

    result["status"] = "completed"
    result["returncode"] = completed.returncode
    result["stdout"] = completed.stdout
    result["stderr"] = completed.stderr
    result["duration_ms"] = round((time.perf_counter() - started) * 1000, 3)
    return result
