"""Tool runner — executes an external recon binary and captures output.

Recon tools make their own connections (they do NOT pass through the egress
chokepoint); the launch gate + default-deny firewall are their controls. This
runner is injectable so the worker is tested without the tools installed.
"""

from __future__ import annotations

import asyncio
import shutil
from dataclasses import dataclass


@dataclass
class ToolResult:
    returncode: int
    stdout: str
    stderr: str


class ToolRunner:
    async def run(self, argv: list[str], timeout: float) -> ToolResult:
        if not argv:
            raise ValueError("empty argv")
        if shutil.which(argv[0]) is None:
            raise FileNotFoundError(f"tool not installed: {argv[0]}")
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise TimeoutError(f"{argv[0]} timed out after {timeout}s")
        return ToolResult(
            returncode=proc.returncode or 0,
            stdout=out.decode(errors="replace"),
            stderr=err.decode(errors="replace"),
        )
