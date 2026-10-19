"""Command-line entry point: ``amwe <email>``.

Orchestrates the pipeline and nothing more — each stage lives in its own module.
Flow: prove ownership -> run every collector -> render the report.
"""

from __future__ import annotations

import argparse
import asyncio
from collections.abc import Sequence

from rich.console import Console
from rich.table import Table

import amwe.collectors  # noqa: F401  (registers built-in collectors on import)
from amwe.collectors.base import all_collectors
from amwe.models import ScanResult, Target
from amwe.verify.email_verify import ConsoleVerifier, Verifier

_console = Console()


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="amwe",
        description="Attack Me With Everything — scan your own public footprint.",
    )
    parser.add_argument("email", help="the email address you want to scan (must be yours)")
    parser.add_argument(
        "--username",
        help="handle to check across platforms (defaults to the email local part)",
    )
    parser.add_argument(
        "--image-url",
        help="public URL of a photo of yours to check for embedded GPS coordinates",
    )
    parser.add_argument(
        "--yes-this-is-me",
        action="store_true",
        help="skip the interactive ownership prompt (only for your own address)",
    )
    return parser.parse_args(argv)


def _prove_ownership(email: str, verifier: Verifier, *, skip: bool) -> bool:
    if skip:
        return True
    verifier.challenge(email)
    entered = _console.input("[bold]Enter the code sent to your address: [/]")
    return verifier.check(email, entered.strip())


async def _run_collectors(target: Target) -> ScanResult:
    result = ScanResult(target=target)
    for collector in all_collectors():
        async for finding in collector.collect(target):
            result.findings.append(finding)
    return result


def _render(result: ScanResult) -> None:
    table = Table(title="What an attacker can already see about you")
    table.add_column("Source", style="cyan")
    table.add_column("Finding", style="white")
    table.add_column("Severity", style="magenta")
    for finding in result.findings:
        table.add_row(finding.source, finding.value, finding.severity)
    _console.print(table)
    _console.print(
        f"\n[bold red]{len(result.findings)}[/] public traces found. "
        "All of this is legal to look up — that is the point."
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    username = args.username or args.email.split("@", 1)[0]
    target = Target(email=args.email, username=username, image_url=args.image_url)

    if not _prove_ownership(target.email, ConsoleVerifier(), skip=args.yes_this_is_me):
        _console.print("[bold red]Ownership not confirmed. Refusing to scan.[/]")
        return 1

    result = asyncio.run(_run_collectors(target))
    _render(result)
    return 0
