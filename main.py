#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""CLI de fetch-sentinel.

Uso:
    python -m fetch_sentinel fetch <URL> [opciones]

Ver sdd/spec.md §8 para el contrato exacto.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from core import citation_tracer as ct
from core import exceptions
from core import fetcher as ft
from core import sandbox as sb
from core import structural_guard as sg
from core import witness_client as wc

# Exit codes según Spec §8.
_EXIT_OK = 0
_EXIT_USAGE = 1
_EXIT_FETCH = 2
_EXIT_GUARD = 3
_EXIT_WITNESS = 4
_EXIT_SANDBOX = 5


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="fetch-sentinel",
        description="Lectura segura de URLs con defensa estructural contra inyeccion.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    f = sub.add_parser("fetch", help="Descargar y sanitizar una URL")
    f.add_argument("url", help="URL http o https")
    f.add_argument("--mode", choices=("strip", "replace"), default="strip",
                   help="Modo de sanitizacion (default: strip)")
    f.add_argument("--trace", action="append", default=[],
                   help="Frase a anclar en el texto (modo trazado). Repetible.")
    f.add_argument("--no-suspicion-score", action="store_true",
                   help="Omitir el score de sospecha (modo puerta rapido)")
    f.add_argument("--timeout", type=float, default=10.0,
                   help="Timeout en segundos (default: 10)")
    f.add_argument("--max-bytes", type=int, default=5_000_000,
                   help="Tope de bytes del body)")
    f.add_argument("--allowlist", action="append", default=[],
                   help="Patron DNS permitido (sufijo). Repetible.")
    f.add_argument("--output", choices=("human", "json"), default="human",
                   help="Formato de salida")

    return p


def _cmd_fetch(args: argparse.Namespace) -> int:
    sb.assert_safe_environment()

    # Capa 1 — fetch.
    fetch_result = ft.fetch(
        args.url,
        timeout=args.timeout,
        max_bytes=args.max_bytes,
        allowlist=args.allowlist or None,
    )

    # Capa 4.1 — witness: registrar tool_call.
    witness = wc.WitnessClient()
    witness.record(
        type="tool_call",
        tool="fetch",
        role=None,
        content=fetch_result.text,
    )

    # Capa 2 — sanitize + delimitadores.
    guard_result = sg.sanitize(
        fetch_result.text,
        url=args.url,
        mode=args.mode,
        include_suspicion_score=not args.no_suspicion_score,
    )

    # Capa 4.1 — witness: registrar tool_response (post-sanitize).
    witness.record(
        type="tool_response",
        tool="fetch",
        role=None,
        content=guard_result.sanitized_text,
    )

    # Capa 4.2 — citation (solo si --trace).
    citations = []
    if args.trace:
        for claim in args.trace:
            citation = ct.trace(guard_result.sanitized_text, claim)
            citations.append({
                "claim": citation.text,
                "start": citation.start,
                "end": citation.end,
                "sha256_substring": citation.sha256_substring,
            })

    # Output.
    if args.output == "json":
        out = {
            "url": guard_result.url,
            "mode": guard_result.mode,
            "sha256_post_sanitize": guard_result.sha256_post_sanitize,
            "suspicion_score": guard_result.suspicion_score,
            "suspicion_signals": guard_result.suspicion_signals,
            "findings_count": guard_result.findings_count,
            "sanitization_applied": guard_result.sanitization_applied,
            "delimited_text": guard_result.delimited_text,
            "citations": citations,
        }
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print(guard_result.delimited_text)
        if citations:
            print()
            print("--- citations ---")
            for c in citations:
                print(f"  [{c['start']}:{c['end']}] sha256={c['sha256_substring'][:16]}... "
                      f"-> {c['claim']!r}")

    return _EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "fetch":
            return _cmd_fetch(args)
        parser.error(f"unknown command: {args.command}")
        return _EXIT_USAGE
    except exceptions.FetchError as e:
        print(f"fetch error: {e}", file=sys.stderr)
        return _EXIT_FETCH
    except exceptions.GuardError as e:
        print(f"guard error: {e}", file=sys.stderr)
        return _EXIT_GUARD
    except exceptions.WitnessError as e:
        print(f"witness error: {e}", file=sys.stderr)
        return _EXIT_WITNESS
    except exceptions.SandboxError as e:
        print(f"sandbox error: {e}", file=sys.stderr)
        return _EXIT_SANDBOX
    except exceptions.CitationError as e:
        print(f"citation error: {e}", file=sys.stderr)
        return _EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())