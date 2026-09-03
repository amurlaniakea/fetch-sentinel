# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Excepciones comunes del paquete fetch-sentinel.

Convención: cada subsistema tiene su base (FetchError, GuardError, etc.).
NO hay jerarquía compartida arriba de Exception salvo los casos que
justifiquen un catch-all. Ver sdd/spec.md §4.
"""


class FetchError(Exception):
    """Base para errores de Capa 1 (fetcher.py)."""


class GuardError(Exception):
    """Base para errores de Capa 2 (structural_guard.py)."""


class SandboxError(Exception):
    """Base para errores de Capa 3 (sandbox.py)."""


class WitnessError(Exception):
    """Base para errores de Capa 4.1 (witness_client.py)."""


class CitationError(Exception):
    """Base para errores de Capa 4.2 (citation_tracer.py)."""