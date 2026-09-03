# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Capa 4.2 — citation_tracer: anclaje resumen↔fuente (modo trazado).

NO resume. NO genera texto. Recibe (texto_fuente, frase) y devuelve el
anclaje (offset, sha256_substring). El LLM downstream hace el resumen;
fetch-sentinel verifica que cada frase del resumen está en el texto
fuente (substring match, NO fuzzy).

Patrón de citefid: substring match + posición.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from core.exceptions import CitationError

# --------------------------------------------------------------------------- #
# Excepciones
# --------------------------------------------------------------------------- #


class NotFound(CitationError):
    """`claim` no aparece en `text`."""


class EmptyClaim(CitationError):
    """`claim` es vacío."""


# --------------------------------------------------------------------------- #
# Tipo
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Citation:
    text: str
    start: int
    end: int
    sha256_substring: str


# --------------------------------------------------------------------------- #
# Trazado
# --------------------------------------------------------------------------- #


def trace(text: str, claim: str) -> Citation:
    """Encuentra la primera ocurrencia literal de `claim` en `text`.

    Args:
        text: Texto fuente (post-sanitize).
        claim: Frase a anclar (substring literal, NO regex).

    Returns:
        Citation con la frase exacta, sus offsets y SHA-256 del substring.

    Raises:
        EmptyClaim: si claim es vacío o solo whitespace.
        NotFound: si claim no aparece en text (o text es vacío).
    """
    if not claim or not claim.strip():
        raise EmptyClaim("empty claim")
    if not text:
        raise NotFound(f"claim {claim!r} not found in empty text")

    # Substring match literal (NO regex — re.escape defensivo).
    start = text.find(claim)
    if start == -1:
        raise NotFound(f"claim {claim!r} not found in text")

    end = start + len(claim)
    substring = text[start:end]
    sha256_substring = hashlib.sha256(substring.encode("utf-8")).hexdigest()

    return Citation(
        text=substring,
        start=start,
        end=end,
        sha256_substring=sha256_substring,
    )