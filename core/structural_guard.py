# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Capa 2 — structural_guard: sanitize + delimitadores + score de sospecha.

Política:
- Reutiliza mcp-tool-sanitizer para eliminar TAG/ZWSP/BIDI override.
- NO detecta homoglifos (KI-1, _KNOWN_LIMITATION).
- NO intenta defensa semántica (Constitución §2.3, §5).
- Encierra el texto en delimitadores estructurales explícitos.
- Computa score de sospecha heurístico (sin umbral — calibrar en Verify).
- Falla cerrado si sanitize_text lanza excepción no esperada.

Ver sdd/spec.md §3 para el contrato exacto.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Literal
from xml.sax import saxutils

from mcp_tool_sanitizer import find_hidden, sanitize_text

from core.exceptions import GuardError

# --------------------------------------------------------------------------- #
# Excepciones (Spec §3.8)
# --------------------------------------------------------------------------- #


class EmptyInput(GuardError):
    """Input text vacío."""


class SanitizeFailed(GuardError):
    """sanitize_text() lanzó una excepción no esperada."""

    def __init__(self, original: Exception) -> None:
        super().__init__(f"sanitize_text failed: {original}")
        self.original = original


# --------------------------------------------------------------------------- #
# Tipos
# --------------------------------------------------------------------------- #


SanitizeMode = Literal["strip", "replace"]


@dataclass(frozen=True)
class GuardResult:
    url: str
    mode: SanitizeMode
    sanitized_text: str
    sha256_post_sanitize: str
    delimited_text: str
    suspicion_score: float
    suspicion_signals: list[str] = field(default_factory=list)
    findings_count: int = 0
    sanitization_applied: bool = False


# --------------------------------------------------------------------------- #
# Sanitización (Spec §3.5)
# --------------------------------------------------------------------------- #


def _sanitize(text: str, mode: SanitizeMode) -> tuple[str, int]:
    """Llama a mcp-tool-sanitizer. Retorna (clean_text, findings_count).

    Raises:
        SanitizeFailed: si sanitize_text lanza una excepción no esperada.
    """
    try:
        findings = find_hidden(text)
        clean = sanitize_text(text, mode=mode)
    except (ValueError, TypeError) as e:
        raise SanitizeFailed(e) from e
    return clean, len(findings)


# --------------------------------------------------------------------------- #
# Score de sospecha (Spec §3.6) — sin umbral
# --------------------------------------------------------------------------- #


# Tokens de control que sugieren instrucción incrustada.
# Lista explícita y revisable (NO filtro binario).
_CONTROL_TOKEN_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\bsystem\s*:", "control_token_system_colon"),
    (r"\bassistant\s*:", "control_token_assistant_colon"),
    (r"\buser\s*:", "control_token_user_colon"),
    (r"^#{2,}\s", "control_token_h2_prefix"),
    (r"<\|", "control_token_chatml_open"),
    (r"\|>", "control_token_chatml_close"),
    (r"\bignora\b", "control_token_ignora_es"),
    (r"\bignore\s+previous\b", "control_token_ignore_previous_en"),
    (r"\bdisregard\s+previous\b", "control_token_disregard_previous"),
    (r"\byou\s+are\s+now\b", "control_token_you_are_now"),
    (r"\bact[uú]a\s+como\b", "control_token_actua_como_es"),
    (r"\byour\s+task\s+is\s+to\b", "control_token_your_task_is_to"),
    (r"\bforget\s+(?:everything|all|previous)\b", "control_token_forget"),
    (r"\bexecute\s+(?:the\s+following|this)\b", "control_token_execute"),
    (r"\bsend\s+(?:to|via)\b", "control_token_send"),
)

# Imperativos que en texto legítimo son raros; densidad alta = sospechoso.
_IMPERATIVE_WORDS = frozenset({
    "ignore", "forget", "execute", "delete", "run", "call",
    "respond", "send", "disregard", "override", "ignora", "olvida", "ejecuta", "borra", "responde", "envía",
    "envia", "actúa", "actua",
})

_IMPERATIVE_RE = re.compile(
    r"\b(" + "|".join(re.escape(w) for w in _IMPERATIVE_WORDS) + r")\b",
    re.IGNORECASE,
)

# Run de mayúsculas sostenidas (>30 chars consecutivos en ALLCAPS).
_ALLCAPS_RUN_RE = re.compile(r"[A-Z]{30,}")


def _compute_suspicion(text: str) -> tuple[float, list[str]]:
    """Heurística de sospecha. Retorna (score, signals).

    Score en [0, 1]. Las ponderaciones son orientativas y la suma se
    clampea. NO se fija umbral aquí (Constitución §6.4).
    """
    signals: list[str] = []
    score = 0.0

    # --- imperative_density: densidad de verbos imperativos.
    words = re.findall(r"\w+", text, flags=re.UNICODE)
    n_words = max(len(words), 1)
    n_imperatives = sum(1 for w in words if w.lower() in _IMPERATIVE_WORDS)
    density = n_imperatives / n_words
    if density > 0:
        signals.append(f"imperative_density:{density:.3f}")
    if density > 0.05:  # más de 5% de palabras son imperativos
        score += min(0.3, density * 6)  # 5% → 0.3 (cap)

    # --- register_shift: ALLCAPS run > 30 chars.
    allcaps_runs = _ALLCAPS_RUN_RE.findall(text)
    if allcaps_runs:
        signals.append(f"register_shift:allcaps_run_{len(allcaps_runs[0])}")
        score += min(0.2, 0.05 * len(allcaps_runs))

    # --- control_tokens: presencia de tokens explícitos.
    n_control = 0
    for pattern, signal_name in _CONTROL_TOKEN_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE | re.MULTILINE):
            signals.append(signal_name)
            n_control += 1
    if n_control > 0:
        # Cada token suma una cantidad; cap 0.4.
        score += min(0.4, 0.1 * n_control)

    # --- instruction_framing: frases que enmarcan como instrucción.
    framing_patterns = (
        r"\binstrucciones\s+para\s+ti\b",
        r"\bpara\s+tí\s*,?\s*haz\b",
        r"\bresponde\s+con\b",
    )
    n_framing = 0
    for p in framing_patterns:
        if re.search(p, text, re.IGNORECASE):
            signals.append(f"instruction_framing:{p[:20]}")
            n_framing += 1
    if n_framing > 0:
        score += min(0.1, 0.05 * n_framing)

    score = min(1.0, max(0.0, score))
    return score, signals


# --------------------------------------------------------------------------- #
# Delimitadores (Spec §3.4)
# --------------------------------------------------------------------------- #


def _wrap_delimiters(
    url: str,
    sha256_post_sanitize: str,
    mode: SanitizeMode,
    suspicion: float,
    text: str,
) -> str:
    """Produce el bloque con delimitadores estructurales."""
    url_escaped = saxutils.escape(url, {'"': "&quot;"})
    return (
        f'<fetched_content url="{url_escaped}" '
        f'sha256="{sha256_post_sanitize}" '
        f'mode="{mode}" '
        f'suspicion="{suspicion:.3f}">\n'
        f'{text}\n'
        f'</fetched_content>'
    )


# --------------------------------------------------------------------------- #
# Orquestador público (Spec §3.2)
# --------------------------------------------------------------------------- #


def sanitize(
    text: str,
    *,
    url: str,
    mode: SanitizeMode = "strip",
    include_suspicion_score: bool = True,
) -> GuardResult:
    """Sanitiza el texto, computa score, envuelve en delimitadores.

    Args:
        text: Texto extraído por Capa 1.
        url: Para incluir en delimitadores (atribución).
        mode: "strip" elimina codepoints; "replace" los sustituye por U+FFFD.
        include_suspicion_score: Si False, omite score y signals
            (modo "puerta" rápido). Aún emite delimitadores.

    Returns:
        GuardResult con texto sanitizado, sha256, delimitadores,
        score y signals.

    Raises:
        EmptyInput: si text está vacío.
        SanitizeFailed: si sanitize_text lanza excepción no esperada.
    """
    if not text or not text.strip():
        raise EmptyInput("empty input text")

    clean, findings_count = _sanitize(text, mode)
    sanitization_applied = (clean != text)

    sha256_post_sanitize = hashlib.sha256(clean.encode("utf-8")).hexdigest()

    if include_suspicion_score:
        # Score sobre el texto POST-SANITIZE: es lo que el LLM downstream
        # va a leer realmente. Si lo computáramos sobre el original, un
        # atacante con un TAG block evade la heurística trivialmente
        # (parte la palabra "ignore" en "igno"+TAG+"re" → \b ignore \b no
        # matchea). Verificar en disco: spike_report.md demuestra este
        # patrón.
        score, signals = _compute_suspicion(clean)
    else:
        score, signals = 0.0, []

    delimited = _wrap_delimiters(
        url=url,
        sha256_post_sanitize=sha256_post_sanitize,
        mode=mode,
        suspicion=score,
        text=clean,
    )

    return GuardResult(
        url=url,
        mode=mode,
        sanitized_text=clean,
        sha256_post_sanitize=sha256_post_sanitize,
        delimited_text=delimited,
        suspicion_score=score,
        suspicion_signals=signals,
        findings_count=findings_count,
        sanitization_applied=sanitization_applied,
    )