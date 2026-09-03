# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests del corpus de fuzzing (10 casos semilla, Spec §10).

Cada caso es un .json en este mismo directorio con campos:
- name, description, input_bytes_hex, expect (findings_count_min/max,
  sanitized_text_utf8_hex_does_not_contain, _KNOWN_LIMITATION).

`suspicion_signals_may_contain` se IGNORA aquí: el umbral del score está
abierto (Constitución §6.4), se calibra en Verify, no se asserta aquí.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.structural_guard import sanitize

CORPUS_DIR = Path(__file__).parent
CASES = sorted(p for p in CORPUS_DIR.glob("*.json"))


def _load_cases():
    """Carga todos los .json del corpus en una lista de dicts."""
    out = []
    for p in CASES:
        data = json.loads(p.read_text(encoding="utf-8"))
        out.append(data)
    return out


@pytest.mark.parametrize("case", _load_cases(), ids=lambda c: c["name"])
def test_corpus_case(case: dict) -> None:
    payload_bytes = bytes.fromhex(case["input_bytes_hex"])
    text = payload_bytes.decode("utf-8")

    result = sanitize(text, url="http://example.com/")

    exp = case["expect"]
    fc_min = exp["findings_count_min"]
    fc_max = exp["findings_count_max"]
    assert fc_min <= result.findings_count <= fc_max, (
        f"{case['name']}: findings_count={result.findings_count} "
        f"not in [{fc_min}, {fc_max}]"
    )

    sanitized_hex = result.sanitized_text.encode("utf-8").hex()
    for forbidden_hex in exp["sanitized_text_utf8_hex_does_not_contain"]:
        assert forbidden_hex not in sanitized_hex, (
            f"{case['name']}: {forbidden_hex!r} should have been stripped "
            f"but survived in sanitized text"
        )

    if exp["_KNOWN_LIMITATION"] is not None:
        # Si el caso declara _KNOWN_LIMITATION, debe estar documentado
        # en sdd/KNOWN_ISSUES.md (KI-1 homoglifos, KI-x base64).
        # El test NO falla por la limitación — solo verifica que
        # findings_count_max es 0 (lo que el assert de arriba ya hizo).
        # Esta línea es para hacer explícito que el caso está marcado.
        pass


def test_corpus_has_10_cases() -> None:
    """Verifica que el corpus tiene exactamente 10 casos semilla (Spec §10)."""
    assert len(CASES) == 10, f"corpus has {len(CASES)} cases, expected 10"


def test_corpus_has_all_required_names() -> None:
    expected = {
        "plain-text-benign",
        "TAG-block-mid-word",
        "ZWSP-mid-word",
        "BIDI-RLO-prefix",
        "CONTROL-TOKEN-ignore",
        "CONTROL-TOKEN-system",
        "CONTROL-TOKEN-actua-como",
        "IMPERATIVE-DENSITY-high",
        "KNOWN-LIMITATION-homoglyph-cyrillic",
        "KNOWN-LIMITATION-base64-payload",
    }
    actual = {p.stem for p in CASES}
    assert expected == actual, f"missing: {expected - actual}, extra: {actual - expected}"


def test_corpus_each_case_has_required_fields() -> None:
    required_top = {"name", "description", "input_bytes_hex", "expect"}
    required_expect = {
        "findings_count_min", "findings_count_max",
        "sanitized_text_utf8_hex_does_not_contain", "_KNOWN_LIMITATION",
    }
    for p in CASES:
        data = json.loads(p.read_text(encoding="utf-8"))
        assert required_top <= set(data.keys()), f"{p.name}: missing top fields"
        assert required_expect <= set(data["expect"].keys()), (
            f"{p.name}: missing expect fields"
        )