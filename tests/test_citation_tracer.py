# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests para Capa 4.2 (citation_tracer.py).

Cobertura:
- Match exacto al inicio / medio / final.
- Match con regex meta-chars NO se interpreta como regex.
- Match case-sensitive.
- claim vacío → EmptyClaim.
- text vacío → NotFound.
- claim no presente → NotFound.
- sha256_substring coincide con SHA-256 del substring.
- Si múltiples matches → devuelve el primero (documentado).
"""

from __future__ import annotations

import hashlib

import pytest

from core.citation_tracer import (
    Citation,
    EmptyClaim,
    NotFound,
    trace,
)

# --------------------------------------------------------------------------- #
# Happy path
# --------------------------------------------------------------------------- #


def test_match_at_start():
    text = "the quick brown fox jumps over the lazy dog"
    c = trace(text, "the quick")
    assert c.text == "the quick"
    assert c.start == 0
    assert c.end == len("the quick")


def test_match_in_middle():
    text = "the quick brown fox jumps over the lazy dog"
    c = trace(text, "brown fox")
    assert c.start == text.index("brown fox")
    assert c.end == c.start + len("brown fox")


def test_match_at_end():
    text = "the quick brown fox jumps over the lazy dog"
    c = trace(text, "lazy dog")
    assert c.end == len(text)


def test_match_returns_first_occurrence():
    text = "foo bar foo bar foo bar"
    c = trace(text, "foo bar")
    assert c.start == 0  # primer match


def test_sha256_substring_correct():
    text = "the quick brown fox"
    c = trace(text, "quick brown")
    expected = hashlib.sha256(b"quick brown").hexdigest()
    assert c.sha256_substring == expected


def test_citation_is_dataclass():
    c = trace("hello world", "hello")
    assert isinstance(c, Citation)


# --------------------------------------------------------------------------- #
# Casos de seguridad
# --------------------------------------------------------------------------- #


def test_match_with_regex_metachars_not_interpreted():
    """Si se tratara como regex, 'a.b*c' podría matchear 'aXYZc'. Aquí NO."""
    text = "this text contains a literal a.b*c in the middle"
    c = trace(text, "a.b*c")
    assert c.text == "a.b*c"
    assert c.start == text.index("a.b*c")


def test_match_is_case_sensitive():
    """Case-sensitive: 'HELLO' no matchea 'hello' ni viceversa."""
    text = "Hello world"
    with pytest.raises(NotFound):
        trace(text, "hello")
    c = trace(text, "Hello")
    assert c.start == 0


def test_no_match_raises_not_found():
    with pytest.raises(NotFound):
        trace("hello world", "goodbye")


def test_empty_claim_raises_empty_claim():
    with pytest.raises(EmptyClaim):
        trace("hello", "")


def test_whitespace_only_claim_raises_empty_claim():
    with pytest.raises(EmptyClaim):
        trace("hello", "   \n\t  ")


def test_empty_text_raises_not_found():
    with pytest.raises(NotFound):
        trace("", "anything")


def test_text_with_newlines():
    text = "line one\nline two\nline three"
    c = trace(text, "two")
    assert c.text == "two"
    assert text[c.start:c.end] == "two"


def test_unicode_substring():
    """El match funciona con caracteres no-ASCII."""
    text = "El niño come manzana"
    c = trace(text, "niño come")
    assert c.text == "niño come"
    assert c.start == text.index("niño come")