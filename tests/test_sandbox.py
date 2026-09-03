# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests para Capa 3 (sandbox.py).

Cobertura:
- is_writable acepta paths dentro de ~/.local/share/fetch-sentinel/
  y ~/.config/fetch-sentinel/.
- is_writable rechaza paths fuera (incluyendo /tmp, /etc, root).
- allowed_env filtra vars no permitidas (OPENAI_API_KEY, etc.).
- assert_safe_environment pasa en entorno de tests.

Patrón I de sdd-audit aplicado: los tests usan monkeypatch en
os.environ (HOME) para que is_writable resuelva la allowlist desde el
path real, sin depender de $HOME del sistema.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from core import sandbox
from core.sandbox import (
    _ENV_ALLOWLIST,
    allowed_env,
    assert_safe_environment,
    is_writable,
)


@pytest.fixture
def fake_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirige HOME a tmp_path y crea los subdirs de la allowlist."""
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".local" / "share" / "fetch-sentinel").mkdir(parents=True)
    (tmp_path / ".config" / "fetch-sentinel").mkdir(parents=True)
    return tmp_path


# --------------------------------------------------------------------------- #
# is_writable
# --------------------------------------------------------------------------- #


def test_is_writable_accepts_local_share(fake_home: Path) -> None:
    target = fake_home / ".local" / "share" / "fetch-sentinel" / "events.jsonl"
    assert is_writable(target) is True


def test_is_writable_accepts_config(fake_home: Path) -> None:
    target = fake_home / ".config" / "fetch-sentinel" / "keys.json"
    assert is_writable(target) is True


def test_is_writable_rejects_tmp(fake_home: Path) -> None:
    target = Path("/tmp/whatever")
    assert is_writable(target) is False


def test_is_writable_rejects_etc(fake_home: Path) -> None:
    target = Path("/etc/passwd")
    assert is_writable(target) is False


def test_is_writable_rejects_home_root(fake_home: Path) -> None:
    target = fake_home / "Documents" / "secret.txt"
    assert is_writable(target) is False


def test_is_writable_rejects_relative_path(fake_home: Path) -> None:
    # Un path relativo que resuelva fuera de la allowlist → False.
    assert is_writable("events.jsonl") is False  # cwd, no en allowlist


# --------------------------------------------------------------------------- #
# allowed_env
# --------------------------------------------------------------------------- #


def test_allowed_env_filters_openai_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-secret")
    env = allowed_env()
    assert "OPENAI_API_KEY" not in env
    assert "sk-secret" not in str(env)


def test_allowed_env_filters_anthropic_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "ant-secret")
    env = allowed_env()
    assert "ANTHROPIC_API_KEY" not in env


def test_allowed_env_filters_atw_witness_key_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    # La var del agente principal (NO la de fetch-sentinel).
    monkeypatch.setenv("ATW_WITNESS_KEY", "agent-key")
    env = allowed_env()
    assert "ATW_WITNESS_KEY" not in env


def test_allowed_env_passes_home(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", "/some/home")
    env = allowed_env()
    assert env.get("HOME") == "/some/home"


def test_allowed_env_passes_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    env = allowed_env()
    assert env.get("PATH") == "/usr/bin:/bin"


def test_allowed_env_passes_fetch_sentinel_own_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ATW_WITNESS_KEY_FETCH_SENTINEL", "fs-key")
    env = allowed_env()
    assert env.get("ATW_WITNESS_KEY_FETCH_SENTINEL") == "fs-key"


def test_allowed_env_does_not_share_reference_with_os_environ(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Defensive copy: modificar el dict retornado NO afecta os.environ."""
    monkeypatch.setenv("HOME", "/orig")
    env = allowed_env()
    env["HOME"] = "/mutated"
    assert os.environ["HOME"] == "/orig"


def test_allowed_env_rejects_extra_var_not_in_allowlist() -> None:
    with pytest.raises(sandbox.SandboxError) as exc_info:
        allowed_env(extra={"UNAUTHORIZED_VAR": "x"})
    assert "UNAUTHORIZED_VAR" in str(exc_info.value)


def test_allowed_env_accepts_extra_var_in_allowlist() -> None:
    env = allowed_env(extra={"HOME": "/custom"})
    assert env["HOME"] == "/custom"


# --------------------------------------------------------------------------- #
# assert_safe_environment
# --------------------------------------------------------------------------- #


def test_assert_safe_environment_passes_with_home(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HOME", "/anywhere")
    assert_safe_environment()  # no raise


def test_assert_safe_environment_raises_without_home(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("HOME", raising=False)
    with pytest.raises(sandbox.SandboxError) as exc_info:
        assert_safe_environment()
    assert "HOME" in str(exc_info.value)


# --------------------------------------------------------------------------- #
# Verificación del invariante
# --------------------------------------------------------------------------- #


def test_env_allowlist_is_explicit() -> None:
    """Las vars en la allowlist están explícitamente listadas. Si añades
    una nueva var (p.ej. para debug), debe ser INTENCIONAL."""
    assert "HOME" in _ENV_ALLOWLIST
    assert "PATH" in _ENV_ALLOWLIST
    # Las sensibles NO están.
    assert "OPENAI_API_KEY" not in _ENV_ALLOWLIST
    assert "ANTHROPIC_API_KEY" not in _ENV_ALLOWLIST
    assert "ATW_WITNESS_KEY" not in _ENV_ALLOWLIST


def test_patrón_i_paths_leídos_en_cada_llamada(
    fake_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Patrón I de sdd-audit: paths se leen en cada llamada, NO como
    defaults congelados en import-time. Cambiar HOME afecta is_writable
    sin reimportar el módulo."""
    target = fake_home / ".local" / "share" / "fetch-sentinel" / "x.jsonl"
    assert is_writable(target) is True

    # Cambiar HOME a otro dir SIN esa estructura.
    new_home = fake_home / "other_home"
    new_home.mkdir()
    monkeypatch.setenv("HOME", str(new_home))
    assert is_writable(target) is False