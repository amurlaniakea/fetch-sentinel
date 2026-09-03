# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests para Capa 4.1 (witness_client.py).

Cobertura:
- Key file creado con permisos 0o600 (Patrón H).
- Store JSONL creado con permisos 0o600.
- seal_ref siempre no vacío (KI-2, requisito AC-3 del witness).
- payload_sha256 correcto (SHA-256 hex del content).
- payload NO embebido en el evento (solo su hash).
- verify True para evento propio.
- verify False con clave distinta (otro cliente).
- Append-only: dos record → dos líneas.
- StorePermissionError si el store ya existe con permisos amplios.

Patrón T014 aplicado: el round-trip record/verify está en el mismo
código (WitnessClient), no hay script paralelo.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from agent_trace_witness.capture import CaptureEvent

from core import witness_client
from core.witness_client import (
    _KEY_FILE_MODE,
    _STORE_FILE_MODE,
    StorePermissionError,
    WitnessClient,
    _load_or_generate_key,
)

# --------------------------------------------------------------------------- #
# Permisos (Patrón H)
# --------------------------------------------------------------------------- #


def test_key_file_created_with_0600(tmp_path: Path) -> None:
    key_path = tmp_path / "keys.json"
    _load_or_generate_key(key_path)
    mode = key_path.stat().st_mode & 0o777
    assert mode == 0o600, f"keyring mode {oct(mode)} != 0o600"


def test_key_file_existing_with_wrong_mode_raises(tmp_path: Path) -> None:
    key_path = tmp_path / "keys.json"
    key_path.write_text('{"key_hex": "deadbeef", "key_id": "x"}')
    os.chmod(key_path, 0o644)
    with pytest.raises(witness_client.WitnessError) as exc_info:
        _load_or_generate_key(key_path)
    assert "0o644" in str(exc_info.value)
    assert "0o600" in str(exc_info.value)


def test_store_file_created_with_0600(tmp_path: Path) -> None:
    client = WitnessClient(
        key_path=tmp_path / "k.json",
        store_path=tmp_path / "s.jsonl",
    )
    client.record(type="tool_call", tool="fetch", role=None, content="x")
    mode = (tmp_path / "s.jsonl").stat().st_mode & 0o777
    assert mode == 0o600, f"store mode {oct(mode)} != 0o600"


def test_store_file_existing_with_wrong_mode_raises(tmp_path: Path) -> None:
    store_path = tmp_path / "s.jsonl"
    store_path.write_text("")  # crea con umask
    os.chmod(store_path, 0o644)
    client = WitnessClient(
        key_path=tmp_path / "k.json",
        store_path=store_path,
    )
    with pytest.raises(StorePermissionError) as exc_info:
        client.record(type="tool_call", tool="fetch", role=None, content="x")
    assert "0o644" in str(exc_info.value)
    assert "0o600" in str(exc_info.value)


# --------------------------------------------------------------------------- #
# Contenido del evento (KI-2)
# --------------------------------------------------------------------------- #


def test_record_emits_event_with_seal_ref(tmp_path: Path) -> None:
    client = WitnessClient(
        key_path=tmp_path / "k.json",
        store_path=tmp_path / "s.jsonl",
    )
    ev = client.record(type="tool_call", tool="fetch", role=None, content="hello")
    assert ev.seal_ref  # no vacío
    assert len(ev.seal_ref) == 64  # SHA-256 hex
    assert all(c in "0123456789abcdef" for c in ev.seal_ref)


def test_record_payload_sha256_correct(tmp_path: Path) -> None:
    import hashlib
    client = WitnessClient(
        key_path=tmp_path / "k.json",
        store_path=tmp_path / "s.jsonl",
    )
    content = "hello world"
    expected = hashlib.sha256(content.encode("utf-8")).hexdigest()
    ev = client.record(type="tool_call", tool="fetch", role=None, content=content)
    assert ev.payload_sha256 == expected


def test_record_does_not_embed_payload(tmp_path: Path) -> None:
    """El payload fetched NUNCA aparece en el JSONL — solo su hash."""
    client = WitnessClient(
        key_path=tmp_path / "k.json",
        store_path=tmp_path / "s.jsonl",
    )
    secret = "SECRET_TOKEN_DO_NOT_LEAK_xyz123"
    client.record(type="tool_call", tool="fetch", role=None, content=secret)
    raw = (tmp_path / "s.jsonl").read_text(encoding="utf-8")
    assert secret not in raw
    # Pero el hash sí está.
    import hashlib
    expected_hash = hashlib.sha256(secret.encode("utf-8")).hexdigest()
    assert expected_hash in raw


def test_record_accepts_bytes_content(tmp_path: Path) -> None:
    client = WitnessClient(
        key_path=tmp_path / "k.json",
        store_path=tmp_path / "s.jsonl",
    )
    ev = client.record(
        type="tool_call", tool="fetch", role=None,
        content=b"\x00\x01\x02 binary content",
    )
    assert ev.payload_sha256


def test_record_accepts_dict_content(tmp_path: Path) -> None:
    client = WitnessClient(
        key_path=tmp_path / "k.json",
        store_path=tmp_path / "s.jsonl",
    )
    ev = client.record(
        type="tool_call", tool="fetch", role=None,
        content={"key": "value", "n": 42},
    )
    assert ev.payload_sha256


# --------------------------------------------------------------------------- #
# Verify
# --------------------------------------------------------------------------- #


def test_verify_true_for_own_event(tmp_path: Path) -> None:
    client = WitnessClient(
        key_path=tmp_path / "k.json",
        store_path=tmp_path / "s.jsonl",
    )
    ev = client.record(type="tool_call", tool="fetch", role=None, content="x")
    assert client.verify(ev) is True


def test_verify_false_for_event_from_other_client(tmp_path: Path) -> None:
    """Dos clientes con claves distintas: A no puede verificar eventos de B."""
    client_a = WitnessClient(
        key_path=tmp_path / "ka.json",
        store_path=tmp_path / "sa.jsonl",
    )
    client_b = WitnessClient(
        key_path=tmp_path / "kb.json",
        store_path=tmp_path / "sb.jsonl",
    )
    ev_b = client_b.record(type="tool_call", tool="fetch", role=None, content="x")
    # B verifica el suyo.
    assert client_b.verify(ev_b) is True
    # A intenta verificar el de B → falla (seal_ref distinto o clave distinta).
    assert client_a.verify(ev_b) is False


def test_verify_false_after_seal_ref_tampered(tmp_path: Path) -> None:
    """Si alguien modifica seal_ref, verify retorna False."""
    client = WitnessClient(
        key_path=tmp_path / "k.json",
        store_path=tmp_path / "s.jsonl",
    )
    ev = client.record(type="tool_call", tool="fetch", role=None, content="x")
    # Tamper: cambiar seal_ref.
    tampered = CaptureEvent(
        ts=ev.ts,
        type=ev.type,
        tool=ev.tool,
        role=ev.role,
        payload_sha256=ev.payload_sha256,
        seal_ref="0" * 64,
        unsealed=ev.unsealed,
    )
    assert client.verify(tampered) is False


# --------------------------------------------------------------------------- #
# Append-only
# --------------------------------------------------------------------------- #


def test_append_only_two_records(tmp_path: Path) -> None:
    client = WitnessClient(
        key_path=tmp_path / "k.json",
        store_path=tmp_path / "s.jsonl",
    )
    client.record(type="tool_call", tool="fetch", role=None, content="first")
    client.record(type="tool_response", tool="fetch", role=None, content="second")
    lines = (tmp_path / "s.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    # Cada línea es JSON válido.
    for line in lines:
        d = json.loads(line)
        assert "ts" in d
        assert "type" in d
        assert "seal_ref" in d


def test_append_only_preserves_existing_lines(tmp_path: Path) -> None:
    """Un segundo cliente con mismo store_path appendea sin borrar lo previo."""
    client1 = WitnessClient(
        key_path=tmp_path / "k1.json",
        store_path=tmp_path / "shared.jsonl",
    )
    client1.record(type="tool_call", tool="fetch", role=None, content="first")
    # Permisos del store los pone client1.
    store_mode = (tmp_path / "shared.jsonl").stat().st_mode & 0o777
    assert store_mode == 0o600

    client2 = WitnessClient(
        key_path=tmp_path / "k2.json",
        store_path=tmp_path / "shared.jsonl",
    )
    client2.record(type="tool_call", tool="fetch", role=None, content="second")
    lines = (tmp_path / "shared.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2


# --------------------------------------------------------------------------- #
# Patrones A y T014 — checks estructurales
# --------------------------------------------------------------------------- #


def test_sealed_seal_uses_fetch_sentinel_tools(tmp_path: Path) -> None:
    """El SealedSeal declara UNA tool: 'fetch' (no herramientas del agente)."""
    client = WitnessClient(
        key_path=tmp_path / "k.json",
        store_path=tmp_path / "s.jsonl",
    )
    sealed = client._ensure_sealed()
    tool_names = [t.name for t in sealed.tools]
    assert tool_names == ["fetch"]


def test_witness_id_is_fetch_sentinel(tmp_path: Path) -> None:
    client = WitnessClient(
        key_path=tmp_path / "k.json",
        store_path=tmp_path / "s.jsonl",
    )
    sealed = client._ensure_sealed()
    assert sealed.witness_id == "fetch-sentinel"


def test_constants_align_with_constitution() -> None:
    """Patrón H — los permisos están fijados al nivel de la Constitución."""
    assert _KEY_FILE_MODE == 0o600
    assert _STORE_FILE_MODE == 0o600


def test_round_trip_in_same_code_no_dual_implementation() -> None:
    """Patrón T014: el round-trip está en WitnessClient.verify, NO en un
    script externo que pueda diverger."""
    import inspect

    from core.witness_client import WitnessClient
    src = inspect.getsource(WitnessClient)
    assert "def verify" in src
    assert "verify_seal" in src  # usa la función del upstream
    # Verifica que NO hay un script _check_seal.py con implementación alternativa.
    pkg_dir = Path(witness_client.__file__).parent.parent
    forbidden = pkg_dir / "core" / "_check_seal.py"
    assert not forbidden.exists()