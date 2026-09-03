# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Capa 4.1 — witness_client: sellado de eventos con HMAC propio.

Patrón W-A' (Constitución §3.4.3):
- fetch-sentinel firma SUS PROPIOS eventos con agent_trace_witness.sign_seal
  usando una clave HMAC DEDICADA (NO la del witness principal del agente).
- Cada evento es un CaptureEvent con payload_sha256 (NO se embebe el
  payload fetched), seal_ref (SHA-256 del SealedSeal firmado).
- Los eventos se escriben a ~/.local/share/fetch-sentinel/events.jsonl,
  append-only, permisos 0o600.

Patrón H de sdd-audit aplicado:
- Permisos restrictivos del keyring (0o600) y store (0o600).
- seal_ref validado contra el SealedSeal REAL (compute_seal_ref), no
  contra un id externo.

Patrón T014 de sdd-audit: el round-trip record/verify está en el mismo
código (WitnessClient), no hay script paralelo "casi igual".
"""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import asdict
from pathlib import Path

from agent_trace_witness import capture
from agent_trace_witness.capture import CaptureEvent
from agent_trace_witness.seal import (
    AgentSpec,
    SealedSeal,
    Tool,
    make_seal,
    sign_seal,
    verify_seal,
)

from core.exceptions import WitnessError

# Tamaño de la clave HMAC (32 bytes = 256 bits, recomendado).
_HMAC_KEY_BYTES = 32

# Permisos restrictivos del keyring y store (Patrón H).
_KEY_FILE_MODE = 0o600
_STORE_FILE_MODE = 0o600


class SealFailed(WitnessError):
    """No se pudo crear/firmar el SealedSeal."""


class StorePermissionError(WitnessError):
    """El store no tiene los permisos esperados."""


class _Paths:
    """Resuelve paths de keyring y store (Patrón I: en cada llamada)."""

    @staticmethod
    def key_path() -> Path:
        home = os.environ.get("HOME", "")
        return Path(home) / ".config" / "fetch-sentinel" / "keys.json"

    @staticmethod
    def store_path() -> Path:
        home = os.environ.get("HOME", "")
        return Path(home) / ".local" / "share" / "fetch-sentinel" / "events.jsonl"


def _load_or_generate_key(key_path: Path) -> str:
    """Carga la clave HMAC del keyring o genera una nueva (32 bytes hex).

    Args:
        key_path: Path al archivo de keys.

    Returns:
        Clave hex (64 chars) lista para sign_seal.

    Raises:
        WitnessError: si no se puede escribir el keyring.
    """
    key_path.parent.mkdir(parents=True, exist_ok=True)

    if key_path.exists():
        data = json.loads(key_path.read_text(encoding="utf-8"))
        # Verifica permisos.
        mode = key_path.stat().st_mode & 0o777
        if mode != _KEY_FILE_MODE:
            raise WitnessError(
                f"keyring {key_path} has mode {oct(mode)}, "
                f"expected {oct(_KEY_FILE_MODE)}"
            )
        return data["key_hex"]

    # Genera clave nueva.
    key_hex = secrets.token_hex(_HMAC_KEY_BYTES)
    key_id = f"fetch-sentinel:{secrets.token_hex(8)}"

    key_path.write_text(
        json.dumps({"key_hex": key_hex, "key_id": key_id}),
        encoding="utf-8",
    )
    os.chmod(key_path, _KEY_FILE_MODE)
    return key_hex


def _make_spec() -> AgentSpec:
    """Declara fetch-sentinel como agente para el witness.

    Importante: tools contiene UNA tool — "fetch" — que es lo que
    fetch-sentinel hace. No declara otras tools del agente principal
    (eso sería el seal del agente, no el de fetch-sentinel).
    Coherente con Constitución §3.3.
    """
    return AgentSpec(
        system_prompt="fetch-sentinel v0.1",
        tools=(Tool(name="fetch", scopes=("read",)),),
        witness_id="fetch-sentinel",
    )


def _make_sealed(key_hex: str) -> SealedSeal:
    """Crea y firma un SealedSeal.

    Nota: passamos `key=key_hex` directamente a sign_seal (no keyring),
    porque fetch-sentinel mantiene su propia clave. El `witness_id` se
    queda en "fetch-sentinel" (constante que identifica al agente);
    el `key_id` (post-firma) identifica la clave específica.
    """
    try:
        spec = _make_spec()
        unsigned = make_seal(spec)  # witness_id="fetch-sentinel" desde spec
        sealed = sign_seal(unsigned, key=key_hex)
        return sealed
    except Exception as e:
        raise SealFailed(f"could not seal: {e}") from e


class WitnessClient:
    """Cliente para emitir y verificar eventos firmados por fetch-sentinel."""

    def __init__(
        self,
        *,
        key_path: Path | None = None,
        store_path: Path | None = None,
    ) -> None:
        # Patrón I: paths se leen en cada llamada, no se cachean.
        self._key_path_override = key_path
        self._store_path_override = store_path

        # Carga/genera clave y crea SealedSeal lazy (en primer record).
        self._key_hex: str | None = None
        self._key_id: str | None = None
        self._sealed: SealedSeal | None = None

    def _ensure_sealed(self) -> SealedSeal:
        """Lazy init: carga clave y crea SealedSeal en el primer uso."""
        if self._sealed is not None:
            return self._sealed

        key_path = self._key_path_override or _Paths.key_path()
        self._key_hex = _load_or_generate_key(key_path)
        # Recupera key_id (que se generó junto con la clave).
        if key_path.exists():
            data = json.loads(key_path.read_text(encoding="utf-8"))
            self._key_id = data.get("key_id", "fetch-sentinel:unknown")
        else:
            self._key_id = "fetch-sentinel:unknown"

        assert self._key_id is not None  # narrow type for pyright
        self._sealed = _make_sealed(self._key_hex)
        return self._sealed

    def _store_path(self) -> Path:
        return self._store_path_override or _Paths.store_path()

    def record(
        self,
        *,
        type: str,
        tool: str | None,
        role: str | None,
        content: bytes | str | dict,
    ) -> CaptureEvent:
        """Registra un evento firmado.

        Args:
            type: Uno de los CHOKE_POINT_EVENT_TYPES del witness.
            tool: Nombre de tool si aplica (p.ej. "fetch").
            role: "user"/"assistant" si aplica a model input/output.
            content: Contenido fetched — se HASHEA, NO se embebe.

        Returns:
            El CaptureEvent creado y persistido.

        Raises:
            WitnessError: si el sellado o la escritura falla.
        """
        sealed = self._ensure_sealed()
        seal_ref = capture.compute_seal_ref(sealed)
        payload_sha256 = capture.compute_payload_hash(content)

        # Construye evento con timestamp explícito (no congelado).
        event = CaptureEvent(
            ts=_now_iso(),
            type=type,  # type: ignore[arg-type]
            tool=tool,
            role=role,
            payload_sha256=payload_sha256,
            seal_ref=seal_ref,
            unsealed=False,
        )

        store = self._store_path()
        store.parent.mkdir(parents=True, exist_ok=True)

        # Append-only: una línea JSON por evento. Usar os.open para
        # controlar el modo del archivo nuevo (Patrón H).
        line = json.dumps(asdict(event), ensure_ascii=False) + "\n"
        file_existed = store.exists()
        if file_existed:
            # Si ya existía, verificamos modo antes de escribir.
            current_mode = store.stat().st_mode & 0o777
            if current_mode > _STORE_FILE_MODE:
                raise StorePermissionError(
                    f"store {store} has mode {oct(current_mode)} (more "
                    f"permissive than {oct(_STORE_FILE_MODE)}); refusing "
                    f"to write sensitive events. Run: chmod 600 {store}"
                )
        try:
            with open(store, "a", encoding="utf-8") as f:
                f.write(line)
            if not file_existed:
                # Archivo recién creado por open("a") — chmod restrictivo.
                os.chmod(store, _STORE_FILE_MODE)
        except OSError as e:
            raise WitnessError(f"could not write to {store}: {e}") from e

        return event

    def verify(self, event: CaptureEvent) -> bool:
        """Verifica que el evento fue firmado por ESTE cliente.

        Raises:
            WitnessError: si la verificación falla por error (no por
                tampering — eso retorna False).
        """
        self._ensure_sealed()
        # Verificar que seal_ref coincide con el SealedSeal que tenemos.
        if self._sealed is None or event.seal_ref != capture.compute_seal_ref(self._sealed):
            return False
        try:
            assert self._key_hex is not None
            return bool(verify_seal(self._sealed, key=self._key_hex))
        except Exception as e:
            raise WitnessError(f"verify failed: {e}") from e


def _now_iso() -> str:
    """ISO-8601 UTC con sufijo +00:00."""
    from datetime import UTC, datetime
    return datetime.now(UTC).isoformat()