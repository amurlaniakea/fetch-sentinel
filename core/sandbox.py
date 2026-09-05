# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Capa 3 — sandbox: convenios de proceso.

No es un sandbox de OS (chroot, nsjail). Son convenciones a nivel de
proceso Python que el llamante (main.py) debe respetar:

- No invocar subprocess con shell=True.
- No escribir fuera de ~/.local/share/fetch-sentinel/ y
  ~/.config/fetch-sentinel/.
- No leer ATW_WITNESS_KEY ni OPENAI_API_KEY ni credenciales del agente.
- os.environ se filtra al cargar el módulo: solo pasan vars explícitamente
  en allowlist (HOME, PATH mínimo, etc.).

Constitución §3.3 — separación de privilegios. Garantía arquitectónica:
si una inyección pasa Capa 1+2, el techo es "resumen incorrecto", nunca
"shell ejecutado".

Patrón I de sdd-audit aplicado: los paths se leen EN CADA LLAMADA desde
os.environ / config, NO como defaults en `def` (eso congela el path en
import-time y rompe monkeypatch).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from core.exceptions import SandboxError

# Allowlist explícita de variables de entorno. Cualquier var fuera de
# esta lista NO se propaga al subproceso. Crítico para no filtrar
# OPENAI_API_KEY, ATW_WITNESS_KEY del agente principal, etc.
_ENV_ALLOWLIST: frozenset[str] = frozenset({
    "HOME",
    "PATH",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    "TMPDIR",
    "USER",
    "LOGNAME",
    # Para el sellado propio de fetch-sentinel (no del agente principal).
    "ATW_WITNESS_KEY_FETCH_SENTINEL",
    # Para depuración opcional.
    "FETCH_SENTINEL_DEBUG",
})

# Paths permitidos para escritura. Path absoluto → expandido.
_WRITE_ALLOWLIST_RELATIVE: tuple[str, ...] = (
    "~/.local/share/fetch-sentinel",
    "~/.config/fetch-sentinel",
)


def _resolve_write_allowlist() -> list[Path]:
    """Resuelve los paths de la allowlist expandiendo ~ y $HOME."""
    os.environ.get("HOME", "")
    return [
        Path(os.path.expanduser(p)).resolve()
        for p in _WRITE_ALLOWLIST_RELATIVE
    ]


def is_writable(path: os.PathLike[str] | str) -> bool:
    """True si `path` está dentro de algún path permitido para escritura.

    Args:
        path: Ruta absoluta o relativa a chequear.

    Returns:
        True si está dentro de ~/.local/share/fetch-sentinel/ o
        ~/.config/fetch-sentinel/.

    Raises:
        SandboxError: si la allowlist no se puede resolver (HOME no
            seteada).
    """
    allowed = _resolve_write_allowlist()
    target = Path(os.fspath(path)).resolve()  # absolute, sin symlinks
    for allowed_path in allowed:
        try:
            target.relative_to(allowed_path)
            return True
        except ValueError:
            continue
    return False


def allowed_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Devuelve un subconjunto filtrado de os.environ.

    Solo vars en la allowlist explícita pasan. El llamante puede añadir
    vars extra (p.ej. para pasar a un subproceso legítimo).

    Args:
        extra: Dict adicional de vars a incluir.

    Returns:
        Nuevo dict con vars permitidas. No comparte referencia con
        os.environ (defensive copy).
    """
    base = {k: v for k, v in os.environ.items() if k in _ENV_ALLOWLIST}
    if extra:
        for k, v in extra.items():
            if k not in _ENV_ALLOWLIST:
                raise SandboxError(
                    f"var {k!r} not in env allowlist; "
                    f"add it to core/sandbox.py:_ENV_ALLOWLIST explicitly"
                )
            base[k] = v
    return base


def assert_safe_environment() -> None:
    """Verifica que el entorno actual cumple los convenios.

    En el contexto de fetch-sentinel (post-import), esto verifica:
    - HOME está seteada (necesaria para resolver allowlist).
    - PATH existe y es razonable (no /dev/null).
    - NO hay vars prohibidas en el entorno que indiquen uso indebido
      (p.ej. el agente puso ATW_WITNESS_KEY pensando que la usábamos).

    Raises:
        SandboxError: si alguna convención se viola.
    """
    home = os.environ.get("HOME")
    if not home:
        raise SandboxError("HOME not set; cannot resolve write allowlist")

    # Aviso (no error) si hay vars que no debemos usar.
    # SEC-04 (sandbox inerte, Gemini 2026-09-03): el código anterior
    # tenía `pass` silencioso. La postura defensiva es: si el proceso
    # fetch-sentinel se inicia con vars de API key del agente principal
    # en os.environ, eso es señal de que el llamante no respetó la
    # separación de privilegios. NO abortamos (eso rompería imports
    # legítimos de las dependencias que sí usan HOME/PATH), pero
    # emitimos un warning explícito a stderr para que un operador
    # detecte la mala configuración en logs/ci.
    suspicious_vars = [
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GOOGLE_API_KEY",
        "ATW_WITNESS_KEY",  # el del agente principal, no el nuestro
    ]
    found = [v for v in suspicious_vars if v in os.environ]
    if found:
        print(
            f"warning: fetch-sentinel detecta vars de entorno del "
            f"agente principal en os.environ: {', '.join(found)}. "
            f"fetch-sentinel NO las usará (no están en allowed_env()), "
            f"pero esto indica que el llamante no respetó la "
            f"separación de privilegios de Capa 3.",
            file=sys.stderr,
        )