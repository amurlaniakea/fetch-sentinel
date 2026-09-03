# fetch-sentinel

![License](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Status](https://img.shields.io/badge/status-alpha-yellow)

**Guardián en tiempo de fetch para agentes autónomos que navegan la web.**

Decide, *antes* de que un contenido externo entre al contexto del LLM, qué
partes son seguras de pasar (dato) y cuáles son sospechosas de instrucción
(vector de inyección). Cuatro capas obligatorias: fetch aislado, detección
estructural de inyección, separación de privilegios, trazabilidad firmada.

## Features

- **Capa 1 — Fetch aislado**: extracción *readability* sin regex sobre HTML,
  descartando `<script>`, `<style>`, `<iframe>`, comentarios y atributos.
  Política estricta de esquema (solo `http`/`https`), `Content-Type`,
  timeout, `max_bytes`, allowlist DNS.
- **Capa 2 — Detección estructural de inyección**: reutiliza
  [mcp-tool-sanitizer](https://github.com/amurlaniakea/mcp-tool-sanitizer)
  para TAG block, ZWSP y BIDI override. Envuelve el texto en
  delimitadores `<fetched_content>` que el LLM downstream debe tratar como
  dato. Score de sospecha heurístico, sin umbral fijo (calibrar contra
  corpus).
- **Capa 3 — Separación de privilegios**: el proceso solo escribe en
  `~/.local/share/fetch-sentinel/` y `~/.config/fetch-sentinel/`. Filtra
  variables de entorno (`OPENAI_API_KEY`, `ATW_WITNESS_KEY` del agente
  principal) — no se propagan al subproceso.
- **Capa 4.1 — Sellado HMAC**: cada fetch firma un evento con clave
  dedicada de fetch-sentinel (`agent-trace-witness` en modo W-A'). El
  payload fetched **nunca se embebe**, solo su SHA-256.
- **Capa 4.2 — Trazabilidad de citas**: anclaje substring+SHA-256 entre
  resumen del agente y texto fuente (modo "trazado").

## Install

```bash
# fetch-sentinel requiere dos repos hermanos instalados en editable.
# Esto es intencional: fetch-sentinel orquesta, no reimplementa.

git clone https://github.com/amurlaniakea/fetch-sentinel
cd fetch-sentinel

python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"

# Dependencias runtime desde el código local (no PyPI; ver KI-4).
.venv/bin/pip install -e /home/sil/mcp-tool-sanitizer
.venv/bin/pip install -e /home/sil/agent-trace-witness
```

> Si trabajas en WSL, NO uses `--break-system-packages`. Siempre venv.

## Usage

```bash
# Modo puerta (default): solo sanitiza y emite delimitadores.
.venv/bin/python main.py fetch https://example.com/

# Modo trazado: añade anclas para frases específicas del resumen.
.venv/bin/python main.py fetch https://example.com/ \
    --trace "specific phrase to anchor" \
    --output json
```

Exit codes:

| Code | Significado |
|------|-------------|
| 0 | Éxito |
| 1 | Error de uso |
| 2 | FetchError (URL, timeout, size, etc.) |
| 3 | GuardError (sanitize falló, input vacío) |
| 4 | WitnessError (sellado falló) |
| 5 | SandboxError (entorno inseguro) |

## Limitations (KI declaradas)

- **KI-1 — Homoglifos**: NO se detectan en v0.1. Un atacante puede
  inyectar instrucciones usando caracteres cirílicos u otros homoglifos.
  Depende del PR upstream de Fase 2 de `mcp-tool-sanitizer`. Caso de
  regresión esperada en `tests/fuzz_injection_corpus/`.
- **KI-2 — Sellado obligatorio**: el witness rechaza eventos sin
  `seal_ref` válido. fetch-sentinel firma con su propia clave HMAC.
- **KI-3 — Shell-escape**: TAG block en heredoc de shell se colapsa.
  En tests, usar `chr(0xE00XX)` en código, no `\uE00XX` en string.
- **KI-4 — Versiones PyPI**: `mcp-tool-sanitizer` y `agent-trace-witness`
  pueden tener commits locales no publicados. Instalar desde path.
- **KI-5 — Imports explícitos**: `agent_trace_witness/__init__.py` solo
  expone `__version__`. Importar submódulos explícitamente.
- **KI-6 — repr() de TAG**: comparar TAG por `ord(ch)`, no por string.

Fuera de alcance (Constitución §5): defensa semántica, decodificación
base64/hex, navegación interactiva, resumir contenido, indexar.

## Development

```bash
.venv/bin/python -m pytest tests/                  # 138 tests
.venv/bin/python -m pytest tests/fuzz_injection_corpus/   # 13 corpus tests
.venv/bin/python -m ruff check .                   # lint
.venv/bin/python -m py_compile core/ main.py       # syntax
```

Estructura:

```
fetch-sentinel/
├── AGENTS.md                  # gobernanza para Hermes
├── LICENSE                    # AGPL-3.0-or-later
├── pyproject.toml
├── README.md                  # este archivo
├── config.toml                # paths y límites (sin umbrales)
├── main.py                    # fetch URL → sanitize → (trazado|puerta)
├── core/
│   ├── exceptions.py
│   ├── fetcher.py             # Capa 1
│   ├── structural_guard.py    # Capa 2
│   ├── sandbox.py             # Capa 3
│   ├── witness_client.py      # Capa 4.1
│   └── citation_tracer.py     # Capa 4.2
├── tests/
│   ├── test_fetcher.py
│   ├── test_structural_guard.py
│   ├── test_sandbox.py
│   ├── test_witness_client.py
│   ├── test_citation_tracer.py
│   ├── test_main.py
│   └── fuzz_injection_corpus/ # 10 casos semilla + generator
└── sdd/
    ├── constitution.md        # contrato no negociable
    ├── spec.md                # contratos de fetcher y structural_guard
    ├── plan.md                # orden de fases
    ├── tasks.md               # T01-T43
    ├── spike_report.md        # evidencia cruda del spike de viabilidad
    └── KNOWN_ISSUES.md        # KI-1 a KI-6
```

## License

Copyright © 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>

AGPL-3.0-or-later — ver [LICENSE](LICENSE) para el texto completo.

This program is free software: you can redistribute it and/or modify it
under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or (at
your option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero
General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.