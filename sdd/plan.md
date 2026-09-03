# Plan — fetch-sentinel

**Versión:** v0.1 (2026-09-03)
**Anclaje:** `sdd/constitution.md`, `sdd/spec.md`
**Próximo documento:** `sdd/tasks.md`

> El plan define el **orden** de implementación y las **dependencias**
> entre componentes. NO redefine contratos (eso es Spec).

---

## §1. Principio de ordenación

El auditor original aprobó esta secuencia en la propuesta de diseño:

> "capa 3 (sandbox) antes que capa 4 (citas); sin aislamiento de
> privilegios no tiene sentido optimizar trazabilidad."

Esto se mantiene. Pero matizo: **Capa 3 es más de convención que de
código**, así que su implementación es liviana. La carga real está en
Capa 1+2 (readability + sanitize) y Capa 4 (witness + tracer).

Orden propuesto:

```
[1] Tipos y excepciones (core/exceptions.py)
    ↓
[2] Capa 1 — fetcher.py (readability + urllib)
    ↓
[3] Capa 2 — structural_guard.py (mcp-tool-sanitizer + score + delimitadores)
    ↓
[4] Capa 3 — sandbox.py (convenios + assert_safe_environment)
    ↓
[5] Capa 4.1 — witness_client.py (sign_seal + emit JSONL)
    ↓
[6] Capa 4.2 — citation_tracer.py (substring match)
    ↓
[7] main.py (CLI integrador)
    ↓
[8] config.toml, README.md, AGENTS.md
    ↓
[9] Verify: py_compile + pytest + ruff + red-team notes
```

Justificación:

- **[1] antes que todo**: las excepciones son importadas por todos los
  módulos. Sin ellas, los `except FetchError` no existen.
- **[2] antes que [3]**: Capa 2 consume el texto de Capa 1.
- **[3] antes que [4]**: el orden del auditor — sin separación de
  privilegios, el resto es teatro.
- **[5] antes que [6]**: witness_client es dep de citation_tracer (cada
  anclaje emitido es un evento witness). No al revés.
- **[7] integra todo**: llega al final.
- **[8] documentación al final del código**, no antes — README de un repo
  sin código es marketing, no documentación.
- **[9] Verify al final**, con la barra descrita en Constitución §6.

---

## §2. Desglose por fase

### Fase 0 — Tipos y excepciones

- **Qué**: `core/exceptions.py` con jerarquía mínima.
- **Por qué primero**: si una excepción se importa tarde, todas las
  firmas de los módulos se rompen en cascada.
- **Tests**: ningún test (es solo dataclasses + clases de error vacías).
- **Done cuando**: `python -c "from core.exceptions import FetchError, GuardError, WitnessError, CitationError, SandboxError"` no lanza.

### Fase 1 — Capa 1 (`core/fetcher.py`)

- **Qué**:
  - `class FetchResult` (dataclass frozen).
  - `class ReadabilityExtractor(html.parser.HTMLParser)` — descarta zonas
    peligrosas, mantiene headings/párrafos/listas/enlaces.
  - `def fetch(url, *, timeout, max_bytes, allowlist)` — orquesta.
  - `class _HttpFetcher` interno, encapsula urllib.
- **Por qué aislada**: Capa 1 es la única que toca red. Si la separamos
  del resto, podemos testear Capa 2-4 con `FetchResult` sintéticos sin red.
- **Tests** (`tests/test_fetcher.py`):
  - Happy path: HTML simple → texto correcto.
  - `<script>`/`<style>` descartados.
  - `<iframe>` descartado.
  - Atributos `alt`/`title` descartados (no van al texto).
  - Comentarios HTML descartados.
  - Timeout (`httpbin.org/delay/N` si hay red; o mock con socket).
  - `max_bytes` excedido → `SizeExceeded`.
  - Status 404 → `HTTPError`.
  - Content-Type `application/json` → `UnsupportedContentType`.
  - Scheme `file://` → `UnsupportedScheme`.
  - Redirect cross-origin sin allowlist → `RedirectNotAllowed`.
  - Allowlist match → permite.
  - Whitespace colapsado.
- **Done cuando**: todos los tests pasan con número real.

### Fase 2 — Capa 2 (`core/structural_guard.py`)

- **Qué**:
  - `class SanitizeMode = Literal["strip","replace"]`.
  - `class GuardResult` (dataclass frozen).
  - `def sanitize(text, *, url, mode, include_suspicion_score)`.
  - `def _compute_suspicion(text) -> tuple[float, list[str]]` (heurística).
  - `def _wrap_delimiters(url, sha256_post_sanitize, mode, suspicion, text)`.
- **Tests** (`tests/test_structural_guard.py`):
  - Input vacío → `EmptyInput`.
  - TAG block → `findings_count >= 1`, no sobrevive al texto.
  - ZWSP → `findings_count >= 1`.
  - BIDI → `findings_count >= 1`.
  - Modo `replace` → TAG sustituido por U+FFFD.
  - Modo `strip` → TAG eliminado completamente.
  - Delimitadores contienen `url`, `sha256` (64 hex), `mode`, `suspicion`
    (3 decimales).
  - Texto vacío entre delimitadores si input vacío post-sanitize.
  - `sanitize_text` lanza `ValueError` → `SanitizeFailed`.
  - Score crece con densidad de imperativos.
  - Score crece con tokens de control.
  - URL con caracteres XML (`&`, `<`, `>`) se escapa en delimitadores.
  - `_KNOWN_LIMITATION`: test con payload cirílico, assert findings_count == 0.
- **Tests del corpus** (`tests/fuzz_injection_corpus/test_corpus.py`):
  - Itera todos los `.json` del corpus.
  - Para cada caso, valida `expect.findings_count_min/max`,
    `sanitized_text_does_not_contain`, `_KNOWN_LIMITATION`.
  - **`suspicion_signals_may_contain`**: solo se imprime, no se asserta
    (umbral abierto, Constitución §6.4).
- **Done cuando**: todos los tests pasan, incluido el `_KNOWN_LIMITATION`.

### Fase 3 — Capa 3 (`core/sandbox.py`)

- **Qué**:
  - `def assert_safe_environment()` — verifica que las convenciones se
    respetan (no `shell=True` en runtime, paths restringidos, vars de
    entorno filtradas).
  - `def allowed_env(extra: dict[str, str] | None = None) -> dict[str, str]`.
  - `def is_writable(path: Path) -> bool` — chequea que el path está
    dentro de los allowlist de escritura.
- **Tests** (`tests/test_sandbox.py`):
  - `assert_safe_environment` pasa en el entorno de tests (no tiene
    shell=True ni acceso a credenciales).
  - `is_writable` rechaza paths fuera de `~/.local/share/fetch-sentinel/`.
  - `is_writable` acepta paths dentro.
  - `allowed_env` filtra vars no explícitas (no `OPENAI_API_KEY`,
    no `ATW_WITNESS_KEY` del agente principal).
  - `is_writable` con un path controlado por el test (monkeypatch del
    path para evitar dependencia del HOME real).
- **Patrón I aplicado**: los paths se leen **en cada llamada** desde
  `os.environ` o `config.toml`, NO como defaults en `def`. Si no, los
  tests con `monkeypatch.setattr` no afectan.
- **Done cuando**: tests pasan, sandbox integrado en main.py.

### Fase 4 — Capa 4.1 (`core/witness_client.py`)

- **Qué**:
  - `class WitnessClient`:
    - `__init__(self, *, key_path, store_path)` — lazy: carga/genera key.
    - `_load_or_generate_key() -> str` — clave HMAC 32 bytes random.
    - `_make_spec() -> AgentSpec` — declara fetch-sentinel como agente.
    - `_make_seal() -> SealedSeal` — make_seal + sign_seal.
    - `record(self, *, type, tool, role, content) -> CaptureEvent`.
    - `verify(self, event) -> bool` — verifica con la misma clave.
- **Tests** (`tests/test_witness_client.py`):
  - Genera key si no existe (en `tmp_path`).
  - Key file tiene permisos 0o600.
  - Store JSONL tiene permisos 0o600.
  - `record` emite evento con `seal_ref` no vacío.
  - `record` emite evento con `payload_sha256` correcto (de `content`).
  - `verify(event)` retorna True para evento propio.
  - `verify(event)` retorna False si se modifica el `payload_sha256`.
  - Append-only: dos `record` generan dos líneas en el JSONL.
  - **Patrón H aplicado**: permisos restrictivos del keyring y store
    verificados (no 0644 por umask).
  - **Patrón T014**: el script standalone de verificación y el código
    integrado implementan el mismo check (no scripts "casi iguales").
- **Done cuando**: tests pasan, integración con agent-trace-witness
  probada con un round-trip (record → verify True).

### Fase 5 — Capa 4.2 (`core/citation_tracer.py`)

- **Qué**:
  - `class Citation` (dataclass frozen).
  - `def trace(text: str, claim: str) -> Citation`.
- **Tests** (`tests/test_citation_tracer.py`):
  - Match exacto al inicio.
  - Match exacto en medio.
  - Match con caracteres especiales (regex meta-chars NO interpretados).
  - No match → `CitationError.NotFound`.
  - Múltiples matches → devuelve el primero (documentado).
  - `claim` con longitud 0 → `CitationError.EmptyClaim`.
  - `text` con longitud 0 → `CitationError.NotFound`.
  - `sha256_substring` coincide con SHA-256 del substring extraído.
- **Done cuando**: tests pasan.

### Fase 6 — `main.py`

- **Qué**:
  - CLI con `argparse`.
  - Orquesta fetch → guard → (trazado si `--trace`) → output.
  - Exit codes según Spec §8.
  - Integración con sandbox.assert_safe_environment al inicio.
  - Integración con witness_client: cada llamada a `fetch` registra un
    evento `tool_call` + `tool_response` (Capa 4 forense).
- **Tests** (`tests/test_main.py`):
  - Modo puerta con HTML simple → salida contiene delimitadores correctos.
  - Modo trazado con `--trace "..."` → salida contiene Citation.
  - Exit code 2 en FetchError (timeout simulado).
  - Exit code 3 en GuardError (input malformado).
  - `--output json` emite JSON canónico.
- **Done cuando**: tests pasan + ejecución manual con URL de ejemplo.

### Fase 7 — Documentación y config

- **Qué**:
  - `pyproject.toml` — atribución + deps + scripts.
  - `README.md` — H1 nombre, badge licencia, descripción, install, usage,
    limitations (KI-1, KI-2 citadas), license section.
  - `AGENTS.md` — gobernanza para Hermes (versión final, no borrador).
  - `config.toml` — según Spec §9.
- **Tests**: ninguno (documentación).
- **Done cuando**: archivos creados, hash SHA-256 verificado.

### Fase 8 — Verify

- **Qué**:
  - `python -m compileall core/ main.py` → 0 errores.
  - `pytest tests/ -v` → número real, todos verdes.
  - `ruff check .` → 0 issues.
  - `tests/fuzz_injection_corpus/test_corpus.py` → 10/10 casos pasan.
  - Smoke test end-to-end: ejecutar `main.py` contra una URL de prueba
    local (página estática en `tmp_path`) y verificar salida.
  - Red-team notes escritas en `sdd/verify_implementation.md`.
- **Done cuando**: todo lo anterior en verde, notas escritas.

---

## §3. Dependencias entre Tasks

```
[1] → [2] → [3] → [4] → [5] → [6] → [7] → [8]
                       ↘      ↗
                        (5) → (6)
```

[4] Sandbox se testea contra [3] pero no la usa directamente. La
integración se hace en [7].

[6] citation_tracer NO depende de [5] witness_client (Tracer es puro,
sin emisión de eventos). La emisión la hace el llamante (main.py).

---

## §4. Riesgos identificados (lecciones sdd-audit aplicadas)

| Patrón | Dónde se aplica | Mitigación |
|---|---|---|
| **A. Código muerto en if/elif** | Capa 2: orden Unicode → score. | Tests con cada rama ejercitada. |
| **H. Escalada local→sudo** | Capa 4.1: permisos del store + keyring. | Test assert 0o600 en ambos. Validación de seal_ref contra el SealedSeal real, no contra un id externo. |
| **I. Default congelado en import-time** | Capa 3 y 4.1: paths. | Paths leídos en cada llamada desde env/config, NO en `def path=DEFAULT`. |
| **N. Umbrales sin corpus** | Capa 2 score. | Umbral NO se fija en código. Constitución §6.4 lo prohíbe. |
| **P. Homoglifos en detección** | Capa 2. | Test `_KNOWN_LIMITATION`. |
| **T014. Dual-implementation chequea cosas distintas** | Capa 4.1: si hay script standalone de verificación. | El check de `verify(event)` se hace en el código que se exporta, NO en un script separado. Si hay script, debe importar la misma función. |
| **KI-3. Shell-escape de TAG block** | Corpus y tests. | Payloads en hex, no en strings literales con `\u`. |

---

## §5. Cambios a este Plan

Cualquier modificación requiere:
1. PR con diff textual.
2. Justificación.
3. Si cambia el orden de fases, re-correr las fases ya completadas
   para verificar que no hay regresión.
4. Aprobación del auditor.