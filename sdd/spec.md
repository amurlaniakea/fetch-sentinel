# Spec — fetch-sentinel

**Versión:** v0.1 (2026-09-03)
**Anclaje:** `sdd/constitution.md` (commit `8956456`)
**Próximo documento:** `sdd/plan.md`

> Esta spec define los **contratos** de los módulos. NO define el orden de
> implementación (eso es `plan.md`) ni el desglose en tareas (eso es
> `tasks.md`). Si un cambio toca §2-§6 de la Constitución, requiere
> reapertura de la Constitución primero.

---

## §1. Resumen arquitectónico (referencia rápida)

```
fetch-sentinel/
├── core/
│   ├── exceptions.py        # tipología de errores
│   ├── fetcher.py           # Capa 1: HTTP → texto readability
│   ├── structural_guard.py  # Capa 2: sanitize_text + delimitadores + score
│   ├── sandbox.py           # Capa 3: procesos sin shell, fs read-only
│   ├── citation_tracer.py   # Capa 4: anclaje resumen↔fuente (modo trazado)
│   └── witness_client.py    # Capa 4: sign_seal + emit JSONL
├── tests/
│   ├── fuzz_injection_corpus/   # casos con expect declarado a priori
│   ├── test_fetcher.py
│   ├── test_structural_guard.py
│   ├── test_sandbox.py
│   ├── test_citation_tracer.py
│   └── test_witness_client.py
├── main.py                  # CLI: fetch URL → sanitize → (trazado|puerta)
├── config.toml              # allowlist, paths de store, sin umbrales
├── pyproject.toml
├── AGENTS.md
├── LICENSE                  # AGPL-3.0-or-later
└── README.md
```

Stack confirmado en Constitución §8:
- **runtime**: stdlib (`html.parser`, `urllib`, `hashlib`, `hmac`, `secrets`,
  `json`, `tomllib`), `mcp-tool-sanitizer>=0.1.0`, `agent-trace-witness>=0.1.0`.
- **dev**: `pytest`, `pytest-cov`, `ruff`, `hypothesis`, `repomapper`.
- **prohibido en runtime**: `torch`, `requests`, `beautifulsoup4`, `lxml`,
  `httpx`. Cualquier dep externa adicional requiere justificación escrita
  en Spec o Plan.

---

## §2. Capa 1 — `core/fetcher.py`

### §2.1 Responsabilidad

Resolver UNA URL `http://` o `https://`, descargar el recurso, extraer el
**texto estructural** (readability mínima: headings, párrafos, listas,
enlaces), descartar zonas peligrosas. Devolver el texto + metadatos. **NO
devuelve HTML crudo al llamante**.

### §2.2 Contrato de entrada

```python
def fetch(url: str, *, timeout: float = 10.0,
          max_bytes: int = 5_000_000,
          allowlist: list[str] | None = None) -> FetchResult:
```

| Parámetro | Tipo | Default | Notas |
|---|---|---|---|
| `url` | `str` | — | Obligatorio. Solo `http://` o `https://`. |
| `timeout` | `float` | `10.0` | Segundos. Aplica a connect + read. |
| `max_bytes` | `int` | `5_000_000` | Tope duro del cuerpo. Si excede, `FetchError.SizeExceeded`. |
| `allowlist` | `list[str]` | `None` | Si se da, la URL debe matchear al menos un patrón (sufijo DNS). Si `None`, no hay allowlist. |

### §2.3 Contrato de salida

```python
@dataclass(frozen=True)
class FetchResult:
    url: str                          # URL final (post-redirección)
    final_url: str                    # mismo campo, semántica clara
    text: str                         # texto extraído (readability)
    sha256_html: str                  # SHA-256 hex del HTML ORIGINAL recibido
    sha256_text: str                  # SHA-256 hex del texto extraído
    content_type: str                 # p.ej. "text/html; charset=utf-8"
    status_code: int                  # 200, 404, etc.
    bytes_read: int                   # bytes efectivamente leídos
    extraction_notes: list[str]       # advertencias ("<script> descartado", etc.)
```

**Decisión sobre `sha256_html`**: se mantiene el HTML original hasheado para
auditoría forense posterior. NO se embebe en eventos de witness (eso es Capa 4).

### §2.4 Política de fetch

| Caso | Comportamiento |
|---|---|
| Esquema ≠ `http`/`https` | `FetchError.UnsupportedScheme` |
| Status ≥ 400 | `FetchError.HTTPError(status_code)` |
| `Content-Type` no comienza con `text/html` | `FetchError.UnsupportedContentType` |
| Body > `max_bytes` | `FetchError.SizeExceeded` (lectura parcial abortada) |
| Timeout | `FetchError.Timeout` |
| Redirect a esquema no permitido | `FetchError.UnsupportedScheme` |
| Redirect cross-origin sin allowlist match | `FetchError.RedirectNotAllowed` |

**Sin reintentos**. Si falla, falla. Capa 3 (sandbox) decide qué hacer.

### §2.5 Política de extracción (readability mínima)

Implementación propia sobre `html.parser.HTMLParser` (stdlib), **SIN** regex
sobre HTML. Pasos:

1. Recorrer el árbol DOM una vez, manteniendo un stack de elementos.
2. **Descartar siempre** el contenido de: `<script>`, `<style>`, `<iframe>`,
   `<noscript>`, `<object>`, `<embed>`, `<template>`.
3. **Conservar** como texto: `<title>`, headings (`h1`-`h6`), `<p>`,
   `<li>`, `<blockquote>`, `<pre>`, `<a>` (solo el texto del enlace, NO el
   href), `<td>`/`<th>` dentro de tablas.
4. **Descartar siempre** el contenido de: comentarios HTML `<!-- -->`,
   atributos (`alt`, `title`, `data-*`, etc.).
5. Whitespace: colapsar runs de whitespace a un solo espacio, preservar
   saltos de línea entre bloques top-level (`<p>`, `<h*>`, `<li>`).

Justificación de "stdlb only, sin readability-lxml":
- Cero deps nativas (lxml es C-extension, complica sandbox).
- Cero deps externas = superficie de ataque mínima en runtime.
- Si la extracción stdlib resulta insuficiente para casos reales, se
  justifica empíricamente y se considera `readability-lxml` en Fase 2.

### §2.6 Errores (definidos en `core/exceptions.py`)

```python
class FetchError(Exception):
    """Base. NO se exporta al llamante final como tal; se mapea en main.py."""

class UnsupportedScheme(FetchError): ...        # file://, javascript:, etc.
class UnsupportedContentType(FetchError): ...  # image/png, application/json, etc.
class HTTPError(FetchError):
    def __init__(self, status_code: int): ...
class SizeExceeded(FetchError):
    def __init__(self, limit: int, partial_bytes: int): ...
class Timeout(FetchError): ...
class RedirectNotAllowed(FetchError):
    def __init__(self, from_url: str, to_url: str): ...
class EmptyBody(FetchError): ...               # body = 0 bytes post-extracción
```

---

## §3. Capa 2 — `core/structural_guard.py`

### §3.1 Responsabilidad

Tomar el texto extraído por Capa 1, **eliminar vectores conocidos de
inyección estructural** (TAG block, ZWSP, BIDI override — reutilizando
`mcp-tool-sanitizer`), envolver el resultado en **delimitadores
estructurales explícitos**, computar un **score de sospecha heurístico**.
**NO intenta defensa semántica** (Constitución §2.3, §5).

### §3.2 Contrato de entrada

```python
def sanitize(text: str, *,
             url: str,
             mode: SanitizeMode = "strip",
             include_suspicion_score: bool = True) -> GuardResult:
```

| Parámetro | Tipo | Default | Notas |
|---|---|---|---|
| `text` | `str` | — | Texto extraído por Capa 1. Vacío → `EmptyInput`. |
| `url` | `str` | — | Para incluir en delimitadores (atribución). |
| `mode` | `Literal["strip","replace"]` | `"strip"` | `strip` quita; `replace` sustituye por U+FFFD. |
| `include_suspicion_score` | `bool` | `True` | Si False, omite el score (modo "puerta" rápido). |

### §3.3 Contrato de salida

```python
@dataclass(frozen=True)
class GuardResult:
    url: str
    mode: SanitizeMode            # "strip" o "replace"
    sanitized_text: str           # post-sanitize, listo para delimitadores
    sha256_post_sanitize: str     # SHA-256 hex de sanitized_text
    delimited_text: str           # bloque con delimitadores, listo para LLM
    suspicion_score: float        # 0.0..1.0
    suspicion_signals: list[str]  # ["imperative_density:high", ...]
    findings_count: int           # cuántos codepoints ocultos se quitaron
    sanitization_applied: bool    # False si text == sanitized_text
```

**Decisión sobre `sha256_post_sanitize`** (la pregunta que dejé pendiente):
el sha256 que viaja en los delimitadores es el del texto **post-sanitize**
(justificación: es lo que el LLM downstream va a leer realmente; la
auditoría forense quiere saber qué BYTES recibió el LLM, no qué descargó
el fetcher — para eso está `sha256_html` en `FetchResult`).

### §3.4 Formato de delimitadores (contrato exacto, byte-a-byte)

```
<fetched_content url="{url}" sha256="{sha256_post_sanitize}" mode="{mode}" suspicion="{suspicion_score:.3f}">
{sanitized_text}
</fetched_content>
```

- `url`: la URL exacta, escapada para XML/HTML (reemplazar `&` por `&amp;`,
  `<` por `&lt;`, `>` por `&gt;`, `"` por `&quot;`).
- `sha256`: 64 hex chars (SHA-256 hex).
- `mode`: literal `"strip"` o `"replace"`.
- `suspicion`: 3 decimales (p.ej. `0.127`, `0.000`).
- El texto sanitizado va tal cual entre los delimitadores. **NO se
  escapa** porque el llamante (agente downstream) sabe que es texto, no
  HTML. Si se escapara, perderíamos legibilidad del LLM y duplicaríamos
  trabajo de escapado en cada uso.

### §3.5 Sanitización (reutilización de mcp-tool-sanitizer)

```python
from mcp_tool_sanitizer import sanitize_text, find_hidden

# find_hidden emite findings de TAG/ZWSP/BIDI; sanitize_text los elimina.
findings = find_hidden(text)
cleaned = sanitize_text(text, mode="strip")  # o "replace"
```

**Patrón A de `sdd-audit` aplicado**: el chequeo Unicode va ANTES del
cómputo del score, no al revés. Si el orden se invierte, una rama del score
queda muerta (KI-1 de mcp-tool-sanitizer: homoglifos no detectados → score
puede alterarse artificialmente).

### §3.6 Score de sospecha (heurística, sin umbral)

```python
score, signals = compute_suspicion(text: str) -> tuple[float, list[str]]
```

Señales implementadas (todas declaradas, ninguna "mágica"):

| Señal | Ponderación parcial | Notas |
|---|---|---|
| `imperative_density` | 0.0–0.3 | Densidad de verbos imperativos ("ignore", "forget", "execute", "send", "delete", "run", "call", "respond"). Cuenta por palabras, normalizado por longitud. |
| `register_shift` | 0.0–0.2 | Detección de cambio abrupto de registro (mayúsculas sostenidas >30 chars en mitad de párrafo normal, p.ej. "IGNORE PREVIOUS INSTRUCTIONS"). |
| `control_tokens` | 0.0–0.4 | Presencia de tokens tipo `system:`, `assistant:`, `user:`, `###`, `<\|...\|>`, `IGNORA`, `actúa como`, `you are now`. Lista explícita y revisable (NO filtro binario). |
| `instruction_framing` | 0.0–0.1 | Presencia de frases tipo "instrucciones para ti", "your task is to", "disregard previous". |

**Score final** = `min(1.0, sum(ponderaciones))`. Las señales se
**emiten siempre** en `suspicion_signals` (transparencia), pero el umbral
para considerarlo "sospechoso" **NO se fija aquí** (Constitución §6.4).

### §3.7 Modo de fallo (Constitución §4.1)

Si `sanitize_text` lanza una excepción no esperada (`ValueError` por modo
desconocido, `TypeError` por entrada no-string, etc.):

- `GuardError.SanitizeFailed` se propaga al llamante.
- **NO** se entrega texto "casi saneado".
- **NO** se silencia la excepción.

Si `text` está vacío → `GuardError.EmptyInput` (no es error recuperable,
es uso legítimo).

### §3.8 Errores

```python
class GuardError(Exception): ...
class EmptyInput(GuardError): ...
class SanitizeFailed(GuardError):
    def __init__(self, original: Exception): ...
```

---

## §4. Excepciones comunes — `core/exceptions.py`

Convención: cada subsistema tiene su base (`FetchError`, `GuardError`,
etc.). NO hay jerarquía compartida arriba de `Exception` salvo los casos
que justifiquen un catch-all.

```python
# core/exceptions.py
class FetchError(Exception): ...
class GuardError(Exception): ...
class SandboxError(Exception): ...
class WitnessError(Exception): ...
class CitationError(Exception): ...

# Las subclases concretas viven en cada módulo (ver §2.6, §3.8, etc.).
```

---

## §5. Capa 3 — `core/sandbox.py` (resumen; detalle en Plan)

**NO** es un sandbox de OS (`chroot`, `nsjail`). Es **convenios a nivel
de proceso Python** que el llamante (main.py) debe respetar:

- No invocar `subprocess` con `shell=True`.
- No escribir fuera de `~/.local/share/fetch-sentinel/` y
  `~/.config/fetch-sentinel/`.
- No leer `ATW_WITNESS_KEY` ni `OPENAI_API_KEY` ni credenciales del agente.
- `os.environ` se filtra al cargar el módulo: solo pasan vars explícitamente
  en allowlist (`HOME`, `PATH` mínimo, `ATW_WITNESS_KEY` para el sellado
  propio de fetch-sentinel, etc.).

`core/sandbox.py` exporta:
- `assert_safe_environment()` → RuntimeError si alguna convención se viola.
- `allowed_env()` → dict con las vars filtradas, para pasar a subprocesos.

Detalle de implementación y tests en Plan/Tasks. Aquí solo el contrato.

---

## §6. Capa 4.1 — `core/witness_client.py` (resumen)

Modos operativo: **W-A'** (Constitución §3.4.3).

- Mantiene `key_id = "fetch-sentinel:<uuid>"` y clave HMAC en
  `~/.config/fetch-sentinel/keys.json` (0o600).
- Crea `SealedSeal` con `make_seal(spec, witness_id)` y lo firma con
  `sign_seal(seal, key=<hex>)`.
- Por cada evento: `CaptureEvent(ts, type, tool, role, payload_sha256,
  seal_ref=compute_seal_ref(sealed), unsealed=False)`.
- Append-only a `~/.local/share/fetch-sentinel/events.jsonl`, modo 0o600.
- `payload_sha256 = compute_payload_hash(content)` — **nunca se embebe el
  contenido**, solo su hash.

Contrato mínimo:

```python
class WitnessClient:
    def __init__(self, *, key_path: Path | None = None,
                 store_path: Path | None = None): ...
    def record(self, *, type: str, tool: str | None,
               role: str | None, content: bytes | str | dict) -> CaptureEvent: ...
    def verify(self, event: CaptureEvent) -> bool: ...
```

Detalle en Plan.

---

## §7. Capa 4.2 — `core/citation_tracer.py` (resumen; SOLO modo trazado)

**NO** resume. **NO** genera texto. Recibe (texto_fuente, frase) y emite
el anclaje (offset, sha256, length). El LLM downstream hace el resumen;
fetch-sentinel verifica que cada frase del resumen está en el texto fuente.

Patrón de `citefid`: substring match + posición.

Contrato mínimo:

```python
@dataclass(frozen=True)
class Citation:
    text: str               # la frase exacta
    start: int              # offset en el texto fuente
    end: int                # offset final
    sha256_substring: str   # SHA-256 hex del substring

def trace(text: str, claim: str) -> Citation:
    """Encuentra la primera ocurrencia de `claim` en `text` (substring match).
    Si no se encuentra → CitationError.NotFound."""
```

`claim` se busca **literalmente**, sin fuzzy match, sin stemming. Si el
resumen es paráfrasis, el llamante debe proporcionar el substring original.

---

## §8. CLI — `main.py`

```bash
python -m fetch_sentinel fetch <URL> \
    [--mode {strip,replace}] \
    [--trace "phrase to anchor" ...]  \
    [--no-suspicion-score] \
    [--timeout 10] \
    [--allowlist example.com] \
    [--output {human,json}]
```

Comportamiento:
- Por defecto, modo **puerta** (sin tracer).
- Si se pasan `--trace`, modo **trazado**: además del texto delimitado,
  emite las anclas de cada frase.
- `--output json` emite el `GuardResult` (o `TraceResult`) como JSON
  canónico. `--output human` (default) emite el `delimited_text`.

Exit codes:
- `0` — éxito.
- `1` — error de uso (CLI mal invocada).
- `2` — `FetchError`.
- `3` — `GuardError`.
- `4` — `WitnessError`.
- `5` — `SandboxError`.

---

## §9. Configuración — `config.toml`

```toml
[fetch]
default_timeout_seconds = 10
max_bytes = 5_000_000
allowlist = []  # vacío = sin allowlist (cualquier dominio)

[paths]
events_jsonl = "~/.local/share/fetch-sentinel/events.jsonl"
keys_json = "~/.config/fetch-sentinel/keys.json"

[witness]
key_id_prefix = "fetch-sentinel"
hmac_recommend_bytes = 32

[citation]
max_phrase_length = 500
```

**Lo que NO va en config.toml**: umbrales del score de sospecha
(Constitución §6.4: se calibran contra el corpus, no se configuran).

---

## §10. Corpus de fuzzing — `tests/fuzz_injection_corpus/`

Esquema de cada caso (un archivo `.json` por caso):

```json
{
  "name": "TAG-block-in-mid-word",
  "description": "TAG LATIN SMALL LETTER A (U+E0061) entre 'igno' y 're'",
  "input_bytes_hex": "69676e6ff3a081a172652070726576696f757320696e737472756374696f6e73",
  "expect": {
    "findings_count_min": 1,
    "findings_count_max": 1,
    "sanitized_text_utf8_hex_does_not_contain": ["f3a081a1"],
    "suspicion_signals_may_contain": ["control_tokens:ignore"],
    "_KNOWN_LIMITATION": null
  }
}
```

**Reglas del esquema**:
- `input_bytes_hex`: el input se da en hex (no string Python) para evitar
  el bug KI-3 del shell-escape con TAG block. Cada test lee el hex y lo
  decodifica con `bytes.fromhex(...).decode("utf-8")`.
- `expect.findings_count_min/max`: rango esperado de codepoints ocultos
  detectados por `find_hidden`.
- `expect.sanitized_text_utf8_hex_does_not_contain`: bytes (en hex UTF-8)
  que NO deben sobrevivir al sanitize. Se valida sobre
  `sanitized_text.encode("utf-8").hex()`.
- `expect.suspicion_signals_may_contain`: señales que el score PUEDE
  emitir (no se exige ninguna específica — el umbral está abierto).
- `expect._KNOWN_LIMITATION`: si no es `null`, afirma el comportamiento
  actual con explicación legible. Ejemplo para homoglifos:

```json
"_KNOWN_LIMITATION": "mcp-tool-sanitizer Fase 1 NO detecta homoglifos. Caso de regresión esperada: el homoglifo cirílico U+0430 sobrevive a sanitize_text. Se cierra cuando se merge PR upstream de Fase 2."
```

**Casos semilla (10)** que el repo incluye desde el primer commit:

1. `plain-text-benign.json` — texto normal, sin inyección. Expect: 0 findings, score bajo.
2. `TAG-block-mid-word.json` — TAG dentro de palabra.
3. `ZWSP-mid-word.json` — ZWSP entre letras.
4. `BIDI-RLO-prefix.json` — BIDI override al inicio.
5. `CONTROL-TOKEN-ignore.json` — "ignore previous instructions" explícito.
6. `CONTROL-TOKEN-system.json` — "system: you are now ...".
7. `CONTROL-TOKEN-actua-como.json` — "actúa como" en español.
8. `IMPERATIVE-DENSITY-high.json` — Muchas oraciones imperativas (legítimo o no, depende del dominio).
9. `KNOWN-LIMITATION-homoglyph-cyrillic.json` — homoglifo cirílico.
10. `KNOWN-LIMITATION-base64-payload.json` — payload base64 (Capa 2 NO lo decodifica).

Estos casos los **escribe Hermes antes** de implementar el scoring (Patrón
O de `sdd-audit`) y **se entregan al auditor para revisión ANTES de la
calibración** (Constitución §6.4.1).

---

## §11. Cambios a esta Spec

Cualquier modificación requiere:
1. PR con diff textual completo.
2. Justificación de por qué el cambio es necesario.
3. Si toca la API pública de `fetcher.py` o `structural_guard.py`
   (firmas de funciones, formato de delimitadores, esquema del corpus),
   re-correr `pytest tests/test_fetcher.py tests/test_structural_guard.py`
   con número real antes de declarar listo.
4. Aprobación EXPLÍCITA del auditor.

---

## §12. Lo que NO está en Spec (defer a Plan)

- Orden de implementación por fases (Plan).
- Desglose en tareas granulares (Tasks).
- Implementación concreta de `Sandbox.assert_safe_environment`.
- Implementación concreta de `WitnessClient.__init__` (gestión de keys).
- Detalle de `Citation.trace` (algoritmo de substring match).
- Estructura interna de cada test file (qué tests exactos).

Estos son los próximos documentos. La Spec cierra los **contratos**; el
Plan y las Tasks los **operacionalizan**.