# Known Issues — fetch-sentinel

Limitaciones conocidas en el momento del spike de viabilidad (2026-09-03).
Cada KI lleva un test que **afirma el comportamiento actual** para que un
cambio futuro no rompa la garantía sin avisar.

## KI-1: mcp-tool-sanitizer NO detecta homoglifos en v0.1

**Origen**: `mcp-tool-sanitizer` README §"Scope (Fase 1)" — explícitamente
deferred a Fase 2. Confirmado experimentalmente en `sdd/spike_report.md`:

```
--- HOMOGLYPH-cyrillic-a ---
  payload_len=28, findings=0
  cleaned='ignаre previous instructions'
```

El carácter cirílico `а` (U+0430), visualmente idéntico al latino `a`,
sobrevive a `sanitize_text(mode="strip")` sin emitir finding.

**Implicación para fetch-sentinel**: un atacante puede inyectar instrucciones
en cirílico (o en otros scripts homoglíficos) sin ser detectado por Capa 2.

**Mitigación en v0.1**:
- Documentar la limitación explícitamente en `README.md` §"Limitations".
- Test `_KNOWN_LIMITATION` en `tests/fuzz_injection_corpus/` que asuma
  `findings == []` para homoglifos (con caso de regresión etiquetado).
- Backlog explícito: PR upstream a mcp-tool-sanitizer para backportar
  Fase 2 (homoglyphs + NFKC). Cuando se fusione, fetch-sentinel sube
  la dependencia y elimina el `_KNOWN_LIMITATION`.

**Caso del corpus (a documentar)**: payload `ign\u0430re previous instructions`
→ assertion: `findings == []`. Sin este test, un cambio futuro en la lib
que rompiera la detección de TAG/ZWSP/BIDI pasaría silencioso mientras
se relajaba la garantía.

## KI-2: agent-trace-witness requiere HMAC para consumir eventos

**Origen**: `agent_trace_witness/capture.py:_make_event` rechaza
explícitamente `seal_ref=""` con `WitnessCaptureError("seal_ref must be a
non-empty string (AC-3)")`. `seal_ref` se computa como SHA-256 del body
canónico de un `SealedSeal`, que se construye con `sign_seal(seal, key)`.

**Implicación**: el "store local desacoplado" (W-A) original no es viable
sin firma. fetch-sentinel DEBE generar `SealedSeal` propios con clave
dedicada.

**Mitigación**: ruta W-A' adoptada en Constitución §3.2. fetch-sentinel
mantiene su propia `key_id` (`fetch-sentinel:<uuid>`) y clave HMAC en
`~/.config/fetch-sentinel/keys.json` (0o600). El witness valida con la
clave pública de fetch-sentinel.

## KI-3: límites del shell-escape en scripts de test

**Origen**: en el primer intento del spike (`/tmp/fetch-sentinel-spike/`,
heredoc `python3 -c "..."`), el shell colapsó el carácter TAG block
`\uE0001` antes de llegar a Python. Resultado: `find_hidden` emitió 0
findings, lo que parecía un bug de la lib. Re-verificado con archivo
`.py` usando `chr(0xE004C)` literal → 1 finding, comportamiento correcto.

**Implicación**: cualquier test que use TAG block debe construir el payload
**en código fuente** (`chr(0xE00XX)`), nunca en heredoc de shell. La razón
es que WSL bash + python heredoc a veces colapsa codepoints en el rango
TAG block antes de llegar al intérprete Python.

**Mitigación**: convención en `tests/fuzz_injection_corpus/`:
- payloads con TAG block: definirlos como `chr(0xE00XX) + "..."`, no como
  strings literales con `\u`.
- si se usan strings literales, verificar con `repr()` que el codepoint
  llegó intacto.
- el test runner debe poder ejecutarse con `pytest tests/` directo (no
  requiere shell especiales).

## KI-4: agent-trace-witness en PyPI vs local

`pip install agent-trace-witness` desde PyPI **NO** está garantizado que
dé la misma versión que `/home/sil/agent-trace-witness` (puede tener
commits locales no publicados). Para desarrollo y auditoría, instalar
siempre con `pip install -e /home/sil/agent-trace-witness` (editable,
local).

En `pyproject.toml` declarar la dependencia como `agent-trace-witness>=0.1.0`
sirve para distribución, pero el venv de desarrollo usa el path editable.

## KI-5: `__init__.py` de agent-trace-witness no expone submódulos

`agent_trace_witness/__init__.py` solo expone `__version__`. Para usar
`capture`, `seal`, `graph`, etc., hay que importarlos explícitamente:

```python
from agent_trace_witness import capture, seal
from agent_trace_witness.capture import CaptureEvent, record_tool_call
from agent_trace_witness.seal import make_seal, sign_seal, SealedSeal
```

fetch-sentinel NO debe depender de cambios de API que asuman exposición
automática. Si el upstream decide exponer submódulos desde `__init__.py`
en el futuro, fetch-sentinel puede simplificar imports, pero no es
requisito.

## KI-6: depuración de TAG block vía repr()

En el spike, `chr(0xE004C)` se imprime como `'\U000e004c'` en `repr()`.
Si un test compara el output carácter a carácter sin `repr()`, glifos
vacíos pueden hacer que el assert parezca verde cuando en realidad el
TAG fue consumido por el terminal.

Convención: en tests de TAG block, comparar siempre con `ord(ch) == 0xE00XX`
o `len(ch) == 1 and ord(ch) >= 0xE0000 and ord(ch) <= 0xE007F`. NUNCA
comparar la cadena visual.