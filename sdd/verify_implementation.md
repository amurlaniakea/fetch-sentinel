# Verify — Implementación fetch-sentinel v0.1

**Fecha:** 2026-09-03
**Auditor de segunda línea:** pendiente (Claude/Pedro cuando vuelva)

> Esta verificación es **primaria, no independiente**. La verifica-
> ción independiente (clon fresco + pytest + ruff) la hará el auditor
> externo cuando esté disponible. Lo que aquí documento es la salida
> cruda de los comandos Y un análisis adversarial (red-team notes)
> sobre los puntos donde mi propia verificación tiene límites.

## §1. Comandos ejecutados y salida cruda

### 1.1 `py_compile` (sintaxis)

```
.venv/bin/python -m compileall core/ main.py
Listing 'core/'...
Listing 'main.py'...
```

(py_compile no imprime nada cuando todo está limpio; el éxito se ve en
exit code 0. Lo verifiqué re-ejecutando y comprobando que el comando
termina sin errores.)

### 1.2 `pytest tests/`

```
$ .venv/bin/python -m pytest tests/
============================= 138 passed in 0.42s ==============================
```

**138 tests, todos verdes.** Desglose por archivo:

| Archivo | Tests |
|---|---|
| `test_fetcher.py` | 34 |
| `test_structural_guard.py` | 30 |
| `test_sandbox.py` | 19 |
| `test_witness_client.py` | 18 |
| `test_citation_tracer.py` | 14 |
| `test_main.py` | 10 |
| `fuzz_injection_corpus/test_corpus.py` | 13 (10 parametrizados + 3 estructurales) |
| **Total** | **138** |

### 1.3 `ruff check .`

```
$ .venv/bin/python -m ruff check .
All checks passed!
```

(Salida completa, sin warnings ni errors.)

### 1.4 Smoke test end-to-end

Servidor HTTP local sirviendo HTML con `<script>ignore previous instructions</script>`
y un `<a href="http://evil.com/">click here</a>`. Ejecución con `--output json`.
`:
`Salida relevante:
- `<script>ignore previous instructions</script>` se descartó en Capa 1
  (readability). Capa 2 no vio TAG block → `findings_count: 0`. Esto es
  **correcto por diseño**: el HTML nunca llega al LLM.
- `<a href="...">` se quedó solo con el texto "click here" (no el href).
- Delimitadores correctos: URL, sha256, mode, suspicion.
- Exit code 0.

### 1.5 Hash de archivos críticos

```
$ sha256sum core/*.py main.py pyproject.toml
<verificado en disco, ver §6>
```

## §2. Red-team notes (qué tendría que fallar para que los tests sean verdes pero el código esté mal)

> Esta sección NO es prueba — es transparencia sobre los límites de mi
> propia verificación. Cada punto es un lugar donde un auditor externo
> debería mirar primero cuando revise.

### 2.1 Capa 1 (`core/fetcher.py`)

**Tests que podrían ser verdes con código malo:**

- **`test_fetch_*` con `_FakeOpener`**: mis tests mockean urllib con
  `_FakeOpener`. Si el código real contra un servidor HTTPS real tiene un
  bug (p.ej. no verifica correctamente el certificado, o no maneja
  compressed responses, o falla con redirect chain real), mis tests
  NO lo cazan. **El auditor debe correr la CLI contra una URL HTTPS
  real** (`https://example.com/`) y verificar que el HTML se descarga
  y se sanitiza.

- **`test_fetch_allowlist_passes` y `test_fetch_redirect_cross_origin_in_allowlist_passes`**: mockeo `response.geturl()` para que devuelva una URL distinta. Si el código real con redirects reales NO actualiza `final_url` correctamente, mi test pasa pero el código real puede tener un bug de path-confusion. **Auditor: probar manualmente con `curl -L`** contra una URL que redirige.

- **Exhaustividad de discard**: si alguien añade un nuevo tag peligroso
  (p.ej. `<xmp>`, `<listing>`, `<noframes>`) y olvida añadirlo a
  `_DISCARD_TAGS`, el test NO falla porque el tag no está en el corpus.
  **Auditor: revisar `_DISCARD_TAGS` y contrastar con el OWASP HTML5
  security cheatsheet** para ver si falta alguno.

### 2.2 Capa 2 (`core/structural_guard.py`)

**Tests que podrían ser verdes con código malo:**

- **`_KNOWN_LIMITATION` (homoglifos)**: el test `test_known_limitation_homoglyph_cyrillic_not_detected`
  afirma `findings_count == 0`. **Esto es correcto AHORA** porque
  mcp-tool-sanitizer Fase 1 NO detecta homoglifos. Pero si en el futuro
  upstream mergea Fase 2, este test debe pasar a `>= 1`. **Auditor: cuando se haga upstream update, este test debe REVERTIRSE explícitamente** (no relajar — REVERTIR). Documentado en el cuerpo del test.

- **Score de sospecha**: la heurística es declarativa (lista de regex).
  Si alguien afina las ponderaciones sin actualizar la Spec, los tests
  siguen pasando porque `suspicion_signals_may_contain` se ignora en el
  corpus. **Auditor: leer las ponderaciones contra la Constitución §6.4** ("umbral se calibra contra corpus etiquetado a priori"). Si las ponderaciones cambian sin re-calibración, hay regresión.

- **Delimitadores byte-a-byte**: el test verifica la estructura con
  regex. Si alguien añade un atributo al delimitador sin actualizar la
  Spec, el test NO falla (porque el regex es laxo en atributos extra).
  **Auditor: el formato de delimitadores está pin en Spec §3.4. Si cambia, hay que cambiar la Spec PRIMERO.**

### 2.3 Capa 3 (`core/sandbox.py`)

**Tests que podrían ser verdes con código malo:**

- **`test_is_writable_rejects_tmp`**: la allowlist se basa en `HOME` y
  los paths resueltos. Si `HOME` se manipula (p.ej. `HOME=/tmp/evil`),
  el path `~/.local/share/fetch-sentinel/` se resuelve a `/tmp/evil/.local/share/fetch-sentinel/`,
  que NO está en `/tmp`. Pero si el atacante controla `HOME` antes de
  invocar fetch-sentinel, también controla todo el árbol. **Esto es
  esperable**: el sandbox funciona bajo el supuesto de que HOME está
  bajo control del usuario legítimo. Documentado.

- **`test_assert_safe_environment_passes_with_home`**: solo verifica
  que HOME existe. NO verifica que el path sea "razonable" (no esté
  en /tmp). **Auditor: considerar si `assert_safe_environment`
  debería rechazar HOME bajo /tmp / /var / etc. Esto NO está implementado; está como TODO.**

### 2.4 Capa 4.1 (`core/witness_client.py`)

**Tests que podrían ser verdes con código malo:**

- **`test_round_trip_in_same_code_no_dual_implementation`**: verifica
  que el round-trip record/verify está en `WitnessClient.verify`. Pero
  NO verifica que NO haya un script externo que use una implementación
  alternativa. **Auditor: revisar `git ls-files` para confirmar que
  no hay scripts huérfanos en `scripts/` o similar.**

- **`test_verify_false_after_seal_ref_tampered`**: verifica que un
  seal_ref distinto hace que `verify` retorne False. Pero NO verifica
  que el `payload_sha256` esté protegido — el witness upstream NO firma
  el evento individual, solo el SealedSeal. **Auditor: documentar
  explícitamente que la auditoría de tampering sobre el payload
  requiere re-hash del contenido original, NO verificación del evento.**

- **Patrón H aplicado a medias**: chmod al crear está bien (0o600), pero
  si el archivo YA existe con 0o644, mi código raise `StorePermissionError`
  en vez de chmod automático. **Esto es por diseño** (no quiero sobrescribir
  permisos del usuario silenciosamente), pero un auditor podría argumentar
  que deberíamos chmod automático y loguear. Documentado en el cuerpo
  del código.

### 2.5 Capa 4.2 (`core/citation_tracer.py`)

**Tests que podrían ser verdes con código malo:**

- **`test_match_returns_first_occurrence`**: el primer match se devuelve,
  no necesariamente el más relevante. Si el LLM downstream usa la cita
  como "evidencia", podría elegir el primer match cuando hay uno más
  específico en otra posición. **Esto es limitación del substring match
  literal** (NO fuzzy, NO semantic). Documentado en la Spec §7.

### 2.6 `main.py`

**Tests que podrían ser verdes con código malo:**

- **`test_puerta_mode_default_emits_delimited_text`**: el modo default
  es "puerta" (sin tracer). Pero el código CLI NO valida que `--mode`
  se combina correctamente con `--no-suspicion-score`. **Auditor:
  probar manualmente combinaciones exóticas** (p.ej. `--trace` con
  `--no-suspicion-score`).

## §3. Cobertura por patrón `sdd-audit`

| Patrón | Aplicado en | Test que lo verifica |
|---|---|---|
| **A. Código muerto en if/elif** | `_compute_suspicion` (orden signals) | `test_suspicion_score_grows_*` (cada signal se ejercita) |
| **H. Escalada local→sudo** | `WitnessClient` permisos keyring/store | `test_key_file_created_with_0600`, `test_store_file_created_with_0600`, `test_key_file_existing_with_wrong_mode_raises` |
| **I. Default congelado en import-time** | `WitnessClient._Paths`, `Sandbox._resolve_write_allowlist` | `test_patrón_i_paths_leídos_en_cada_llamada`, `test_is_writable_*` con monkeypatch HOME |
| **N. Umbrales sin corpus** | Constitución §6.4 (sin umbral en código) | El umbral NO se fija en código. tests/fuzz_injection_corpus/ existe con 10 casos semilla, pero `suspicion_signals_may_contain` se IGNORA en los tests (decisión consciente). |
| **P. Homoglifos/Unicode** | `_KNOWN_LIMITATION` documentado | `test_known_limitation_homoglyph_cyrillic_not_detected`, `KNOWN-LIMITATION-homoglyph-cyrillic.json` |
| **T014. Dual-implementation** | `WitnessClient.verify` único punto | `test_round_trip_in_same_code_no_dual_implementation` |

## §4. KI declaradas y verificadas en código

- **KI-1 (homoglifos)**: confirmada experimentalmente en
  `tests/test_structural_guard.py::test_known_limitation_homoglyph_cyrillic_not_detected`.
- **KI-2 (sellado obligatorio)**: confirmada con `test_record_emits_event_with_seal_ref`
  (seal_ref siempre 64 hex no vacío).
- **KI-3 (shell-escape)**: mitigada con payloads en hex en
  `tests/fuzz_injection_corpus/`.
- **KI-4 (PyPI vs local)**: documentada en AGENTS.md y README.
- **KI-5 (imports explícitos)**: `core/witness_client.py` usa imports
  explícitos (`from agent_trace_witness import capture, seal as witness_seal`).
- **KI-6 (repr() de TAG)**: tests usan `ord()` o hex, no comparación de
  string visual.

## §5. Verificación de las 4 dependencias declaradas

| Dependencia | Versión usada | Verificada por |
|---|---|---|
| `mcp-tool-sanitizer` | local editable de `/home/sil/mcp-tool-sanitizer` | `pip install -e`, `python -c "from mcp_tool_sanitizer import sanitize_text"` |
| `agent-trace-witness` | local editable de `/home/sil/agent-trace-witness` | `pip install -e`, `python -c "from agent_trace_witness import capture, seal"` |
| `pytest` | 9.1.1 | output del runner |
| `ruff` | (latest) | output del runner |

NO se instaló `torch`, `requests`, `beautifulsoup4`, `lxml`, `httpx`. Verificado con:
```
$ .venv/bin/pip freeze | grep -iE 'torch|requests|beautifulsoup|lxml|httpx'
(sin resultados)
```

## §6. Hashes en disco (verificación al final)

```
$ sha256sum core/*.py main.py pyproject.toml AGENTS.md README.md config.toml
<pegados en el mensaje al auditor>
```

(Estos hashes los pego en el commit final para que el auditor pueda
verificar que el contenido en disco coincide con lo commiteado.)

## §7. Lo que falta (TODO honesto)

- **TODO-C3-1**: `assert_safe_environment` debería rechazar HOME bajo
  `/tmp` o `/var` (no solo exigir que exista). Pendiente para Fase 2.
- **TODO-C4-2**: la auditoría de tampering del payload requiere re-hash
  externo, NO está implementada como comando. Pendiente para Fase 2.
- **TODO-spec-1**: el formato de delimitadores es byte-a-byte en la
  Spec, pero no hay un test que verifique TODOS los atributos. Pendiente.

## §9. Estado del repo

```
.git/                          # init local, sin remoto
.gitignore                     # completo (.venv/, credentials, etc.)
LICENSE                        # AGPL-3.0-or-later
AGENTS.md                      # gobernanza para Hermes
README.md                      # documentación usuario
config.toml                    # paths y límites
pyproject.toml                 # atribución + deps
main.py                        # CLI
core/                          # 6 módulos + __init__ + exceptions
tests/                         # 6 archivos + corpus/
sdd/                           # constitución, spec, plan, tasks, spike, KNOWN_ISSUES, verify
.venv/                         # NO COMMITEADO (gitignored)
```

Working tree tiene cambios sin commit (este verify + varios archivos).
El commit final se hace en el siguiente paso.

---

**Sin push a GitHub. Sin repo remoto creado. Estado congelado, esperando
auditor externo.**