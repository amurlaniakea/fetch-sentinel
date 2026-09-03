# Constitución — fetch-sentinel

**Estado:** v0.1 (2026-09-03)
**Auditor:** Claude (vía Pedro Sordo Martínez)
**Anclaje técnico:** `sdd/spike_report.md`, `sdd/KNOWN_ISSUES.md`

> Esta constitución es el contrato no negociable del proyecto. Cualquier
> PR que la contradiga se rechaza sin discusión. Cambios a la constitución
> requieren aprobación explícita de Pedro.

---

## §1. Misión

**fetch-sentinel** es el guardián en tiempo de fetch para agentes autónomos
que navegan la web. Su trabajo es decidir, **antes** de que un contenido
externo entre al contexto del LLM:

1. Qué partes de ese contenido son seguras de pasar (dato) y cuáles son
   sospechosas de ser instrucción (vector de inyección).
2. Si el contenido fetched debe ser trazado (citado) cuando se use para
   producir un resumen o respuesta al usuario final, o solo pasado por la
   puerta (sanitizado) cuando va a entrar a otro sistema downstream.

fetch-sentinel **NO** decide qué hace el agente con la información; solo
la entrega en una forma que (a) elimina vectores conocidos de inyección,
(b) ancla las afirmaciones del resumen al texto fuente, y (c) registra
cada evento en un log firmado externo para auditoría posterior.

---

## §2. Modelo de amenazas (invariante)

Estos cuatro vectores son los que fetch-sentinel existe para defender. NO
son una lista wishful; son el contrato.

### §2.1 Inyección indirecta de prompts vía contenido fetched

**Vector**: una página web contiene instrucciones ocultas (texto invisible,
comentarios HTML, atributos alt, metadata, payload base64, homoglifos) que
el LLM lee como si fueran parte del prompt del sistema.

**Defensa**: Capa 1 (readability extraction, descarta script/style/iframe),
Capa 2 (normalización Unicode + delimitadores estructurales).

### §2.2 Exfiltración en cadena

**Vector**: el agente que llama a fetch-sentinel tiene acceso a shell,
filesystem de escritura, email, API keys. Una inyección exitosa en el
texto fetched escala a **acción real no autorizada**, no solo a texto
contaminado.

**Defensa**: Capa 3 (separación de privilegios). El proceso fetch-sentinel
corre sin shell, sin escritura en filesystem (excepto el store local de
eventos firmados), sin acceso a credenciales del agente principal. Si la
inyección pasa Capa 1+2, el techo es "resumen incorrecto" — nunca
"shell ejecutado".

### §2.3 Manipulación semántica sin instrucción explícita

**Vector**: contenido diseñado para sesgar el resumen sin parecer una
instrucción directa (propaganda, "hechos" seleccionados, framing).

**Defensa**: **NO** es defendible por Capa 1 o 2 — es una propiedad del
modelo y del prompt del sistema, no del texto fetched. fetch-sentinel
debe **documentar este límite** explícitamente y dejar el problema al
agente downstream (que es quien debe tener su propia defensa semántica,
si la tiene).

**Decisión de diseño del proyecto**: fetch-sentinel NO intenta
defenderse de §2.3. Esta restricción es por diseño, no por imposibilidad
técnica demostrada: el equipo del proyecto considera que un componente
estructural de defensa en el punto de entrada no debe intentar tamizar
significado — esa tarea es de otro componente (modelo + prompt del
sistema del agente downstream). Si en el futuro se demuestra que un
mecanismo concreto y verificable puede defender fetch-sentinel de §2.3
sin convertirlo en un firewall semántico, esta constitución se reabre.

### §2.4 Ofuscación de payload

**Vector**: encoding (base64, hex), homoglifos, caracteres invisibles
(TAG block, ZWSP, bidi override), composición Unicode.

**Defensa**: Capa 2 (reutilizar mcp-tool-sanitizer para TAG/ZWSP/BIDI;
**NO** detecta homoglifos en v0.1, ver KI-1).

---

## §3. Arquitectura — 4 capas obligatorias

### §3.1 Capa 1 — Fetch aislado

- Extracción tipo *readability* sobre el HTML fetched: quedarse con
  headings, párrafos, listas, enlaces. **Descartar** `<script>`, `<style>`,
  `<iframe>`, `<noscript>`, `<object>`, `<embed>`.
- NUNCA pasar HTML/JS crudo al LLM.
- El proceso de fetch resuelve exactamente una URL y se cierra. No hay
  "navegación libre" ni "session cookies persistentes" entre fetches.

### §3.2 Capa 2 — Detección estructural de inyección

Esta capa es **estricta** y **delimitada**. NO es un firewall semántico.

- **Reutilizar** `mcp_tool_sanitizer.sanitize_text(mode="strip")` sobre
  el texto extraído. Esto elimina TAG block, ZWSP y BIDI override.
- **Envolver** el texto limpio en delimitadores estructurales explícitos
  que el prompt del sistema marca como **dato, nunca instrucción**:
  ```
  <fetched_content url="..." sha256="..." mode="...">
  ...texto sanitizado...
  </fetched_content>
  ```
  La separación de canal aquí es **mecánica** (delimitadores), no
  declarativa ("confía en que el modelo se dé cuenta").
- **Score de sospecha heurístico** (densidad de imperativos, cambios
  abruptos de registro, presencia de tokens de control tipo
  "system"/"ignora"/"actúa como"). Este score es **señal para revisión
  humana**, NUNCA filtro binario. El umbral **NO se fija en esta
  Constitución**; se calibra empíricamente contra
  `tests/fuzz_injection_corpus/` en la fase Verify (ver §6.4).

#### §3.2.1 — Limitaciones declaradas de Capa 2 (innegociables)

- **NO detecta homoglifos** en v0.1 (KI-1, documentado en
  `KNOWN_ISSUES.md`). La mitigación depende de un PR upstream a
  mcp-tool-sanitizer; mientras tanto, el corpus de fuzzing incluye
  homoglifos como casos de **regresión esperada** con test
  `_KNOWN_LIMITATION`.
- **NO detecta** base64, hex, rot13 ni otros encodings del payload. Si
  el atacante codifica "ignore previous instructions" en base64, fetch-
  sentinel lo entrega decodificado-forma-base64 al LLM downstream, que
  es quien debe tener su propio decoder-aware defense.
- **NO intenta** defensa semántica (§2.3 está fuera de alcance).

### §3.3 Capa 3 — Separación de privilegios

Esta capa convierte un fallo de Capa 2 en un fallo **acotado**.

El proceso fetch-sentinel corre sin:
- shell (`subprocess` solo invoca el fetcher HTTP, sin `shell=True`).
- escritura en filesystem del usuario, excepto:
  - el store local de eventos firmados (`~/.local/share/fetch-sentinel/events.jsonl`),
  - el keyring de fetch-sentinel (`~/.config/fetch-sentinel/keys.json`, 0o600).
- acceso a credenciales del agente principal (NO comparte `ATW_WITNESS_KEY`,
  NO comparte API keys de OpenAI/etc.).
- capacidad de invocar otras herramientas del agente (MCP, email, calendar).

**Garantía arquitectónica**: si una inyección pasa Capa 1+2, el techo es
"resumen fetched contiene contenido malicioso que el LLM downstream puede
leer como instrucción". El techo **NO** es "shell ejecutado" ni "email
enviado" ni "API key exfiltrada".

### §3.4 Capa 4 — Trazabilidad de citas + integración witness

Dos modos operativos, mutuamente excluyentes por llamada:

#### §3.4.1 Modo "trazado" (con `citation_tracer`)

Cuando el llamante va a producir un resumen o respuesta al usuario final.

Cada frase del resumen se ancla a un offset+hash del texto fuente
(patrón de `citefid`). El anclaje es **mecánico** (substring match +
posición), no "confiar en temperature=0".

Resultado: el llamante recibe (resumen, anclas) y puede verificar offline
que cada frase del resumen está en el texto fuente.

#### §3.4.2 Modo "puerta" (sin tracer)

Cuando el texto fetched va a entrar a OTRO sistema downstream (RAG ya
existente, búsqueda indexada, otro sanitizador).

Solo se aplica Capa 1+2. NO se exige Capa 4. El llamante recibe el texto
sanitizado con sus delimitadores y listo.

Esta distinción evita que fetch-sentinel se convierta en un **resumidor
forzoso** que filtra contenido completo al LLM cuando solo se quería un
chunk para indexar.

#### §3.4.3 Integración con agent-trace-witness (W-A')

fetch-sentinel **sí sella** sus propios eventos con
`agent_trace_witness.sign_seal` usando una **clave HMAC dedicada de
fetch-sentinel**:

- La clave vive en `~/.config/fetch-sentinel/keys.json` (0o600).
- La `key_id` es `fetch-sentinel:<uuid>`.
- Cada evento es un `CaptureEvent` con `payload_sha256` (NO se embebe el
  payload fetched), `seal_ref` (SHA-256 del SealedSeal firmado por
  fetch-sentinel), `tool="fetch"`, `role` (cuando aplica).
- Los eventos se escriben a `~/.local/share/fetch-sentinel/events.jsonl`
  en formato JSON canónico, uno por línea, append-only.
- agent-trace-witness los consume con `run_capture` cuando se ejecuta la
  auditoría; valida la firma con la clave pública de fetch-sentinel.

**`agent-trace-witness` pasa de "dep opcional" a dep de runtime** porque
Capa 4 depende de `sign_seal`, `CaptureEvent`, `compute_payload_hash`.
Es justificable: implementar un subconjunto del formato a mano duplica
trabajo del ecosistema.

---

## §4. Principios (no negociables, en orden de prioridad)

1. **Privilegio mínimo sobre defensa perfecta.** Es mejor fallar cerrado
   (no entregar el contenido) que entregar un contenido que parezca seguro
   y no lo sea. fetch-sentinel **falla cerrado** en Capa 2 si
   `sanitize_text` lanza una excepción no esperada; **falla cerrado** en
   Capa 4 si el sellado del evento falla (en ese caso, NO se entrega el
   resultado al llamante — se aborta la llamada).

2. **Separación de canal sobre instrucciones declarativas.** El texto
   fetched va SIEMPRE dentro de delimitadores estructurales explícitos.
   El prompt del sistema del agente downstream debe declarar esos
   delimitadores como "dato, nunca instrucción". Esto NO es defensa
   suficiente por sí solo, pero es un prerequisite necesario.

3. **Trazabilidad mecánica sobre confianza declarativa.** Citas por
   offset+hash, no por "temperature=0". Logs firmados, no "logs que
   prometo no modificar".

4. **Límites declarados sobre cobertura aspiracional.** KI-1 (homoglifos),
   KI-2 (sellado obligatorio), KI-3 (test con chr() no con \u), etc. NO se
   ocultan; se documentan en `KNOWN_ISSUES.md` con un test que afirma el
   comportamiento actual.

5. **Reutilización del ecosistema sobre reimplementación.** Si mcp-tool-
   sanitizer tiene el detector, se importa. Si agent-trace-witness tiene
   el formato de evento, se emite en ese formato. fetch-sentinel orquesta
   y sanitiza con su lógica propia; lo demás viene de fuera.

6. **Evidencia cruda sobre narrativa.** Ningún "listo" sin `pytest` con
   número real. Ningún "funciona" sin `cat` del archivo relevante. Ningún
   AC cumplido sin salida cruda verificable por el auditor en su propia
   terminal.

---

## §5. Fuera de alcance (explícito)

- **Defensa semántica (§2.3)** — propaganda, framing, hechos seleccionados.
  fetch-sentinel NO intenta defenderse de esto. El problema es del modelo
  + prompt del sistema downstream, no del texto fetched.
- **Detección de homoglifos en v0.1** — KI-1, depende de upstream.
- **Decodificación de payload ofuscado (base64, hex, rot13, etc.)** — es
  problema del agente downstream que recibe el dato.
- **Navegación interactiva** — fetch-sentinel hace una URL por llamada,
  no simula un usuario con cookies/session entre fetches.
- **Resumir el contenido** — fetch-sentinel NO resume. Devuelve el
  contenido (sanitizado, con o sin anclas) al llamante. Resumir es
  responsabilidad del agente downstream.
- **Indexar el contenido** — si fetch-sentinel acaba integrando búsqueda,
  eso es Fase posterior con herramienta apropiada (NO repomapper, ver
  `spike_report.md`).
- **Publicación a PyPI** — la primera versión se instala desde GitHub.
  Publicar a PyPI requiere decisión explícita de Pedro (regla de
  gobernanza del ecosistema).

---

## §6. Verificación y métricas

### §6.1 Evidencia mínima antes de declarar una fase "lista"

- `pytest` con NÚMERO REAL ("34 passed"), no "tests verdes".
- `ruff check .` limpio.
- `py_compile` de todo el paquete.
- Archivo completo de cada `.py` modificado, **en bloque de código** en
  el mensaje al auditor (no resumen, no diff parcial — el auditor lo
  lee y objeta punto por punto).

### §6.2 Auditoría independiente

El auditor (Claude, vía Pedro) re-ejecuta desde clon fresco. **Pedro NO
acepta veredictos auto-declarados** ("yo mismo audité y está bien" no
cuenta). La verificación es:

```bash
git clone /path/to/fetch-sentinel
cd fetch-sentinel
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
.venv/bin/ruff check .
```

Sin esto, la fase NO se considera aprobada.

### §6.3 Patrones de bug que el auditor caza (resumen operativo)

Referencia: `sdd-audit` skill. Aplican a fetch-sentinel los patrones:

- **A. Código muerto en rama if/elif** — revisar el orden de checks en
  Capa 2 (Unicode ANTES de score, no al revés).
- **H. Confirmación falsificable localmente → escalada** — el store local
  de eventos debe tener permisos restrictivos (0o700 dir, 0o600 file);
  el `seal_ref` debe validarse contra el evento firmado, no contra un
  "último id conocido".
- **I. Default congelado en import-time rompe monkeypatch** — los paths
  del store local y keyring se leen de env/config en llamada, NO como
  default en `def`.
- **N. No fijar números sin corpus anclado** — el umbral del score de
  sospecha NO se fija aquí. Se calibra en §6.4.
- **P. Homoglifos/Unicode en detección** — KI-1; el test
  `_KNOWN_LIMITATION` afirma el comportamiento actual con explicación.

### §6.4 Calibración del score de sospecha (Verify)

El umbral del score de sospecha **NO se define en esta Constitución**.
Se determina empíricamente contra `tests/fuzz_injection_corpus/`:

1. El corpus se construye ANTES de implementar el scoring (Patrón O de
   `sdd-audit`). Cada caso lleva `expect` (qué debe dispararse / no) escrito
   ANTES de correr nada.
2. El humano (Pedro) revisa los casos del corpus en crudo ANTES de la
   calibración.
3. La métrica de aceptación es TPR y FPR sobre el corpus etiquetado a
   priori. NO se acepta un único número mágico ("0.5 funciona"); se exige
   ver la curva ROC / precision-recall y un umbral justificado contra un
   FPR objetivo (sugerencia: FPR ≤ 5% en texto legítimo).
4. El umbral se justifica con la **curva ROC / precision-recall calculada
   sobre el corpus etiquetado a priori**, no con un número mágico
   aspiracional. Si se cita trabajo previo (papers, benchmarks
   publicados), se cita con arXiv ID o DOI resuelto contra la fuente
   primaria; si no se puede verificar la fuente, no se cita.

---

## §7. Estructura de repo (anclada al diseño original con correcciones)

```
fetch-sentinel/
├── AGENTS.md                      # gobernanza para Hermes (ver §8)
├── LICENSE                        # AGPL-3.0-or-later
├── pyproject.toml                 # atribución + deps (incluye mcp-tool-sanitizer,
│                                    agent-trace-witness como runtime; repomapper
│                                    como [dev])
├── README.md
├── config.toml                    # límites de gasto, allowlist de dominios,
│                                    rutas de store local (NO umbrales de score)
├── core/
│   ├── __init__.py
│   ├── fetcher.py                 # Capa 1: readability, sin exec
│   ├── structural_guard.py        # Capa 2: sanitize_text + delimitadores + score
│   ├── sandbox.py                 # Capa 3: proceso read-only, sin shell/fs/creds
│   ├── citation_tracer.py         # Capa 4: anclaje resumen↔fuente (modo trazado)
│   ├── witness_client.py          # Capa 4: sellado con sign_seal + emit JSONL
│   └── exceptions.py
├── tests/
│   ├── fuzz_injection_corpus/     # casos con `expect` declarado a priori
│   ├── test_fetcher.py
│   ├── test_structural_guard.py
│   ├── test_sandbox.py
│   ├── test_citation_tracer.py
│   └── test_witness_client.py
└── main.py                        # CLI mínimo: leer URL → sanitize → (trazado|puerta)
```

---

## §8. AGENTS.md (borrador para Hermes)

```text
# AGENTS — fetch-sentinel

## Objetivo
Leer y resumir contenido web en local, de forma agnóstica y trazable, con
defensa estructural contra inyección de prompts en tiempo de fetch.

## Restricciones duras
- Prohibido ejecutar comandos de shell basados en texto extraído de la web.
- Prohibido que el proceso de lectura tenga acceso a filesystem de escritura
  fuera de `~/.local/share/fetch-sentinel/` y `~/.config/fetch-sentinel/`.
- Prohibido saltarse structural_guard.py bajo cualquier circunstancia.
- Modo "trazado" exige citation_tracer; modo "puerta" no.
- No se crea repo remoto hasta ~90% de completitud (regla de gobernanza de Pedro).
- SDD estricto: Constitución → Spec → Plan → Tasks → Implement → Verify.
- Ningún AC cumplido sin stdout crudo verificable en el mensaje al auditor.

## Stack
- mcp-tool-sanitizer (runtime) — detección Unicode Capa 2.
- agent-trace-witness (runtime) — sellado de eventos Capa 4.
- repomapper ([dev]) — generar AGENTS.md del propio repo.
- pytest, ruff, hypothesis — testing/lint.
- Sin torch, sin requests (usar httpx o stdlib), sin bs4 (usar stdlib html.parser
  o readability-lxml si se justifica en Spec).
```

---

## §9. Atribución y licencia

- **Autor:** Pedro Sordo Martínez — amurlaniakea@gmail.com (con tilde).
- **Licencia:** AGPL-3.0-or-later (texto íntegro de gnu.org en `LICENSE`).
- **SPDX header** en todo archivo fuente nuevo:
  ```
  # SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
  # SPDX-License-Identifier: AGPL-3.0-or-later
  ```

Deuda del ecosistema: `mcp-tool-sanitizer`, `agent-trace-witness`,
`citefid`, `rag-sanitizer`, `corpus-scrub` tienen la atribución SIN tilde
en sus `pyproject.toml`. No se corrigen en esta sesión; quedan en backlog.

---

## §10. Cambios a esta constitución

Cualquier modificación requiere:
1. PR con diff textual completo de la sección afectada.
2. Justificación escrita de por qué el cambio es necesario (no opcional).
3. Re-verificación del spike si el cambio toca §2, §3, §5 o §6.
4. Aprobación EXPLÍCITA de Pedro (no del agente).

Sin estos cuatro, el cambio se rechaza.