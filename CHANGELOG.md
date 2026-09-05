# Changelog

Todos los cambios visibles al usuario se documentan aquí. El formato
sigue [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), y este
proyecto se adhiere a [Semantic Versioning](https://semver.org/).

## [Unreleased]

### ⚠️ BREAKING CHANGES

#### KI-7 residual — allowlist vacío = fail-closed (decisión 2026-09-04)

**Comportamiento anterior (v0.1.x)**: `--allowlist` ausente o lista
vacía equivalía a "sin restricción" — el fetcher aceptaba CUALQUIER
URL http/https.

**Comportamiento nuevo (v0.2+)**: `--allowlist` ausente o lista vacía
se considera **fail-closed**. El fetcher rechaza con
`FetchError("allowlist is empty")` y `rc=2`.

**Por qué**: el modelo de amenaza declara que fetch-sentinel es un
guardián en tiempo de fetch para agentes autónomos. La postura
"seguro por defecto" es coherente con el resto de decisiones de
diseño (SSRF block, structural guard, witness client). Permitir
fetches implícitos sin allowlist explícita es el opuesto de esa
postura.

**Cómo adaptarse**:
1. Configurar `[fetch].allowlist` en `config.toml` con la lista
   de hosts que tu agente necesita fetchar (ej.
   `allowlist = ["example.com", "github.com"]`).
2. O pasar `--allowlist <pattern>` (repetible) en cada invocación
   del CLI.
3. Ver `sdd/spec.md §2.2` para los detalles del contrato.

**No hay escape-hatch**: no existe flag `--no-allowlist` ni similar.
Si necesitas un comportamiento "permitir todo", esa es una decisión
de seguridad que debe documentarse en tu config, no implícita en el
CLI.

#### SEC-07 — delimitador `<fetched_content>` ahora se neutraliza también para fullwidth

**Comportamiento anterior**: `_neutralize_delimiters` solo cubría
`<` ASCII (U+003C). Variantes Fullwidth (`＜` U+FF1C) pasaban sin
neutralizar.

**Comportamiento nuevo**: NFKC se aplica al texto antes de la
regex. `＜fetched_content＞` se neutraliza igual que
`<fetched_content>`.

**Por qué**: si un LLM downstream normaliza NFKC antes de
tokenizar (algunos lo hacen), el delimitador fullwidth se
interpretaría como cierre legítimo, rompiendo Capa 2.

#### SEC-04 — `assert_safe_environment` ahora avisa a stderr si detecta vars de API key del agente

**Comportamiento anterior**: el check de vars prohibidas
(OPENAI_API_KEY, etc.) tenía `pass` silencioso.

**Comportamiento nuevo**: si `os.environ` contiene vars prohibidas
al inicio del proceso, se emite un warning explícito a stderr
listándolas. El proceso sigue ejecutando.

**Por qué**: si el operador despliega fetch-sentinel sin respetar
la separación de privilegios de Capa 3, no se entera. El warning
lo hace visible en logs/CI.

#### SEC-05 — `config.toml` ahora se lee, se aplica subordinado a CLI, y avisa de claves no aplicables

**Comportamiento anterior**: `config.toml` existía en el repo
pero `main.py` no lo cargaba nunca. Un operador que desplegaba
asumiendo que sus ajustes se aplicaban estaba fallando en
silencio.

**Comportamiento nuevo**: `main.py` lee `config.toml` si existe,
aplica `[fetch].*` como defaults subordinados a CLI, y emite
warning a stderr listando cualquier clave que esta versión no
aplique al runtime.

**Por qué**: misma razón que SEC-04 — el fallo silencioso es peor
que un warning explícito.

### Fixed

- **KI-10 / KI-11** (rama `audit/ki-10-11`, merges previos):
  SSRF TOCTOU cerrado con pinning de IP + loop manual de redirects.
  Ver `sdd/KNOWN_ISSUES.md` y `sdd/verify_implementation.md`.
- **KI-12 / KI-13**: sha256 sobre cuerpo neutralizado + bypass de
  espacio en KI-13 cerrados.
- **KI-14 / KI-15**: scheme en redirects + cobertura HTTPS/TLS
  cerrados.
- **Test flaky de SEC-05**: `test_main_end_to_end_uses_config_*`
  ya no hace llamadas de red reales (gracias a la cazada de
  Claude, auditor 3ª ronda).

## [0.1.0] - 2026-09-03

Versión inicial con:
- Capa 1: fetcher con SSRF block, IP pinning, redirect loop manual.
- Capa 2: structural guard con delimitadores y score de sospecha.
- Capa 3: sandbox con convenios de proceso.
- Capa 4.1: witness client con sellado HMAC.
- Capa 4.2: citation tracer con anclaje resumen↔fuente.
- CLI: `main.py fetch <url> [opciones]`.
- Suite: 161 tests (en `dde3348`).

[Unreleased]: https://github.com/amurlaniakea/fetch-sentinel/compare/dde3348...HEAD
[0.1.0]: https://github.com/amurlaniakea/fetch-sentinel/releases/tag/v0.1.0
