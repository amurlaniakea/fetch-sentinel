# AGENTS.md — fetch-sentinel

## Objetivo

Leer y resumir contenido web en local, de forma agnóstica y trazable, con
defensa estructural contra inyección de prompts en tiempo de fetch.

## Restricciones duras

- Prohibido ejecutar comandos de shell basados en texto extraído de la web.
- Prohibido que el proceso de lectura tenga acceso a filesystem de escritura
  fuera de `~/.local/share/fetch-sentinel/` y `~/.config/fetch-sentinel/`.
- Prohibido saltarse `core/structural_guard.py` bajo cualquier circunstancia.
- Modo "trazado" exige `core/citation_tracer.py`; modo "puerta" no.
- No se crea repo remoto hasta ~90% de completitud (regla de gobernanza de Pedro).
- SDD estricto: Constitución → Spec → Plan → Tasks → Implement → Verify.
- Ningún AC cumplido sin stdout crudo verificable en el mensaje al auditor.

## Stack

- **runtime**: stdlib (`html.parser`, `urllib`, `hashlib`, `hmac`, `secrets`,
  `json`, `tomllib`), `mcp-tool-sanitizer>=0.1.0`, `agent-trace-witness>=0.1.0`.
- **dev**: `pytest`, `pytest-cov`, `ruff`, `hypothesis`, `repomapper`.
- **prohibido en runtime**: `torch`, `requests`, `beautifulsoup4`, `lxml`,
  `httpx`. Cualquier dep externa adicional requiere justificación escrita
  en Spec o Plan.

## Capas (resumen)

1. **Capa 1 — `core/fetcher.py`**: HTTP → texto readability (descarta
   `<script>`, `<style>`, `<iframe>`, comentarios, atributos).
2. **Capa 2 — `core/structural_guard.py`**: sanitize + delimitadores +
   score de sospecha.
3. **Capa 3 — `core/sandbox.py`**: convenios de proceso (write-allowlist,
   env-allowlist, sin shell).
4. **Capa 4.1 — `core/witness_client.py`**: sellado HMAC propio + emit JSONL.
5. **Capa 4.2 — `core/citation_tracer.py`**: anclaje resumen↔fuente.

## Limitaciones declaradas (ver `sdd/KNOWN_ISSUES.md`)

- KI-1: NO se detectan homoglifos (v0.1; depende de upstream mcp-tool-sanitizer).
- KI-2: agent-trace-witness exige sellado HMAC (W-A').
- KI-3: TAG block en heredoc de shell se colapsa — usar `chr(0xE00XX)` literal.
- KI-4: agent-trace-witness PyPI puede diferir del local — usar `-e /path`.
- KI-5: imports explícitos de submódulos (`from agent_trace_witness import capture, seal`).
- KI-6: TAG block en `repr()` se imprime vacío — comparar por `ord()`, no por string.

## Cómo verificar localmente

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pip install -e /home/sil/mcp-tool-sanitizer
.venv/bin/pip install -e /home/sil/agent-trace-witness
.venv/bin/python -m pytest tests/
.venv/bin/python -m ruff check .
.venv/bin/python main.py fetch https://example.com/ --output json
```

Sin los pasos `pip install -e` para los repos hermanos, los tests fallan
con `ModuleNotFoundError`. NO usar `pip install --break-system-packages`
en WSL — usar siempre venv.