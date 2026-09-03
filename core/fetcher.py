# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Capa 1 — fetcher: HTTP → texto readability.

Política:
- Solo http:// y https://.
- Sin reintentos. Si falla, falla (Capa 3 decide qué hacer).
- Descarta <script>, <style>, <iframe>, <noscript>, <object>, <embed>,
  <template>, comentarios HTML, atributos (alt, title, data-*).
- Conserva texto de headings, párrafos, listas, enlaces (solo el texto,
  no el href), celdas de tabla.
- Whitespace colapsado entre bloques top-level.

Ver sdd/spec.md §2 para el contrato exacto.
"""

from __future__ import annotations

import hashlib
import html.parser
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from core.exceptions import FetchError

# --------------------------------------------------------------------------- #
# Excepciones (Spec §2.6)
# --------------------------------------------------------------------------- #


class UnsupportedScheme(FetchError):
    """Scheme distinto de http/https (file://, javascript:, ftp://, etc.)."""


class UnsupportedContentType(FetchError):
    """Content-Type que no es text/html."""


class HTTPError(FetchError):
    """Status >= 400."""

    def __init__(self, status_code: int) -> None:
        super().__init__(f"HTTP {status_code}")
        self.status_code = status_code


class SizeExceeded(FetchError):
    """Body excedió max_bytes."""

    def __init__(self, limit: int, partial_bytes: int) -> None:
        super().__init__(f"body exceeds {limit} bytes (read {partial_bytes})")
        self.limit = limit
        self.partial_bytes = partial_bytes


class Timeout(FetchError):
    """Timeout de urllib."""


class RedirectNotAllowed(FetchError):
    """Redirect cross-origin sin match en allowlist."""

    def __init__(self, from_url: str, to_url: str) -> None:
        super().__init__(f"redirect from {from_url} to {to_url} not allowed")
        self.from_url = from_url
        self.to_url = to_url


class EmptyBody(FetchError):
    """HTML sin contenido textual extraíble."""


# --------------------------------------------------------------------------- #
# Dataclass de salida (Spec §2.3)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class FetchResult:
    url: str
    final_url: str
    text: str
    sha256_html: str
    sha256_text: str
    content_type: str
    status_code: int
    bytes_read: int
    extraction_notes: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Readability mínima (Spec §2.5)
# --------------------------------------------------------------------------- #


# Tags cuyo contenido se descarta SIEMPRE (incluso si anidan otros válidos).
_DISCARD_TAGS = frozenset(
    {"script", "style", "iframe", "noscript", "object", "embed", "template"}
)

# Tags cuyo contenido se conserva COMO TEXTO.
_KEEP_TAGS = frozenset(
    {
        "title",
        "h1", "h2", "h3", "h4", "h5", "h6",
        "p",
        "li",
        "blockquote",
        "pre",
        "a",
        "td", "th",
        "div", "section", "article", "main", "header", "footer", "aside",
    }
)

# Tags que introducen un salto de línea top-level (Spec §2.5.5).
_BLOCK_TAGS = frozenset(
    {"p", "h1", "h2", "h3", "h4", "h5", "h6", "li", "blockquote", "pre",
     "tr", "div", "section", "article", "main", "header", "footer"}
)


class ReadabilityExtractor(html.parser.HTMLParser):
    """Extractor de texto estructural sobre HTMLParser (stdlib).

    Implementación propia: cero regex sobre HTML, cero deps externas.
    Mantiene stack de elementos activos. Descarta zonas peligrosas
    (Spec §2.5).
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._chunks: list[str] = []
        self._skip_depth: int = 0  # >0 cuando estamos dentro de un tag descartado
        self._notes: list[str] = []
        self._had_doctype: bool = False

    def error(self, message: str) -> None:
        # HTMLParser exige implementar error; no hacemos nada (parseamos
        # en modo "recuperar" — es Robust Parsing por defecto).
        pass

    def handle_decl(self, decl: str) -> None:
        if decl.upper().startswith("DOCTYPE"):
            self._had_doctype = True

    def handle_comment(self, data: str) -> None:
        # Comentarios HTML: descartar siempre (Spec §2.5.4).
        # NO añadir el comentario a chunks aunque estemos fuera de skip.
        if self._skip_depth == 0:
            self._notes.append("html_comment_discarded")

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in _DISCARD_TAGS:
            self._skip_depth += 1
            self._notes.append(f"{tag}_opened_discarded")
            return
        if tag in _BLOCK_TAGS and self._chunks and not self._chunks[-1].endswith("\n"):
            # Bloque top-level: añadir newline antes si no hay.
            self._chunks.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in _DISCARD_TAGS:
            if self._skip_depth > 0:
                self._skip_depth -= 1
            return
        if tag in _BLOCK_TAGS:
            self._chunks.append("\n")

    def handle_data(self, data: str) -> None:
        if self._skip_depth > 0:
            return
        # Aplica whitespace colapsado intra-bloque.
        # NO colapsamos a nivel global — los \n entre bloques se respetan.
        cleaned = " ".join(data.split())
        if cleaned:
            self._chunks.append(cleaned)
            self._chunks.append(" ")

    def get_text(self) -> str:
        raw = "".join(self._chunks)
        # Colapsa runs de whitespace pero PRESERVA \n entre bloques.
        out_lines: list[str] = []
        for line in raw.split("\n"):
            out_lines.append(" ".join(line.split()))
        text = "\n".join(out_lines)
        # Quita líneas vacías múltiples (max una seguida).
        while "\n\n\n" in text:
            text = text.replace("\n\n\n", "\n\n")
        return text.strip()

    def get_notes(self) -> list[str]:
        return list(self._notes)


# --------------------------------------------------------------------------- #
# HTTP fetcher (interno, Spec §2.4)
# --------------------------------------------------------------------------- #


class _HttpFetcher:
    """Encapsula urllib.request.urlopen con timeout, max_bytes, redirect policy."""

    def __init__(
        self,
        *,
        timeout: float,
        max_bytes: int,
        allowlist: list[str] | None,
        _opener: Any = None,
    ) -> None:
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.allowlist = allowlist
        # _opener es param de inyección para tests (mock de urllib).
        self._opener = _opener

    def fetch(self, url: str) -> tuple[bytes, str, int, list[str]]:
        """Devuelve (body_bytes, content_type, status_code, notes).

        Raises:
            UnsupportedScheme, HTTPError, SizeExceeded, Timeout,
            RedirectNotAllowed, UnsupportedContentType.
        """
        self._validate_scheme(url)

        opener = self._opener if self._opener is not None else urllib.request.build_opener(
            _NoRedirectHandler()
        )

        req = urllib.request.Request(url, headers={"User-Agent": "fetch-sentinel/0.1"})

        try:
            # timeout=NO redirige por defecto si no permitimos; el handler lo hace.
            response = opener.open(req, timeout=self.timeout)  # type: ignore[arg-type]
        except urllib.error.HTTPError as e:
            raise HTTPError(e.code) from e
        except urllib.error.URLError as e:
            if isinstance(e.reason, TimeoutError):
                raise Timeout(f"timeout after {self.timeout}s") from e
            raise FetchError(f"urability error: {e.reason}") from e
        except TimeoutError as e:
            raise Timeout(f"timeout after {self.timeout}s") from e

        try:
            content_type = response.headers.get("Content-Type", "")
            status_code = response.status
            final_url = response.geturl()

            # Validar status ANTES de procesar body (4xx/5xx → HTTPError).
            if status_code >= 400:
                raise HTTPError(status_code)

            # Validar redirect cross-origin si hay allowlist.
            if final_url != url:
                self._validate_redirect(url, final_url)

            # Validar content-type.
            if not content_type.lower().startswith("text/html"):
                raise UnsupportedContentType(
                    f"content-type {content_type!r} not supported"
                )

            # Leer con tope de bytes.
            body = bytearray()
            while True:
                chunk = response.read(8192)
                if not chunk:
                    break
                body.extend(chunk)
                if len(body) > self.max_bytes:
                    raise SizeExceeded(self.max_bytes, len(body))

            notes: list[str] = []
            return bytes(body), content_type, status_code, notes
        finally:
            try:
                response.close()
            except Exception:  # noqa: BLE001, S110 — cierre best-effort
                # El cierre de la response es defensivo; un fallo aquí
                # NO debe enmascarar el resultado real de la operación.
                pass

    def _validate_scheme(self, url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise UnsupportedScheme(f"scheme {parsed.scheme!r} not supported")

    def _validate_redirect(self, from_url: str, to_url: str) -> None:
        if self.allowlist is None:
            return  # sin allowlist, redirects OK
        from_host = (urlparse(from_url).hostname or "").lower()
        to_host = (urlparse(to_url).hostname or "").lower()
        if from_host == to_host:
            return
        # Cross-origin: to_host debe matchear allowlist.
        for pattern in self.allowlist:
            if _match_host(to_host, pattern):
                return
        raise RedirectNotAllowed(from_url, to_url)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Handler que NO sigue redirects automáticamente.

    Si la URL final requiere redirect, urllib abre la nueva URL sin
    notificar — pero nuestro _HttpFetcher chequea response.geturl() y
    valida contra allowlist antes de procesar.
    """

    def http_error_301(self, req, fp, code, msg, headers):  # type: ignore[override]
        return self._follow(req, fp, code, msg, headers)

    def http_error_302(self, req, fp, code, msg, headers):  # type: ignore[override]
        return self._follow(req, fp, code, msg, headers)

    def http_error_303(self, req, fp, code, msg, headers):  # type: ignore[override]
        return self._follow(req, fp, code, msg, headers)

    def http_error_307(self, req, fp, code, msg, headers):  # type: ignore[override]
        return self._follow(req, fp, code, msg, headers)

    def _follow(self, req, fp, code, msg, headers):  # type: ignore[override]
        # Deja que urllib haga el redirect; _HttpFetcher valida final_url.
        return super().http_error_302(req, fp, code, msg, headers) or fp


def _match_host(host: str, pattern: str) -> bool:
    """Sufijo DNS. 'example.com' matchea 'example.com' y 'a.b.example.com'."""
    pattern = pattern.lower().lstrip(".")
    host = host.lower()
    return host == pattern or host.endswith("." + pattern)


# --------------------------------------------------------------------------- #
# Allowlist helper (Spec §2.2)
# --------------------------------------------------------------------------- #


def _check_allowlist(url: str, allowlist: list[str] | None) -> None:
    """Raise FetchError si URL no matchea allowlist (si allowlist is not None)."""
    if allowlist is None:
        return
    host = (urlparse(url).hostname or "").lower()
    for pattern in allowlist:
        if _match_host(host, pattern):
            return
    raise FetchError(f"url {url!r} not in allowlist")


# --------------------------------------------------------------------------- #
# Orquestador público (Spec §2.2)
# --------------------------------------------------------------------------- #


def fetch(
    url: str,
    *,
    timeout: float = 10.0,
    max_bytes: int = 5_000_000,
    allowlist: list[str] | None = None,
    _opener: Any = None,
) -> FetchResult:
    """Resuelve UNA URL y devuelve el texto extraído.

    Args:
        url: Solo http:// o https://.
        timeout: Segundos. Aplica a connect + read.
        max_bytes: Tope duro del cuerpo.
        allowlist: Si se da, la URL Y cualquier redirect cross-origin
            deben matchear al menos un patrón (sufijo DNS).
        _opener: Param de inyección para tests. No usar en producción.

    Returns:
        FetchResult con texto extraído, hashes, content-type, status,
        bytes leídos y notas de extracción.

    Raises:
        UnsupportedScheme, UnsupportedContentType, HTTPError,
        SizeExceeded, Timeout, RedirectNotAllowed, EmptyBody.
    """
    _check_allowlist(url, allowlist)

    http = _HttpFetcher(
        timeout=timeout,
        max_bytes=max_bytes,
        allowlist=allowlist,
        _opener=_opener,
    )

    body_bytes, content_type, status_code, http_notes = http.fetch(url)

    sha256_html = hashlib.sha256(body_bytes).hexdigest()

    extractor = ReadabilityExtractor()
    try:
        extractor.feed(body_bytes.decode("utf-8", errors="replace"))
        extractor.close()
    except Exception as e:
        raise FetchError(f"html parse failed: {e}") from e

    text = extractor.get_text()
    notes = http_notes + extractor.get_notes()

    if not text:
        raise EmptyBody("no extractable text")

    sha256_text = hashlib.sha256(text.encode("utf-8")).hexdigest()

    final_url = url  # _HttpFetcher podría exponer final_url si lo extendemos

    return FetchResult(
        url=url,
        final_url=final_url,
        text=text,
        sha256_html=sha256_html,
        sha256_text=sha256_text,
        content_type=content_type,
        status_code=status_code,
        bytes_read=len(body_bytes),
        extraction_notes=notes,
    )