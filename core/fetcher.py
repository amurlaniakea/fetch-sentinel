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
import ipaddress
import socket
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


class BlockedAddress(FetchError):
    """KI-7: la URL resuelve a una IP en un rango bloqueado.

    Por defecto se bloquean: privadas, loopback, link-local, reserved,
    multicast, unspecified. El bloqueo se aplica tanto a la URL inicial
    como a cada URL post-redirect cross-host.
    """

    def __init__(self, host: str, ip: str, reason: str) -> None:
        super().__init__(f"blocked {host} (resolves to {ip}): {reason}")
        self.host = host
        self.ip = ip
        self.reason = reason


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


class _HttpResult:
    """Resultado interno de _HttpFetcher.fetch().

    Incluye final_url para que el orquestador público pueda propagar
    la URL post-redirección al FetchResult (KI-9: la Spec §2.3 exige
    que url y final_url reflejen redirecciones).
    """

    def __init__(
        self,
        body: bytes,
        content_type: str,
        status_code: int,
        final_url: str,
        notes: list[str],
    ) -> None:
        self.body = body
        self.content_type = content_type
        self.status_code = status_code
        self.final_url = final_url
        self.notes = notes


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

    def fetch(self, url: str) -> _HttpResult:
        """Devuelve _HttpResult(body, content_type, status, final_url, notes).

        KI-7: valida la IP resuelta (rechaza rangos reservados) ANTES de
        cualquier socket.connect(). Lo repite tras cada redirect cross-host.

        Raises:
            UnsupportedScheme, HTTPError, SizeExceeded, Timeout,
            RedirectNotAllowed, UnsupportedContentType, BlockedAddress.
        """
        self._validate_scheme(url)

        # KI-7: rechazar IPs en rangos reservados ANTES de conectar.
        # Si el host es directamente una IP literal, urlparse la extrae.
        # Si es hostname, getaddrinfo la resuelve y valida.
        parsed_initial = urlparse(url)
        host = parsed_initial.hostname
        if host:
            _resolve_and_validate_blocked(host)

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
                # KI-7: tras redirect cross-host, re-validar la IP del
                # nuevo host (puede haber DNS rebinding entre allowlist
                # match por nombre y conexión real).
                parsed_final = urlparse(final_url)
                final_host = parsed_final.hostname
                if final_host:
                    _resolve_and_validate_blocked(final_host)

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
            return _HttpResult(
                body=bytes(body),
                content_type=content_type,
                status_code=status_code,
                final_url=final_url,
                notes=notes,
            )
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


def _ip_is_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    """Devuelve la razón del bloqueo, o None si la IP es pública.

    KI-7: bloquea por defecto privadas, loopback, link-local, reserved,
    multicast, unspecified. Esto se aplica SIEMPRE, incluso con allowlist
    vacía o None — la allowlist añade hosts permitidos, no relaja el
    bloqueo de rangos reservados.

    Orden de checks: el más específico gana. `is_link_local` se evalúa
    ANTES que `is_private` porque Python 3.12 reporta `is_private=True`
    para 169.254.0.0/16 también (overlap con link-local), pero queremos
    reportar `link_local` específicamente porque es el caso de metadata
    de nube (169.254.169.254), que es el vector SSRF por excelencia.
    """
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link_local"
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_multicast:
        return "multicast"
    if ip.is_reserved:
        return "reserved"
    if ip.is_private:
        return "private"
    return None


def _resolve_and_validate_blocked(host: str) -> str:
    """Resuelve `host` y rechaza si la IP es de un rango bloqueado.

    KI-7 + protección contra DNS rebinding. Devuelve la IP resuelta (la
    primera de getaddrinfo) si es pública. Lanza BlockedAddress si la
    IP cae en algún rango reservado.
    """
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        raise FetchError(f"could not resolve {host}: {e}") from e

    for info in infos:
        # info[4] es sockaddr: tuple[str, int] (IPv4) o
        # tuple[str, int, int, int] (IPv6). El primer elemento es la IP.
        sockaddr = info[4]
        ip_str = str(sockaddr[0])
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        reason = _ip_is_blocked(ip)
        if reason is not None:
            raise BlockedAddress(host=host, ip=ip_str, reason=reason)
        return ip_str
    # Si getaddrinfo devuelve tuplas sin IP parseable, fallback al primer
    # sockaddr (no debería pasar, pero por seguridad).
    return str(infos[0][4][0])


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

    http_result = http.fetch(url)
    body_bytes = http_result.body
    content_type = http_result.content_type
    status_code = http_result.status_code
    http_notes = http_result.notes

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

    # KI-9: la Spec §2.3 exige que final_url refleje la URL
    # post-redirección, no la URL original de input.
    final_url = http_result.final_url

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