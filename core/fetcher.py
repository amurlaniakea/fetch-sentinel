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
import http.client
import ipaddress
import socket
import urllib.error
import urllib.parse
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


class RedirectLimitExceeded(FetchError):
    """KI-11 (T48): el chain de redirects excedió el máximo permitido.

    Por defecto 5 hops (suficiente para usos legítimos, previene loops
    accidentales y ataques de DoS vía cadena infinita de redirects).
    """

    def __init__(self, max_redirects: int) -> None:
        super().__init__(
            f"redirect chain exceeded {max_redirects} hops"
        )
        self.max_redirects = max_redirects


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

    `location` se añade en T48: cuando el status es 3xx, el loop de
    redirects necesita el header Location para resolver la siguiente
    URL. Es `None` si no había Location.
    """

    def __init__(
        self,
        body: bytes,
        content_type: str,
        status_code: int,
        final_url: str,
        notes: list[str],
        location: str | None = None,
    ) -> None:
        self.body = body
        self.content_type = content_type
        self.status_code = status_code
        self.final_url = final_url
        self.notes = notes
        self.location = location


class _HttpFetcher:
    """Encapsula http.client con timeout, max_bytes, allowlist, pinning de IP.

    KI-10 (T47): pinning de IP — la conexión TCP se abre contra la IP
    validada (no contra una segunda resolución DNS interna). Cierra el
    TOCTOU entre la validación KI-7 y la conexión real.

    KI-11 (T48): redirects se manejan manualmente con un loop de max
    redirects. No hay HTTPRedirectHandler que siga redirects antes de
    que el llamante pueda validar el siguiente destino.

    Refactor de KI-9 (3250c4c): el antiguo _HttpFetcher usaba
    urllib.request.urlopen con _NoRedirectHandler (que NO era
    realmente "no redirect" — seguía redirects via super()). Ahora usa
    http.client.HTTPConnection / HTTPSConnection directamente con
    connect() sobreescrito y loop manual de redirects.
    """

    # KI-11: máximo número de redirects. Suficiente para usos legítimos
    # (URL shorteners, login flows), previene loops accidentales y DoS.
    DEFAULT_MAX_REDIRECTS = 5

    def __init__(
        self,
        *,
        timeout: float,
        max_bytes: int,
        allowlist: list[str] | None,
        max_redirects: int = DEFAULT_MAX_REDIRECTS,
        _opener: Any = None,
    ) -> None:
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.allowlist = allowlist
        self.max_redirects = max_redirects

    def fetch(self, url: str) -> _HttpResult:
        """Devuelve _HttpResult(body, content_type, status, final_url, notes).

        Loop manual de redirects (KI-11): hasta max_redirects hops,
        validando allowlist + IP en cada uno antes de conectar (T47/T48).

        Raises:
            UnsupportedScheme, HTTPError, SizeExceeded, Timeout,
            RedirectNotAllowed, RedirectLimitExceeded,
            UnsupportedContentType, BlockedAddress.
        """
        self._validate_scheme(url)

        current_url = url
        for _ in range(self.max_redirects + 1):
            result = self._do_request_pinned(current_url)
            status = result.status_code

            # 2xx: devolvemos.
            if 200 <= status < 300:
                return result

            # 4xx/5xx: error.
            if status >= 400:
                raise HTTPError(status)

            # 3xx: seguir solo si hay Location y estamos bajo max_redirects.
            if 300 <= status < 400:
                location = result.location
                if not location:
                    return result  # 3xx sin Location: devolvemos tal cual.
                # Resolver URL absoluta o relativa.
                new_url = urllib.parse.urljoin(current_url, location)
                # KI-14 (T51): validar scheme en CADA salto de redirect.
                # Sin esto, un redirect a gopher://, ftp://, file://, etc.
                # pasaría y _do_request_pinned lo trataría como HTTP plano,
                # permitiendo SSRF-a-puerto-arbitrario en hosts públicos
                # ya autorizados (Claude, 3ª ronda de auditoría).
                self._validate_scheme(new_url)
                # Validar allowlist cross-host.
                if new_url != current_url:
                    self._validate_redirect(current_url, new_url)
                # KI-7: re-validar IP del nuevo host ANTES de conectar.
                # NOTA (T53): la protección que cierra de verdad KI-11 vive
                # en _do_request_pinned(), que valida la IP en TODA
                # invocación — sea la URL inicial o un salto de redirect.
                # Esta línea aquí es defense-in-depth: si el llamante
                # modificase _do_request_pinned en el futuro y la
                # validación interna fallase, esta capa del bucle
                # seguiría protegiendo. NO es la primera línea de defensa.
                parsed_new = urlparse(new_url)
                if parsed_new.hostname:
                    _resolve_and_validate_blocked(parsed_new.hostname)
                current_url = new_url
                continue

            # Status 1xx u otro: tratar como error inesperado.
            raise FetchError(
                f"unexpected status code {status} from {current_url}"
            )

        # Si el loop se agotó sin 2xx, fue por max_redirects.
        raise RedirectLimitExceeded(self.max_redirects)

    def _do_request_pinned(self, url: str) -> _HttpResult:
        """Realiza UN request HTTP con pinning de IP (KI-10 / T47).

        Resuelve el host a una IP UNA vez, valida que no esté en rango
        bloqueado (KI-7), y abre la conexión TCP contra ESA IP. El
        `Host:` header va con el hostname original (para SNI / Host
        header / validaciones TLS).
        """
        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            raise FetchError(f"could not parse host from {url!r}")

        # KI-7: resolver IP y validar antes de cualquier socket.connect().
        validated_ip = _resolve_and_validate_blocked(host)

        # Determinar puerto.
        if parsed.port is not None:
            port = parsed.port
        elif parsed.scheme == "https":
            port = 443
        else:
            port = 80

        # Construir path (con query string).
        path = parsed.path or "/"
        if parsed.query:
            path = path + "?" + parsed.query

        # Crear la conexión. host= va aquí (no la IP) para SNI/Host
        # header/validación TLS. La IP la fijamos dentro de connect()
        # sobreescrito (T47).
        if parsed.scheme == "https":
            conn = http.client.HTTPSConnection(
                host=host,
                port=port,
                timeout=self.timeout,
            )
        else:
            conn = http.client.HTTPConnection(
                host=host,
                port=port,
                timeout=self.timeout,
            )

        # KI-10 / T47: PINNING. Sobreescribir connect() para que use
        # EXCLUSIVAMENTE la IP validada. NO se delega a super().connect()
        # porque urllib / http.client resuelven DNS por su cuenta
        # (segunda resolución DNS = ventana para DNS rebinding).
        #
        # Para HTTPS: HTTPSConnection.connect() en la stdlib hace
        # super().connect() (crea socket) y luego self._context.wrap_socket().
        # Si sobreescribo connect(), tengo que replicar el wrap_socket
        # manualmente con server_hostname=self.host (NO la IP) para que
        # la verificación de certificado TLS use el hostname original.
        # original_connect no se usa — la sobreescribimos entera.
        validated_ip_capture = validated_ip
        port_capture = port
        host_capture = host
        scheme_capture = parsed.scheme
        timeout_capture = self.timeout

        def _pinned_connect() -> None:
            sock = socket.create_connection(
                (validated_ip_capture, port_capture),
                timeout=timeout_capture,
            )
            if scheme_capture == "https":
                # _context es el SSLContext creado por HTTPSConnection.__init__
                # (defaults a ssl.create_default_context() si no se pasa).
                ctx = conn._context  # type: ignore[attr-defined]
                sock = ctx.wrap_socket(sock, server_hostname=host_capture)
            conn.sock = sock
            # Si necesitamos cerrar, conn.close() cierra sock si está set.

        conn.connect = _pinned_connect  # type: ignore[method-assign]

        try:
            conn.request(
                "GET",
                path,
                headers={
                    "Host": host,
                    "User-Agent": "fetch-sentinel/0.1",
                },
            )
            resp = conn.getresponse()
            status_code = resp.status
            content_type = resp.getheader("Content-Type", "")
            location = resp.getheader("Location", "")

            # Validar content-type solo en 2xx (los 3xx no leen body).
            # Para 3xx leemos Location arriba, status ya está, no leemos body.
            # Para 4xx/5xx leemos un poco para el mensaje pero no más.
            # Aquí leemos todo si es 2xx; si no, devolvemos sin body.

            # Validar status ANTES de procesar body.
            if status_code >= 400:
                # 4xx/5xx → HTTPError. Cerrar y propagar.
                try:
                    conn.close()
                except Exception:  # noqa: BLE001, S110
                    pass
                raise HTTPError(status_code)

            # Validar content-type solo en 2xx.
            if 200 <= status_code < 300 and not content_type.lower().startswith(
                "text/html"
            ):
                try:
                    conn.close()
                except Exception:  # noqa: BLE001, S110
                    pass
                raise UnsupportedContentType(
                    f"content-type {content_type!r} not supported"
                )

            # Leer body con tope (solo si 2xx).
            body = bytearray()
            if 200 <= status_code < 300:
                while True:
                    chunk = resp.read(8192)
                    if not chunk:
                        break
                    body.extend(chunk)
                    if len(body) > self.max_bytes:
                        try:
                            conn.close()
                        except Exception:  # noqa: BLE001, S110
                            pass
                        raise SizeExceeded(self.max_bytes, len(body))

            # Cerrar la conexión.
            try:
                conn.close()
            except Exception:  # noqa: BLE001, S110
                pass

            # Para 3xx, body queda vacío (no leemos); devolvemos con
            # location en el campo dedicado para que el loop de redirects
            # lo recoja sin tener que parsear notes[0].
            return _HttpResult(
                body=bytes(body),
                content_type=content_type,
                status_code=status_code,
                final_url=url,
                notes=[],
                location=location or None,
            )
        except TimeoutError as e:
            try:
                conn.close()
            except Exception:  # noqa: BLE001, S110
                pass
            raise Timeout(f"timeout after {self.timeout}s") from e
        except OSError as e:
            try:
                conn.close()
            except Exception:  # noqa: BLE001, S110
                pass
            raise FetchError(f"network error: {e}") from e

    @staticmethod
    def _validate_scheme(url: str) -> None:
        """Wrapper trivial sobre la función libre del módulo.

        Mantenido para no romper las 2 llamadas internas
        `self._validate_scheme(...)` en fetch() y en el bucle de
        redirects. La lógica real vive en `validate_scheme()` de
        módulo, accesible sin instanciar la clase.
        """
        validate_scheme(url)

    def _validate_redirect(self, from_url: str, to_url: str) -> None:
        # KI-7 residual: lista vacía o None = fail-closed (rechaza).
        # Antes era "sin allowlist, redirects OK".
        if not self.allowlist:
            raise RedirectNotAllowed(from_url, to_url)
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


def validate_scheme(url: str) -> None:
    """Levanta UnsupportedScheme si el scheme de `url` no es http o https.

    KI-7 residual (preparación): función libre de módulo, separada del
    método `_HttpFetcher._validate_scheme` para que `fetch()` público
    pueda llamarla sin instanciar la clase. El método de la clase
    queda como wrapper trivial que delega aquí.

    La razón histórica de no hacerlo así antes: el método usaba
    `self` implícitamente, pero la lógica no accede a ningún estado
    de instancia. Sacarla a función libre es refactor puro, sin
    cambio de comportamiento.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise UnsupportedScheme(f"scheme {parsed.scheme!r} not supported")


def _check_allowlist(url: str, allowlist: list[str] | None) -> None:
    """Levanta FetchError si `url` no matchea `allowlist`.

    KI-7 residual (decisión de Pedro, 2026-09-04): allowlist `None` o
    `[]` ahora se considera fail-closed (rechaza). Antes significaba
    'sin restricción'. Cambio de comportamiento por defecto del CLI:
    seguro por defecto. Para tests internos que necesiten el
    comportamiento previo, pasar una lista explícita con un patrón
    comodín — nunca se permite 'sin allowlist' de forma implícita
    desde el CLI.

    El mensaje de error apunta al CHANGELOG y a la config para que
    el operador sepa cómo recuperarse sin tener que leer el código.
    """
    if allowlist is None or len(allowlist) == 0:
        raise FetchError(
            f"url {url!r} rejected: allowlist is empty. "
            f"Pass --allowlist <pattern> (repeatable) or set "
            f"[fetch].allowlist in config.toml. "
            f"fetch-sentinel v0.2+ defaults to fail-closed: "
            f"empty allowlist means 'no host is allowed', NOT "
            f"'all hosts are allowed'."
        )
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
        allowlist: Lista de patrones DNS (sufijo) permitidos. Si se da,
            la URL Y cualquier redirect cross-origin deben matchear al
            menos un patrón. None y [] se consideran fail-closed
            (rechaza) — KI-7 residual, decisión de Pedro 2026-09-04.
        _opener: Param de inyección para tests. No usar en producción.

    Returns:
        FetchResult con texto extraído, hashes, content-type, status,
        bytes leídos y notas de extracción.

    Raises:
        UnsupportedScheme, UnsupportedContentType, HTTPError,
        SizeExceeded, Timeout, RedirectNotAllowed, EmptyBody.
    """
    # Orden de validación: scheme → allowlist → IP. Scheme primero
    # porque una URL con scheme no soportado (file://, javascript:)
    # no puede tener host parseable, así que el check de allowlist
    # no podría ejecutarse significativamente. Consistente con el
    # orden aplicado en redirects (T51).
    validate_scheme(url)
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