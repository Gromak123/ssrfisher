#!/usr/bin/env python3
# ssrfisher.py
#
# SSRFisher — Hook requests. Reel logs.
# by @Gromak123
#
# A lightweight HTTP/HTTPS lure server for SSRF testing (CTF & pentest).
# - Custom status codes, redirects, bodies, and streamed file downloads
# - Pretty Rich console logs + clean JSONL file logging
# - HTTPS with auto-signed certs (--ssl) or provided cert/key
# - Mimic real servers + optional open CORS
# - Copy-friendly body output (--detach-body) (prints raw to stdout, no Rich truncation)
# - Unlimited body preview with 0 (console + JSONL)

from __future__ import annotations

import argparse
import base64
import datetime as _dt
import ipaddress
import itertools
import json
import mimetypes
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

# --- Rich ---
try:
    from rich.console import Console, Group
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.syntax import Syntax
    from rich.rule import Rule
except ImportError:
    raise SystemExit("Missing dependency: rich\nInstall with: pip install rich\n")

APP_VERSION = "1.0.1"
SLOGAN = "Hook requests. Reel logs."
AUTHOR_TAG = "@Gromak123"

ASCII_ART = r""" _____ _________________ _     _               
/  ___/  ___| ___ \  ___(_)   | |              
\ `--.\ `--.| |_/ / |_   _ ___| |__   ___ _ __ 
 `--. \`--. \    /|  _| | / __| '_ \ / _ \ '__|
/\__/ /\__/ / |\ \| |   | \__ \ | | |  __/ |   
\____/\____/\_| \_\_|   |_|___/_| |_|\___|_|   
                                               
                                               """

METHOD_STYLE = {
    "GET": "bold cyan",
    "HEAD": "bold cyan",
    "POST": "bold magenta",
    "PUT": "bold magenta",
    "PATCH": "bold magenta",
    "DELETE": "bold red",
    "OPTIONS": "bold yellow",
}

# Mimic presets (simple + plausible)
MIMIC_PRESETS: dict[str, dict] = {
    "nginx": {
        "server": "nginx",
        "headers": [
            ("Accept-Ranges", "bytes"),
            ("Connection", "keep-alive"),
        ],
    },
    "apache": {
        "server": "Apache/2.4.58 (Unix)",
        "headers": [
            ("Accept-Ranges", "bytes"),
            ("Connection", "keep-alive"),
        ],
    },
    "iis": {
        "server": "Microsoft-IIS/10.0",
        "headers": [
            ("X-Powered-By", "ASP.NET"),
            ("X-AspNet-Version", "4.0.30319"),
            ("X-AspNetMvc-Version", "5.2"),
            ("Accept-Ranges", "bytes"),
        ],
    },
}


# ---------------------------
# Utility
# ---------------------------
def now_iso() -> str:
    return _dt.datetime.now().isoformat(timespec="seconds")


def status_style(code: int) -> str:
    if 200 <= code <= 299:
        return "bold green"
    if 300 <= code <= 399:
        return "bold cyan"
    if 400 <= code <= 499:
        return "bold yellow"
    return "bold red"


def is_redirect(code: int) -> bool:
    return 300 <= code < 400


def parse_headers(kv_list: list[str] | None) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for item in kv_list or []:
        if ":" not in item:
            raise ValueError(f"Invalid header (expected 'Key: Value'): {item!r}")
        k, v = item.split(":", 1)
        out.append((k.strip(), v.lstrip()))
    return out


def merge_headers(base: list[tuple[str, str]], override: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """
    Merge headers case-insensitively, letting 'override' win.
    Keeps a stable order: base first, then any new override keys.
    """
    store: dict[str, tuple[str, str]] = {}
    order: list[str] = []

    def put(k: str, v: str) -> None:
        lk = k.lower()
        if lk not in store:
            order.append(lk)
        store[lk] = (k, v)

    for k, v in base:
        put(k, v)
    for k, v in override:
        put(k, v)

    return [store[lk] for lk in order]


def pretty_body(body: bytes, content_type: str, maxn: int) -> tuple[str, str, bool]:
    """
    Return (lang, rendered_str, truncated_bool) for console display.
    maxn == 0 means unlimited.
    """
    if not body:
        return "text", "", False

    if maxn <= 0:
        shown = body
        truncated = False
    else:
        truncated = len(body) > maxn
        shown = body[:maxn]

    ct = (content_type or "").lower()

    if "application/json" in ct:
        try:
            obj = json.loads(shown.decode("utf-8", errors="strict"))
            return "json", json.dumps(obj, indent=2, ensure_ascii=False), truncated
        except Exception:
            pass

    if "application/x-www-form-urlencoded" in ct:
        try:
            qs = shown.decode("utf-8", errors="replace")
            parsed = parse_qs(qs, keep_blank_values=True)
            return "json", json.dumps(parsed, indent=2, ensure_ascii=False), truncated
        except Exception:
            pass

    return "text", shown.decode("utf-8", errors="replace"), truncated


def sanitize_header_value(value: str, arg_name: str) -> str:
    """
    Prevent header injection via CRLF.
    """
    if any(c in value for c in ("\r", "\n")):
        raise SystemExit(f"{arg_name}: invalid value (CR/LF not allowed)")
    return value.strip()


def script_prog() -> str:
    # Avoid hardcoding ssrfisher.py/ssrf_server.py in help output
    base = os.path.basename(sys.argv[0] or "") or "ssrfisher.py"
    return base


# ---------------------------
# TLS helpers
# ---------------------------
def _parse_sans(s: str | None) -> tuple[list[str], list[ipaddress._BaseAddress]]:
    dns: list[str] = []
    ips: list[ipaddress._BaseAddress] = []
    if not s:
        return dns, ips
    for item in [x.strip() for x in s.split(",") if x.strip()]:
        try:
            ips.append(ipaddress.ip_address(item))
        except ValueError:
            dns.append(item)
    return dns, ips


def _best_default_cn(bind_addr: str) -> str:
    try:
        ip = ipaddress.ip_address(bind_addr)
        if ip.is_unspecified:  # 0.0.0.0 or ::
            return "localhost"
        return bind_addr
    except ValueError:
        return bind_addr or "localhost"


def _auto_sans(bind_addr: str, extra_san: str | None) -> tuple[list[str], list[ipaddress._BaseAddress]]:
    dns = ["localhost"]
    ips: list[ipaddress._BaseAddress] = [
        ipaddress.ip_address("127.0.0.1"),
        ipaddress.ip_address("::1"),
    ]

    try:
        ip = ipaddress.ip_address(bind_addr)
        if not ip.is_unspecified:
            ips.append(ip)
    except ValueError:
        if bind_addr and bind_addr not in ("0.0.0.0", "::"):
            dns.append(bind_addr)

    extra_dns, extra_ips = _parse_sans(extra_san)
    for d in extra_dns:
        if d not in dns:
            dns.append(d)
    for i in extra_ips:
        if i not in ips:
            ips.append(i)

    return dns, ips


def _try_generate_selfsigned_with_cryptography(
    cert_path: str,
    key_path: str,
    common_name: str,
    bind_addr: str,
    extra_san: str | None,
) -> None:
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except Exception as e:
        raise RuntimeError(f"cryptography not available: {e!r}")

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SSRFisher"),
    ])

    dns, ips = _auto_sans(bind_addr, extra_san)
    san_entries = [x509.DNSName(d) for d in dns] + [x509.IPAddress(i) for i in ips]

    now = _dt.datetime.now(_dt.timezone.utc)  # timezone-aware UTC
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(minutes=5))
        .not_valid_after(now + _dt.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .sign(key, hashes.SHA256())
    )

    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def _try_generate_selfsigned_with_openssl(
    cert_path: str,
    key_path: str,
    common_name: str,
    bind_addr: str,
    extra_san: str | None,
) -> None:
    dns, ips = _auto_sans(bind_addr, extra_san)
    san_parts = [f"DNS:{d}" for d in dns] + [f"IP:{str(i)}" for i in ips]
    san_value = "subjectAltName=" + ",".join(san_parts)

    base_cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", key_path, "-out", cert_path,
        "-days", "365",
        "-subj", f"/CN={common_name}",
    ]

    cmd_with_san = base_cmd + ["-addext", san_value]
    try:
        subprocess.run(cmd_with_san, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return
    except Exception:
        pass

    subprocess.run(base_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def prepare_ssl_material(
    mode: str,
    ssl_key: str | None,
    common_name: str,
    bind_addr: str,
    extra_san: str | None,
) -> tuple[str, str | None, str | None, dict]:
    temp_dir: str | None = None
    details: dict = {}

    if mode == "auto":
        temp_dir = tempfile.mkdtemp(prefix="ssrfisher_tls_")
        cert_path = os.path.join(temp_dir, "cert.pem")
        key_path = os.path.join(temp_dir, "key.pem")

        details["cn"] = common_name
        dns, ips = _auto_sans(bind_addr, extra_san)
        details["san_dns"] = dns
        details["san_ip"] = [str(i) for i in ips]

        try:
            _try_generate_selfsigned_with_cryptography(cert_path, key_path, common_name, bind_addr, extra_san)
            details["backend"] = "cryptography"
        except Exception:
            _try_generate_selfsigned_with_openssl(cert_path, key_path, common_name, bind_addr, extra_san)
            details["backend"] = "openssl"

        return cert_path, key_path, temp_dir, details

    cert_path = mode
    if not os.path.isfile(cert_path):
        raise SystemExit(f"--ssl: certificate not found: {cert_path}")

    key_path = ssl_key
    if key_path is not None and not os.path.isfile(key_path):
        raise SystemExit(f"--ssl-key: key not found: {key_path}")

    details["backend"] = "provided"
    return cert_path, key_path, None, details


def build_ssl_context(cert_path: str, key_path: str | None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    return ctx


# ---------------------------
# HTTP handler
# ---------------------------
class SSRFHandler(BaseHTTPRequestHandler):
    # Keep default clean (no "Python/x.y")
    server_version = "SSRFisher/" + APP_VERSION
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        return

    def version_string(self) -> str:
        custom = getattr(self.server, "server_header", None)
        if custom:
            return custom
        return super().version_string().strip()

    def _next_req_id(self) -> int:
        with self.server._counter_lock:
            return next(self.server._counter)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return b""
        return self.rfile.read(length)

    def _file_log(self, entry: dict) -> None:
        fp = self.server.log_fp
        if not fp:
            return
        with self.server.log_file_lock:
            fp.write(json.dumps(entry, ensure_ascii=False) + "\n")
            fp.flush()

    def _emit_cors_headers(self) -> None:
        if not getattr(self.server, "cors_enabled", False):
            return

        origin = self.headers.get("Origin")
        creds_requested = bool(getattr(self.server, "cors_credentials", False))
        open_mode = bool(getattr(self.server, "cors_open", False))
        configured_origin = getattr(self.server, "cors_origin", None)  # may be None

        # Browser reality:
        # - Credentials + '*' is rejected, so we reflect Origin when creds/open is enabled.
        reflect_origin = False
        allow_origin: str

        if configured_origin is not None:
            if configured_origin == "*" and creds_requested:
                reflect_origin = True
                allow_origin = "*"
            else:
                allow_origin = configured_origin
        else:
            reflect_origin = creds_requested or open_mode
            allow_origin = "*"

        send_creds = creds_requested

        if reflect_origin:
            if origin:
                allow_origin = origin
                self.send_header("Vary", "Origin")
            else:
                allow_origin = "*"
                send_creds = False

        self.send_header("Access-Control-Allow-Origin", allow_origin)

        if send_creds:
            self.send_header("Access-Control-Allow-Credentials", "true")

        allow_methods = getattr(self.server, "cors_allow_methods", None) or "GET,POST,PUT,PATCH,DELETE,OPTIONS,HEAD"
        self.send_header("Access-Control-Allow-Methods", allow_methods)

        allow_headers = getattr(self.server, "cors_allow_headers", None)
        if allow_headers is None:
            req_hdrs = self.headers.get("Access-Control-Request-Headers")
            allow_headers = req_hdrs if req_hdrs else "Authorization,Content-Type"
        self.send_header("Access-Control-Allow-Headers", allow_headers)

        expose = getattr(self.server, "cors_expose_headers", None)
        if expose is not None:
            self.send_header("Access-Control-Expose-Headers", expose)
        elif open_mode:
            self.send_header("Access-Control-Expose-Headers", "*")

        max_age = getattr(self.server, "cors_max_age", None)
        if max_age is not None:
            self.send_header("Access-Control-Max-Age", str(max_age))

        if getattr(self.server, "cors_private_network", False):
            if (self.headers.get("Access-Control-Request-Private-Network") or "").lower() == "true":
                self.send_header("Access-Control-Allow-Private-Network", "true")

    def _send_response(self, req_id: int, send_body: bool = True) -> dict:
        code = self.server.response_code

        body_bytes = self.server.response_body
        file_path = self.server.response_file_path
        file_size = self.server.response_file_size

        content_type = self.server.content_type
        location = self.server.location if (is_redirect(code) and self.server.location) else None
        content_disposition = self.server.content_disposition

        length = file_size if file_path else len(body_bytes or b"")

        self.send_response(code)

        if getattr(self.server, "emit_ssrfisher_headers", True):
            self.send_header("X-SSRFisher", "1")
            self.send_header("X-SSRFisher-ReqID", str(req_id))

        self._emit_cors_headers()

        if location:
            self.send_header("Location", location)

        if content_disposition:
            self.send_header("Content-Disposition", content_disposition)

        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))

        for k, v in self.server.extra_headers:
            self.send_header(k, v)

        self.end_headers()

        if send_body:
            if file_path:
                with open(file_path, "rb") as f:
                    shutil.copyfileobj(f, self.wfile)
            elif body_bytes:
                self.wfile.write(body_bytes)

        return {
            "status": code,
            "location": location,
            "content_type": content_type,
            "content_disposition": content_disposition,
            "content_length": length,
            "tls": bool(self.server.tls_enabled),
            "cors": bool(getattr(self.server, "cors_enabled", False)),
        }

    def _console_log(self, req_id: int, req_body: bytes, elapsed_ms: int, resp_meta: dict) -> None:
        if self.server.quiet:
            return

        console: Console = self.server.console
        parts = urlsplit(self.path)
        path_only = parts.path or "/"
        query = parts.query or ""
        qdict = parse_qs(query, keep_blank_values=True) if query else {}

        client_ip, client_port = self.client_address
        method = self.command.upper()

        title = Text.assemble(
            ("#", "dim"),
            (str(req_id), "bold white"),
            ("  ", "dim"),
            (now_iso(), "dim"),
            ("  ", "dim"),
            (f"{client_ip}:{client_port}", "dim"),
            ("  ", "dim"),
            (method, METHOD_STYLE.get(method, "bold white")),
            (" ", "dim"),
            (path_only, "bold white"),
        )
        if query:
            title.append("  ?" + query, style="dim")

        summary = Table.grid(padding=(0, 1))
        summary.add_column(justify="right", style="cyan", no_wrap=True)
        summary.add_column(style="white")

        host = self.headers.get("Host", "")
        ua = self.headers.get("User-Agent", "")
        xff = self.headers.get("X-Forwarded-For", "")
        if host:
            summary.add_row("Host", host)
        if xff:
            summary.add_row("X-Forwarded-For", xff)
        if ua:
            summary.add_row("User-Agent", ua)

        summary.add_row("HTTP", self.request_version)
        summary.add_row("Handled", f"{elapsed_ms} ms")

        renderables = [summary]

        if qdict:
            qp_table = Table(title="Query params", title_style="bold", header_style="bold")
            qp_table.add_column("Key", style="cyan", no_wrap=True)
            qp_table.add_column("Values", style="white")
            for k, vals in qdict.items():
                qp_table.add_row(k, json.dumps(vals, ensure_ascii=False))
            renderables.append(qp_table)

        if self.server.show_headers:
            hdr_table = Table(title="Headers", title_style="bold", header_style="bold")
            hdr_table.add_column("Header", style="cyan", no_wrap=True)
            hdr_table.add_column("Value", style="white")
            for k, v in self.headers.items():
                hdr_table.add_row(k, v)
            renderables.append(hdr_table)

        detached_body: tuple[str, str, str] | None = None  # (lang, rendered, label)

        if self.server.show_body:
            ct = self.headers.get("Content-Type", "")
            maxn = self.server.log_body_max
            lang, rendered, truncated = pretty_body(req_body, ct, maxn)

            if not req_body:
                renderables.append(Text("(empty body)", style="dim"))
            else:
                label = f"{len(req_body)} bytes"
                if ct:
                    label += f" | {ct}"
                if maxn <= 0:
                    label += " | unlimited"
                if truncated and maxn > 0:
                    label += f" | truncated (+{len(req_body) - maxn} bytes)"

                if getattr(self.server, "detach_body", False):
                    renderables.append(Text(f"(body printed below for easy copy) [{label}]", style="dim"))
                    detached_body = (lang, rendered, label)
                else:
                    renderables.append(
                        Panel(
                            Syntax(rendered, lang, word_wrap=True),
                            title=f"Body  [{label}]",
                            title_align="left",
                            border_style="bright_black",
                        )
                    )

        with self.server.console_lock:
            console.print(Panel(Group(*renderables), title=title, title_align="left", border_style="blue"))

            if detached_body:
                _lang, rendered, label = detached_body

                # Use Rich only for separators; print BODY via raw stdout to avoid Rich truncation on huge lines.
                console.print(Rule(Text(f"Body #{req_id}  [{label}]", style="dim"), style="bright_black"))

                if rendered and not rendered.endswith("\n"):
                    rendered += "\n"
                sys.stdout.write(rendered)
                sys.stdout.flush()

                console.print(Rule(style="bright_black"))

            code = resp_meta["status"]
            line = Text.assemble(("→ response ", "dim"), (str(code), status_style(code)))

            if resp_meta.get("location"):
                line.append("   Location: ", style="dim")
                line.append(resp_meta["location"], style="bold cyan")

            if resp_meta.get("content_disposition"):
                line.append("   Content-Disposition: ", style="dim")
                line.append(resp_meta["content_disposition"], style="bold")

            line.append("   bytes: ", style="dim")
            line.append(str(resp_meta.get("content_length", 0)), style="bold")

            if resp_meta.get("tls"):
                line.append("   TLS", style="bold green")

            if resp_meta.get("cors"):
                line.append("   CORS", style="bold green")

            console.print(line)
            console.print()

    def _handle_any(self, send_body: bool = True) -> None:
        req_id = self._next_req_id()
        start = time.time()
        req_body = self._read_body()
        elapsed_ms = int((time.time() - start) * 1000)

        parts = urlsplit(self.path)
        qdict = parse_qs(parts.query or "", keep_blank_values=True) if parts.query else {}

        resp_meta = self._send_response(req_id, send_body=send_body)

        try:
            self._console_log(req_id, req_body, elapsed_ms, resp_meta)
        except Exception as e:
            with self.server.console_lock:
                self.server.console.print(f"[red]Console log error:[/red] {e!r}")

        entry = {
            "ts": now_iso(),
            "app": "SSRFisher",
            "version": APP_VERSION,
            "req_id": req_id,
            "tls": bool(self.server.tls_enabled),
            "cors": bool(getattr(self.server, "cors_enabled", False)),
            "client": {"ip": self.client_address[0], "port": self.client_address[1]},
            "request": {
                "method": self.command,
                "path": parts.path,
                "raw_path": self.path,
                "query": parts.query,
                "query_params": qdict,
                "http_version": self.request_version,
            },
            "response": resp_meta,
            "timing": {"elapsed_ms": elapsed_ms},
        }

        if self.server.file_log_headers:
            entry["request"]["headers"] = dict(self.headers.items())

        if self.server.file_log_body:
            body_len = len(req_body)
            maxn = self.server.file_log_body_max
            if maxn <= 0:
                preview = req_body
                truncated = False
            else:
                preview = req_body[:maxn]
                truncated = body_len > maxn

            entry["request"]["body"] = {
                "length": body_len,
                "truncated": truncated,
                "preview_utf8": preview.decode("utf-8", errors="replace"),
                "preview_b64": base64.b64encode(preview).decode("ascii"),
            }

        self._file_log(entry)

    def do_GET(self): self._handle_any(True)
    def do_POST(self): self._handle_any(True)
    def do_PUT(self): self._handle_any(True)
    def do_DELETE(self): self._handle_any(True)
    def do_PATCH(self): self._handle_any(True)
    def do_OPTIONS(self): self._handle_any(True)
    def do_HEAD(self): self._handle_any(False)


# ---------------------------
# Parser + Rich help
# ---------------------------
def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog=script_prog(),
        description="SSRFisher is a lightweight HTTP/HTTPS lure server for SSRF testing (CTF & pentest).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,  # Rich by default; plain only when --no-color
    )

    ap.add_argument("-h", "--help", action="store_true", help="Show help and exit. (Rich by default)")
    ap.add_argument("--version", action="store_true", help="Show version and exit.")

    net = ap.add_argument_group("Network")
    net.add_argument(
        "--bind", "--listen", dest="bind", default="0.0.0.0",
        help="IP address to bind to (default: 0.0.0.0). Use a specific interface IP when you have multiple NICs."
    )
    net.add_argument("--port", "-p", type=int, default=8000, help="TCP port to listen on (default: 8000).")

    resp = ap.add_argument_group("Response")
    resp.add_argument("--code", "-c", type=int, default=200, help="HTTP status code to return (default: 200).")
    resp.add_argument("--location", default=None, help="Location header value (only sent if status code is 3xx).")

    src = resp.add_mutually_exclusive_group()
    src.add_argument("--body", "-b", default=None,
                     help="Response body as text (UTF-8). If no body/file is provided, defaults to 'OK\\n'.")
    src.add_argument("--body-file", default=None,
                     help="Path to a local file to use as the response body (fully loaded in memory).")
    src.add_argument("--download-file", default=None,
                     help="Path to a local file to stream as the response body (recommended for large files).")

    resp.add_argument("--content-type", default=None,
                      help="Override Content-Type. If omitted, guessed from file extension for file responses, else text/plain.")
    resp.add_argument("--content-disposition", default=None,
                      help='Set Content-Disposition manually, e.g. \'attachment; filename="poc.txt"\'.')
    resp.add_argument("--download-name", default=None,
                      help='If using --download-file and you want a different filename, e.g. "loot.png".')
    resp.add_argument("--inline", action="store_true",
                      help="If using --download-file and no --content-disposition is set, use inline instead of attachment.")

    mimic_choices = ", ".join(sorted(MIMIC_PRESETS.keys()))
    mimic = ap.add_argument_group("Response fingerprinting / mimicry")
    mimic.add_argument(
        "--no-ssrfisher-headers",
        action="store_true",
        help="Do not send SSRFisher fingerprint headers (X-SSRFisher, X-SSRFisher-ReqID)."
    )
    mimic.add_argument(
        "--server",
        dest="server_header",
        default=None,
        help="Override the HTTP 'Server' header value (e.g., 'nginx', 'Apache/2.4.58', 'Microsoft-IIS/10.0')."
    )
    mimic.add_argument(
        "--mimic",
        choices=sorted(MIMIC_PRESETS.keys()),
        default=None,
        help=f"Apply a preset ({mimic_choices}). Implies: disable X-SSRFisher headers, set a realistic Server header, and add common headers."
    )

    cors = ap.add_argument_group("CORS")
    cors.add_argument(
        "--cors-open",
        action="store_true",
        help="Enable permissive CORS (reflect Origin when present; allow credentials; allow common methods/headers)."
    )
    cors.add_argument(
        "--cors-origin",
        default=None,
        help="Override Access-Control-Allow-Origin (e.g., '*', 'https://example.com'). "
             "If omitted and credentials are enabled, Origin is reflected."
    )
    cors.add_argument(
        "--cors-credentials",
        action="store_true",
        help="Send Access-Control-Allow-Credentials: true (forces Origin reflection if --cors-origin isn't set)."
    )
    cors.add_argument(
        "--cors-allow-methods",
        default=None,
        help="Override Access-Control-Allow-Methods (default: GET,POST,PUT,PATCH,DELETE,OPTIONS,HEAD)."
    )
    cors.add_argument(
        "--cors-allow-headers",
        default=None,
        help="Override Access-Control-Allow-Headers. If omitted, echoes Access-Control-Request-Headers or uses 'Authorization,Content-Type'."
    )
    cors.add_argument(
        "--cors-expose-headers",
        default=None,
        help="Set Access-Control-Expose-Headers. If omitted with --cors-open, uses '*'."
    )
    cors.add_argument(
        "--cors-max-age",
        type=int,
        default=600,
        help="Set Access-Control-Max-Age in seconds (default: 600). Use 0 to disable."
    )
    cors.add_argument(
        "--cors-private-network",
        action="store_true",
        help="If the request asks for Private Network access, reply with Access-Control-Allow-Private-Network: true."
    )

    hdr = ap.add_argument_group("Custom headers")
    hdr.add_argument("--add-header", action="append", default=[],
                     help="Add a custom response header (repeatable). Example: --add-header 'X-Test: 1'")

    ui = ap.add_argument_group("Console output")
    ui.add_argument("--log-body-max", type=int, default=4096,
                    help="Max request body bytes displayed in console (default: 4096). Use 0 for unlimited.")
    ui.add_argument("--detach-body", action="store_true",
                    help="Print request bodies below the main request panel (copy-friendly, no borders).")
    ui.add_argument("--no-color", action="store_true",
                    help="Disable colored console output (also switches help to plain argparse output).")
    ui.add_argument("--no-headers", action="store_true", help="Do not display request headers in console.")
    ui.add_argument("--no-body", action="store_true", help="Do not display request bodies in console.")
    ui.add_argument("--quiet", action="store_true",
                    help="Disable all console output (useful when only writing JSONL logs).")

    logg = ap.add_argument_group("File logging (JSONL)")
    logg.add_argument("--log-file", default=None,
                      help="Append JSONL events to this file (one JSON object per request).")
    logg.add_argument("--file-log-headers", action="store_true",
                      help="Include request headers in JSONL logs.")
    logg.add_argument("--file-log-body", action="store_true",
                      help="Include request body preview in JSONL logs (UTF-8 + base64).")
    logg.add_argument("--file-log-body-max", type=int, default=8192,
                      help="Max request body bytes stored in JSONL logs (default: 8192). Use 0 for unlimited.")

    tls = ap.add_argument_group("TLS / HTTPS")
    tls.add_argument("--ssl", nargs="?", const="auto", default=None,
                     help="Enable HTTPS. If used without a value, SSRFisher generates an auto-signed certificate. "
                          "If a value is provided, it must be a PEM certificate path (can be combined cert+key PEM).")
    tls.add_argument("--ssl-key", default=None,
                     help="PEM private key path (only needed if the cert PEM does not include the private key).")
    tls.add_argument("--ssl-cn", default=None,
                     help="Common Name for auto-signed cert. Default is derived from --bind (specific IP) or 'localhost'.")
    tls.add_argument("--ssl-san", default=None,
                     help="Extra SubjectAltName entries for auto-signed cert (comma-separated, DNS or IP). "
                          "Example: --ssl-san 'demo.local,10.0.0.12'")

    return ap


def _format_opt(a: argparse.Action) -> str:
    opt = ", ".join(a.option_strings)
    if a.nargs == "?":
        opt += " [VALUE]"
    elif a.nargs:
        opt += " VALUE"
    return opt


def print_rich_help(console: Console, parser: argparse.ArgumentParser) -> None:
    header = Table.grid(padding=(0, 1))
    header.add_column()
    header.add_row(Text(ASCII_ART, style="bold cyan"))
    header.add_row(Text(f"Version : {APP_VERSION}", style="bold white"))
    header.add_row(Text(SLOGAN, style="dim"))
    header.add_row(Text(AUTHOR_TAG, style="bold magenta"))
    console.print(Panel(header, border_style="cyan"))

    console.print(
        "[bold]SSRFisher[/bold] is a lightweight [cyan]HTTP/HTTPS lure server[/cyan] for SSRF testing (CTF & pentest).\n"
        "Control status codes, redirects, response bodies, file downloads, and log every request.\n"
        "\n"
        "[dim]Notes:[/dim]\n"
        "• Use [bold]--log-body-max 0[/bold] for unlimited console body preview.\n"
        "• Use [bold]--file-log-body-max 0[/bold] for unlimited JSONL body preview.\n"
        "• Use [bold]--detach-body[/bold] to print bodies below the panel (copy-friendly).\n"
    )

    usage = parser.format_usage().strip()
    console.print(Panel(Text(usage, style="white"), title="Usage", border_style="green"))

    for grp in parser._action_groups:
        actions = [a for a in grp._group_actions if getattr(a, "option_strings", None)]
        if not actions:
            continue

        table = Table(show_header=True, header_style="bold", box=None, padding=(0, 1))
        table.add_column("Option", style="cyan", no_wrap=True)
        table.add_column("Description", style="white")

        for a in actions:
            table.add_row(_format_opt(a), (a.help or "").strip())

        console.print(Panel(table, title=grp.title, title_align="left", border_style="blue"))

    examples = [
        ("Basic HTTP lure (200 OK)", f'python {script_prog()} --port 8000 --code 200 --body "OK"'),
        ("Redirect (3xx) with Location", f'python {script_prog()} --bind 0.0.0.0 --port 80 --code 302 --location "http://127.0.0.1/admin"'),
        ("Serve a local file as a download (streamed)", f'python {script_prog()} --port 8000 --code 200 --download-file "C:\\tmp\\poc.png"'),
        ("JSONL logging", f"python {script_prog()} --port 8000 --log-file .\\ssrfisher.jsonl --file-log-headers --file-log-body"),
        ("Unlimited console body (copy-friendly)", f"python {script_prog()} --port 8000 --log-body-max 0 --detach-body"),
        ("Unlimited JSONL body (use with care)", f"python {script_prog()} --port 8000 --log-file .\\ssrfisher.jsonl --file-log-body --file-log-body-max 0"),
        ("Mimic IIS (stealth headers + realistic Server)", f"python {script_prog()} --port 8000 --mimic iis"),
        ("Open CORS (credentials + Origin reflection)", f"python {script_prog()} --port 8000 --cors-open"),
        ("HTTPS auto-signed (recommended: pip install cryptography)", f"python {script_prog()} --bind 0.0.0.0 --port 443 --ssl"),
    ]

    ex_text = Text()
    for title, cmd in examples:
        ex_text.append(f"# {title}\n", style="dim")
        ex_text.append(f"{cmd}\n\n", style="white")

    console.print(Panel(ex_text, title="Examples", border_style="magenta"))


# ---------------------------
# Main
# ---------------------------
def main() -> None:
    parser = build_parser()

    pre_args, _unknown = parser.parse_known_args()

    if pre_args.version:
        print(f"SSRFisher Version : {APP_VERSION}")
        return

    if pre_args.help:
        if getattr(pre_args, "no_color", False):
            print(parser.format_help())
        else:
            console = Console(no_color=False)
            print_rich_help(console, parser)
        return

    args = parser.parse_args()
    console = Console(no_color=args.no_color)

    # Apply mimic preset (before headers/server finalization)
    mimic_headers: list[tuple[str, str]] = []
    if args.mimic:
        preset = MIMIC_PRESETS[args.mimic]
        mimic_headers = list(preset.get("headers", []))

        # Mimic implies: disable X-SSRFisher headers
        args.no_ssrfisher_headers = True

        # Set Server header if user didn't provide one
        if not args.server_header:
            args.server_header = preset.get("server")

    # Parse user headers + merge with mimic headers
    user_headers = parse_headers(args.add_header)
    extra_headers = merge_headers(mimic_headers, user_headers)

    # Default body if nothing provided
    if args.body is None and not args.body_file and not args.download_file:
        args.body = "OK\n"

    # Build response payload
    response_body: bytes | None = None
    response_file_path: str | None = None
    response_file_size = 0

    if args.download_file:
        response_file_path = args.download_file
        if not os.path.isfile(response_file_path):
            raise SystemExit(f"--download-file: file not found: {response_file_path}")
        response_file_size = os.path.getsize(response_file_path)
    elif args.body_file:
        if not os.path.isfile(args.body_file):
            raise SystemExit(f"--body-file: file not found: {args.body_file}")
        with open(args.body_file, "rb") as f:
            response_body = f.read()
    else:
        response_body = (args.body or "").encode("utf-8", errors="replace")

    # Content-Type
    if args.content_type:
        content_type = args.content_type
    else:
        if response_file_path or args.body_file:
            path = response_file_path or args.body_file
            guessed, _ = mimetypes.guess_type(path)
            content_type = guessed or "application/octet-stream"
        else:
            content_type = "text/plain; charset=utf-8"

    # Content-Disposition
    content_disposition = args.content_disposition
    if not content_disposition and response_file_path:
        fname = args.download_name or os.path.basename(response_file_path)
        mode = "inline" if args.inline else "attachment"
        content_disposition = f'{mode}; filename="{fname}"'

    # JSONL log file open (append)
    log_fp = open(args.log_file, "a", encoding="utf-8", newline="") if args.log_file else None

    # Server header override (safe)
    server_header = None
    if args.server_header:
        server_header = sanitize_header_value(args.server_header, "--server")

    # CORS config
    cors_enabled = bool(args.cors_open or args.cors_origin or args.cors_credentials)
    cors_max_age = None if args.cors_max_age == 0 else args.cors_max_age

    # Create server
    httpd = ThreadingHTTPServer((args.bind, args.port), SSRFHandler)

    # Server config
    httpd.response_code = args.code
    httpd.location = args.location
    httpd.response_body = response_body
    httpd.response_file_path = response_file_path
    httpd.response_file_size = response_file_size
    httpd.content_type = content_type
    httpd.content_disposition = content_disposition
    httpd.extra_headers = extra_headers

    httpd.emit_ssrfisher_headers = not args.no_ssrfisher_headers
    httpd.server_header = server_header

    httpd.cors_enabled = cors_enabled
    httpd.cors_open = bool(args.cors_open)
    httpd.cors_credentials = bool(args.cors_credentials or args.cors_open)
    httpd.cors_origin = args.cors_origin
    httpd.cors_allow_methods = args.cors_allow_methods
    httpd.cors_allow_headers = args.cors_allow_headers
    httpd.cors_expose_headers = args.cors_expose_headers
    httpd.cors_max_age = cors_max_age
    httpd.cors_private_network = bool(args.cors_private_network)

    httpd.log_body_max = args.log_body_max
    httpd.detach_body = bool(args.detach_body)
    httpd.show_headers = not args.no_headers
    httpd.show_body = not args.no_body
    httpd.quiet = args.quiet

    httpd.log_fp = log_fp
    httpd.log_file_lock = threading.Lock()
    httpd.file_log_headers = args.file_log_headers
    httpd.file_log_body = args.file_log_body
    httpd.file_log_body_max = args.file_log_body_max

    httpd._counter = itertools.count(1)
    httpd._counter_lock = threading.Lock()
    httpd.console = console
    httpd.console_lock = threading.Lock()

    # TLS setup (optional)
    tls_enabled = False
    scheme = "http"
    tls_details: dict = {}

    if args.ssl:
        cn = args.ssl_cn or _best_default_cn(args.bind)
        cert_path, key_path, _temp_dir, tls_details = prepare_ssl_material(
            args.ssl, args.ssl_key, cn, args.bind, args.ssl_san
        )
        ctx = build_ssl_context(cert_path, key_path)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        tls_enabled = True
        scheme = "https"

    httpd.tls_enabled = tls_enabled

    # Header panel + runtime info panel
    if not args.quiet:
        header = Table.grid(padding=(0, 1))
        header.add_column()
        header.add_row(Text(ASCII_ART, style="bold cyan"))
        header.add_row(Text(f"Version : {APP_VERSION}", style="bold white"))
        header.add_row(Text(SLOGAN, style="dim"))
        header.add_row(Text(AUTHOR_TAG, style="bold magenta"))
        console.print(Panel(header, border_style="cyan"))

        info = Table.grid(padding=(0, 2))
        info.add_column(justify="right", style="cyan", no_wrap=True)
        info.add_column(style="white")

        info.add_row("Listen", f"{scheme}://{args.bind}:{args.port}")
        info.add_row("TLS", "[bold green]ON[/bold green]" if tls_enabled else "[dim]OFF[/dim]")
        info.add_row("Status", f"[{status_style(args.code)}]{args.code}[/{status_style(args.code)}]")

        info.add_row("Mimic", args.mimic or "-")

        effective_server = httpd.server_header or f"SSRFisher/{APP_VERSION}"
        info.add_row("Server", effective_server)
        info.add_row("X-Headers", "ON" if httpd.emit_ssrfisher_headers else "OFF")

        info.add_row("CORS", "ON" if cors_enabled else "OFF")
        if cors_enabled:
            info.add_row("CORS creds", "ON" if httpd.cors_credentials else "OFF")
            info.add_row("CORS origin", httpd.cors_origin or ("reflect" if httpd.cors_credentials else "*"))

        info.add_row("Detach body", "ON" if httpd.detach_body else "OFF")
        info.add_row("Console max body", "unlimited" if args.log_body_max <= 0 else str(args.log_body_max))
        info.add_row("JSONL max body", "unlimited" if args.file_log_body_max <= 0 else str(args.file_log_body_max))

        if args.location and is_redirect(args.code):
            info.add_row("Location", f"[bold cyan]{args.location}[/bold cyan]")

        if content_disposition:
            info.add_row("Disposition", f"[bold]{content_disposition}[/bold]")

        info.add_row("Content-Type", content_type)

        if response_file_path:
            info.add_row("Response", f"{response_file_size} bytes (streamed file: {response_file_path})")
        else:
            info.add_row("Response", f"{len(response_body or b'')} bytes")

        if args.log_file:
            info.add_row("JSONL log", args.log_file)

        if tls_enabled and args.ssl == "auto":
            backend = tls_details.get("backend", "auto")
            info.add_row("Auto-cert", f"{backend} | CN={tls_details.get('cn','?')}")
            if tls_details.get("san_dns") or tls_details.get("san_ip"):
                info.add_row("SAN (DNS)", ", ".join(tls_details.get("san_dns", [])) or "-")
                info.add_row("SAN (IP)", ", ".join(tls_details.get("san_ip", [])) or "-")

        info.add_row("Stop", "CTRL+C")
        console.print(Panel(info, border_style="green"))

        if tls_enabled and args.ssl == "auto" and tls_details.get("backend") == "openssl":
            console.print("[yellow]Tip:[/yellow] For clean auto-signed cert generation, install cryptography: [bold]pip install cryptography[/bold]\n")

        if is_redirect(args.code) and not args.location:
            console.print("[yellow]Note:[/yellow] 3xx status without --location, so no Location header will be sent.\n")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        if not args.quiet:
            console.print("\n[dim]Stopped.[/dim]")
    finally:
        httpd.server_close()
        if log_fp:
            log_fp.close()


if __name__ == "__main__":
    main()
