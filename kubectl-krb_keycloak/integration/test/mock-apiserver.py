#!/usr/bin/env python3
"""Minimal HTTPS mock Kubernetes API server for integration tests.

Serves until it receives one kubectl request with an Authorization header,
prints headers/body and the decoded Bearer JWT, writes a machine-readable
record for assertions, then exits.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import ssl
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import urlparse


def b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def decode_jwt(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3 or not all(parts):
        raise ValueError("token is not a compact JWT with three non-empty segments")
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    # Signature is not verified; the mock only displays structure.
    return {"header": header, "payload": payload, "signature_present": parts[2] != ""}


def api_versions_body(server_address: str) -> bytes:
    return json.dumps(
        {
            "kind": "APIVersions",
            "versions": ["v1"],
            "serverAddressByClientCIDRs": [
                {"clientCIDR": "0.0.0.0/0", "serverAddress": server_address}
            ],
        }
    ).encode()


def version_body() -> bytes:
    return json.dumps(
        {
            "major": "1",
            "minor": "33",
            "gitVersion": "v1.33.0-mock",
            "gitCommit": "mock",
            "gitTreeState": "clean",
            "buildDate": "1970-01-01T00:00:00Z",
            "goVersion": "go1.25.0",
            "compiler": "gc",
            "platform": "linux/amd64",
        }
    ).encode()


class Handler(BaseHTTPRequestHandler):
    record_path: str = ""
    # Set after a request carrying Authorization is fully processed.
    done: bool = False
    result_code: int = 1

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write("mock-apiserver: " + (fmt % args) + "\n")

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self.handle_request()

    def do_POST(self) -> None:  # noqa: N802
        self.handle_request()

    def do_PUT(self) -> None:  # noqa: N802
        self.handle_request()

    def do_PATCH(self) -> None:  # noqa: N802
        self.handle_request()

    def do_DELETE(self) -> None:  # noqa: N802
        self.handle_request()

    def handle_request(self) -> None:
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length > 0 else b""
        headers = {k: v for k, v in self.headers.items()}
        auth = headers.get("Authorization") or headers.get("authorization") or ""
        path = urlparse(self.path).path

        # Health / accidental probes without credentials: ignore and keep listening.
        if not auth:
            self._respond(
                401,
                b'{"kind":"Status","status":"Failure","message":"Unauthorized","code":401}\n',
            )
            return

        print("=== mock Kubernetes API server: received request ===", flush=True)
        print(f"method: {self.command}", flush=True)
        print(f"path: {self.path}", flush=True)
        print("headers:", flush=True)
        for name, value in sorted(headers.items()):
            # Print full Authorization so the Bearer JWT is visible in logs.
            print(f"  {name}: {value}", flush=True)
        print("body:", flush=True)
        if body:
            try:
                print(body.decode(), flush=True)
            except UnicodeDecodeError:
                print(repr(body), flush=True)
        else:
            print("(empty)", flush=True)

        record: dict[str, Any] = {
            "method": self.command,
            "path": self.path,
            "headers": headers,
            "body": body.decode("utf-8", errors="replace"),
            "authorization": auth,
            "ok": False,
            "error": None,
            "jwt": None,
        }

        if not auth.startswith("Bearer "):
            record["error"] = "missing or non-Bearer Authorization header"
            self._fail(record, 401, b'{"kind":"Status","status":"Failure","message":"Unauthorized","code":401}\n')
            return

        token = auth[len("Bearer ") :].strip()
        if not token:
            record["error"] = "empty Bearer token"
            self._fail(record, 401, b'{"kind":"Status","status":"Failure","message":"Unauthorized","code":401}\n')
            return

        try:
            jwt = decode_jwt(token)
        except (ValueError, json.JSONDecodeError, binascii.Error) as err:
            record["error"] = f"invalid JWT: {err}"
            self._fail(record, 401, b'{"kind":"Status","status":"Failure","message":"invalid token","code":401}\n')
            return

        record["jwt"] = jwt
        record["token"] = token
        print("decoded JWT header:", flush=True)
        print(json.dumps(jwt["header"], indent=2, sort_keys=True), flush=True)
        print("decoded JWT payload:", flush=True)
        print(json.dumps(jwt["payload"], indent=2, sort_keys=True), flush=True)

        groups = jwt["payload"].get("groups")
        if not isinstance(groups, list) or "/developers" not in groups:
            record["error"] = "JWT groups claim missing /developers"
            self._fail(
                record,
                403,
                b'{"kind":"Status","status":"Failure","message":"forbidden","code":403}\n',
            )
            return

        record["ok"] = True
        self._write_record(record)
        print("verification passed: Bearer JWT present with /developers group", flush=True)

        host = self.headers.get("Host", "127.0.0.1:6443")
        if path in ("/api", "/api/"):
            self._respond(200, api_versions_body(host))
        elif path == "/version" or path.startswith("/version?"):
            self._respond(200, version_body())
        elif path.startswith("/api/"):
            self._respond(
                200,
                json.dumps(
                    {
                        "kind": "APIResourceList",
                        "groupVersion": "v1",
                        "resources": [],
                    }
                ).encode(),
            )
        else:
            self._respond(
                200,
                json.dumps({"kind": "Status", "status": "Success", "code": 200}).encode(),
            )
        Handler.result_code = 0
        Handler.done = True

    def _fail(self, record: dict[str, Any], status: int, body: bytes) -> None:
        self._write_record(record)
        self._respond(status, body)
        print(f"verification failed: {record['error']}", flush=True)
        Handler.result_code = 1
        Handler.done = True

    def _write_record(self, record: dict[str, Any]) -> None:
        with open(self.record_path, "w", encoding="utf-8") as handle:
            json.dump(record, handle, indent=2, sort_keys=True)
            handle.write("\n")

    def _respond(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class QuietHTTPServer(HTTPServer):
    """HTTPServer that tolerates short-lived probe connections without HTTP."""

    def handle_error(self, request: Any, client_address: Any) -> None:
        exc = sys.exc_info()[1]
        sys.stderr.write(f"mock-apiserver: connection from {client_address} error: {exc}\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", default="127.0.0.1:6443")
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--record", required=True, help="path to write the received request record JSON")
    args = parser.parse_args()

    host, port_s = args.listen.rsplit(":", 1)
    port = int(port_s)

    Handler.record_path = args.record
    Handler.done = False
    Handler.result_code = 1
    server = QuietHTTPServer((host, port), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=args.cert, keyfile=args.key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.timeout = 1.0

    print(f"mock Kubernetes API server listening on https://{host}:{port}", flush=True)
    try:
        while not Handler.done:
            server.handle_request()
    finally:
        server.server_close()
    return Handler.result_code


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # pragma: no cover - catastrophic startup failure
        print(f"mock-apiserver failed: {exc}", file=sys.stderr, flush=True)
        raise SystemExit(1) from exc
