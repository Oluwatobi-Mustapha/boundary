#!/usr/bin/env python3
"""
Local signed proxy for the Boundary audit dashboard.

Why:
- API Gateway routes are protected with AWS_IAM.
- Browsers do not natively SigV4-sign requests.
- This proxy signs requests with your current AWS credentials and forwards them.

Usage:
  python3 scripts/dashboard_proxy.py \
    --dashboard-url "https://<api-id>.execute-api.<region>.amazonaws.com/dashboard" \
    --open
"""

import argparse
import ssl
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest


def _parse_dashboard_url(dashboard_url: str) -> Tuple[str, str, str]:
    parsed = urlparse(dashboard_url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError("dashboard_url must be a valid https URL")

    host_parts = parsed.netloc.split(".")
    if len(host_parts) < 4 or host_parts[1] != "execute-api":
        raise ValueError("dashboard_url must point to an API Gateway execute-api endpoint")

    region = host_parts[2]
    api_root = f"{parsed.scheme}://{parsed.netloc}"
    default_path = parsed.path or "/dashboard"
    return api_root, default_path, region


def _hop_by_hop(header_name: str) -> bool:
    return header_name.lower() in {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
    }


class _SignedProxyHandler(BaseHTTPRequestHandler):
    api_root = ""
    default_path = "/dashboard"
    region = ""
    credentials = None
    ssl_context = None

    def _target_url(self) -> str:
        incoming = urlparse(self.path)
        path = incoming.path or "/"
        if path == "/":
            path = self.default_path
        query = f"?{incoming.query}" if incoming.query else ""
        return f"{self.api_root}{path}{query}"

    def _signed_headers(self, target_url: str) -> Dict[str, str]:
        req = AWSRequest(method="GET", url=target_url, headers={"Host": urlparse(target_url).netloc})
        SigV4Auth(self.credentials, "execute-api", self.region).add_auth(req)
        return dict(req.prepare().headers.items())

    def do_GET(self):  # noqa: N802
        target_url = self._target_url()
        try:
            signed_headers = self._signed_headers(target_url)
            upstream_req = Request(target_url, method="GET", headers=signed_headers)
            with urlopen(upstream_req, timeout=30, context=self.ssl_context) as upstream:
                body = upstream.read()
                self.send_response(upstream.getcode())
                for key, value in upstream.headers.items():
                    if _hop_by_hop(key):
                        continue
                    if key.lower() == "content-length":
                        continue
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        except HTTPError as err:
            body = err.read()
            self.send_response(err.code)
            for key, value in err.headers.items():
                if _hop_by_hop(key):
                    continue
                if key.lower() == "content-length":
                    continue
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except URLError as err:
            message = f"Upstream connectivity error: {err}".encode("utf-8")
            self.send_response(502)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(message)))
            self.end_headers()
            self.wfile.write(message)
        except Exception as err:  # pragma: no cover - operational fallback
            message = f"Proxy error: {err}".encode("utf-8")
            self.send_response(500)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(message)))
            self.end_headers()
            self.wfile.write(message)

    def log_message(self, fmt, *args):  # noqa: A003
        # Keep logs concise and readable.
        print(f"[dashboard-proxy] {self.address_string()} - {fmt % args}")


def _build_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    try:
        import certifi  # type: ignore

        ctx.load_verify_locations(cafile=certifi.where())
    except Exception:
        # Fall back to system trust store if certifi is unavailable.
        pass
    return ctx


def main() -> None:
    parser = argparse.ArgumentParser(description="Run local SigV4 proxy for Boundary dashboard")
    parser.add_argument("--dashboard-url", required=True, help="Terraform output audit_dashboard_url")
    parser.add_argument("--bind", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8787, help="Local port (default: 8787)")
    parser.add_argument("--open", action="store_true", help="Open browser after proxy starts")
    args = parser.parse_args()

    api_root, default_path, region = _parse_dashboard_url(args.dashboard_url)
    session = boto3.Session()
    credentials = session.get_credentials()
    if credentials is None:
        raise RuntimeError("No AWS credentials found. Authenticate first (AWS CLI/SSO).")
    frozen = credentials.get_frozen_credentials()

    _SignedProxyHandler.api_root = api_root
    _SignedProxyHandler.default_path = default_path
    _SignedProxyHandler.region = region
    _SignedProxyHandler.credentials = frozen
    _SignedProxyHandler.ssl_context = _build_ssl_context()

    server = ThreadingHTTPServer((args.bind, args.port), _SignedProxyHandler)
    local_url = f"http://{args.bind}:{args.port}/"
    print(f"Signed proxy listening on {local_url}")
    print(f"Forward target: {api_root}{default_path}")

    if args.open:
        webbrowser.open(local_url)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
