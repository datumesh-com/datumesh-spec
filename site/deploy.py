#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Deploy site/index.html and the logo files as a static Cloudflare Worker on datumesh.com and www.

    CF_API_TOKEN=... python3 site/deploy.py      (or the token in /root/cf-key)

The token needs Workers Scripts: Edit (account) and Workers Routes: Edit
(zone datumesh.com). Free plan; no server, no storage, no DNS change.
"""

import base64
import json
import os
import pathlib
import urllib.request
import uuid

ZONE_NAME = "datumesh.com"
SCRIPT = "datumesh-holding"
ROUTES = ["datumesh.com/*", "www.datumesh.com/*"]
API = "https://api.cloudflare.com/client/v4"
HERE = pathlib.Path(__file__).resolve().parent
ASSETS = HERE.parent / "assets"
# Path served -> (file, content type). Everything is embedded in the Worker.
FILES = {
    "/": (HERE / "index.html", "text/html; charset=utf-8"),
    "/datumesh-logo.svg": (ASSETS / "datumesh-logo.svg", "image/svg+xml"),
    "/datumesh-mark.svg": (ASSETS / "datumesh-mark.svg", "image/svg+xml"),
    "/favicon.ico": (ASSETS / "datumesh-mark.svg", "image/svg+xml"),
    "/datumesh.png": (ASSETS / "datumesh.png", "image/png"),
}


def token():
    if os.environ.get("CF_API_TOKEN"):
        return os.environ["CF_API_TOKEN"].strip()
    return pathlib.Path("/root/cf-key").read_text().strip()


def call(method, path, body=None, content_type="application/json"):
    data = body if isinstance(body, bytes) or body is None else json.dumps(body).encode()
    request = urllib.request.Request(API + path, data=data, method=method)
    request.add_header("Authorization", f"Bearer {token()}")
    if data is not None:
        request.add_header("Content-Type", content_type)
    try:
        with urllib.request.urlopen(request) as response:
            return json.load(response)["result"]
    except urllib.error.HTTPError as e:
        raise SystemExit(f"{method} {path}: {e.code} {e.read().decode()[:500]}")


def worker_source():
    files = {
        path: {"type": ctype, "b64": base64.b64encode(file.read_bytes()).decode()}
        for path, (file, ctype) in FILES.items()
    }
    return f"""const FILES = {json.dumps(files)};
const decoded = {{}};
function body(path) {{
  if (!decoded[path]) decoded[path] = Uint8Array.from(atob(FILES[path].b64), (c) => c.charCodeAt(0));
  return decoded[path];
}}
export default {{
  fetch(request) {{
    const url = new URL(request.url);
    if (url.protocol === "http:") {{
      url.protocol = "https:";
      return Response.redirect(url.toString(), 301);
    }}
    const path = url.pathname === "/index.html" ? "/" : url.pathname;
    if (!FILES[path]) return new Response("Not found", {{ status: 404, headers: {{ "content-type": "text/plain" }} }});
    return new Response(body(path), {{
      headers: {{
        "content-type": FILES[path].type,
        "cache-control": "public, max-age=300",
        "x-content-type-options": "nosniff",
        "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'",
      }},
    }});
  }},
}};
"""


def multipart(parts):
    boundary = uuid.uuid4().hex
    out = b""
    for name, filename, ctype, content in parts:
        out += f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"".encode()
        if filename:
            out += f"; filename=\"{filename}\"".encode()
        out += f"\r\nContent-Type: {ctype}\r\n\r\n".encode() + content + b"\r\n"
    return out + f"--{boundary}--\r\n".encode(), f"multipart/form-data; boundary={boundary}"


def main():
    zone = call("GET", f"/zones?name={ZONE_NAME}")[0]
    account = zone["account"]["id"]
    metadata = {"main_module": "worker.js", "compatibility_date": "2026-10-01"}
    body, ctype = multipart([
        ("metadata", None, "application/json", json.dumps(metadata).encode()),
        ("worker.js", "worker.js", "application/javascript+module", worker_source().encode()),
    ])
    call("PUT", f"/accounts/{account}/workers/scripts/{SCRIPT}", body, ctype)
    print(f"uploaded worker {SCRIPT}")
    existing = {r["pattern"]: r for r in call("GET", f"/zones/{zone['id']}/workers/routes")}
    for pattern in ROUTES:
        route = {"pattern": pattern, "script": SCRIPT}
        if pattern in existing:
            call("PUT", f"/zones/{zone['id']}/workers/routes/{existing[pattern]['id']}", route)
        else:
            call("POST", f"/zones/{zone['id']}/workers/routes", route)
        print(f"route {pattern} -> {SCRIPT}")


if __name__ == "__main__":
    main()
