"""Bounded HTTP test service; logs actual request metadata, never reads real secrets."""
import argparse
import json
import os
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

DESTINATIONS = {"a": "http://server_a:8080/ping", "b": "http://server_b:8080/ping"}


def serve(role: str, port: int, events: str | None = None, destinations=None, bind="0.0.0.0"):
    destinations = destinations or DESTINATIONS
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):  # avoid mixing request logs with experiment data
            return
        def do_POST(self):
            t0 = time.time()
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not (0 <= length <= 4096):
                    self.send_error(413, "Payload exceeds lab limit")
                    return
                body = self.rfile.read(length)
                if role == "gateway":
                    if self.path not in ("/a", "/b"):
                        self.send_error(404)
                        return
                    name = self.path[1:]
                    target = destinations[name]
                    with urllib.request.urlopen(urllib.request.Request(target, data=body, method="POST"), timeout=3) as response:
                        content = response.read(4096)
                        status = response.status
                else:
                    name = role
                    content = b'{"ok":true}'
                    status = 200
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                if role == "gateway" and events:
                    # Instrumentation-level observations, NOT independently captured Zeek connections.
                    record = {"ts": t0, "ts_end": time.time(), "episode_id": self.headers.get("X-Lab-Episode"),
                              "src_host": self.client_address[0], "dst_host": name, "proto": "tcp", "service": "http",
                              "orig_bytes": len(body), "resp_bytes": len(content), "status": status,
                              "duration": time.time() - t0, "sensor": "application_gateway"}
                    p = Path(events)
                    p.parent.mkdir(parents=True, exist_ok=True)
                    with p.open("a", encoding="utf-8") as fp:
                        fp.write(json.dumps(record, sort_keys=True) + "\n")
                        fp.flush()
            except (urllib.error.URLError, TimeoutError, ValueError) as exc:
                self.send_error(502, "Lab backend unavailable")
    server = ThreadingHTTPServer((bind, port), Handler)
    try:
        server.serve_forever()
    finally:
        server.server_close()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--role", choices=["gateway", "service"], required=True)
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--events")
    a = p.parse_args()
    serve(a.role, a.port, a.events)

if __name__ == "__main__":
    main()
