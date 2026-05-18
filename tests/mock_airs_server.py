#!/usr/bin/env python3
"""
Mock Prisma AIRS API server for hook integration tests.

Routes:
  POST /allow          -> {"action":"allow",...}
  POST /block          -> {"action":"block","category":"prompt_injection",...}
  POST /block-response -> {"action":"block","category":"dlp",...}  (response-type detections)
  POST /error          -> HTTP 500
  POST /slow           -> 200 after 10s delay (triggers timeout in hooks)
  POST <anything else> -> {"action":"allow",...}  (default)

Usage:
  python3 mock_airs_server.py <port>
"""

import json
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

ALLOW = {
    "action": "allow",
    "scan_id": "mock-scan-allow-001",
    "category": "none",
    "prompt_detected": {},
    "response_detected": {},
}

BLOCK_PROMPT = {
    "action": "block",
    "scan_id": "mock-scan-block-001",
    "category": "prompt_injection",
    "prompt_detected": {"injection": True, "jailbreak": False},
    "response_detected": {},
}

BLOCK_RESPONSE = {
    "action": "block",
    "scan_id": "mock-scan-block-002",
    "category": "dlp",
    "prompt_detected": {},
    "response_detected": {"dlp": True, "malicious_code": False},
}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)

        path = self.path.split("?")[0].rstrip("/")

        if path.endswith("/error"):
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"Internal Server Error")
            return

        if path.endswith("/slow"):
            time.sleep(10)
            body = ALLOW
        elif path.endswith("/block-response"):
            body = BLOCK_RESPONSE
        elif path.endswith("/block"):
            body = BLOCK_PROMPT
        else:
            body = ALLOW

        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass  # suppress access logs during tests


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
    server = HTTPServer(("127.0.0.1", port), Handler)
    print(f"Mock AIRS server listening on 127.0.0.1:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
