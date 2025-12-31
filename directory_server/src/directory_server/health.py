"""
Health check and monitoring HTTP server.

Provides endpoints for health checks and status monitoring.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from typing import TYPE_CHECKING, Any

from loguru import logger

if TYPE_CHECKING:
    from directory_server.server import DirectoryServer


class HealthCheckHandler(BaseHTTPRequestHandler):
    server_instance: DirectoryServer | None = None

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._handle_health()
        elif self.path == "/status":
            self._handle_status()
        else:
            self.send_error(404)

    def _handle_health(self) -> None:
        if not self.server_instance:
            self.send_error(503)
            return

        try:
            is_healthy = self.server_instance.is_healthy()
            status_code = 200 if is_healthy else 503

            self.send_response(status_code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()

            response = {"status": "healthy" if is_healthy else "unhealthy"}
            self.wfile.write(json.dumps(response).encode())
        except Exception as e:
            logger.error(f"Health check error: {e}")
            self.send_error(500)

    def _handle_status(self) -> None:
        if not self.server_instance:
            self.send_error(503)
            return

        try:
            stats = self.server_instance.get_detailed_stats()

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()

            self.wfile.write(json.dumps(stats, default=str).encode())
        except Exception as e:
            logger.error(f"Status check error: {e}")
            self.send_error(500)


class HealthCheckServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 8080):
        self.host = host
        self.port = port
        self.httpd: HTTPServer | None = None
        self.thread: Thread | None = None

    def start(self, server_instance: DirectoryServer) -> None:
        HealthCheckHandler.server_instance = server_instance

        self.httpd = HTTPServer((self.host, self.port), HealthCheckHandler)
        self.thread = Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

        logger.info(f"Health check server started on {self.host}:{self.port}")

    def stop(self) -> None:
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()  # Explicitly close the socket
            logger.info("Health check server stopped")
