# Aegis360 Burp Proxy History Exporter — Jython 2.7 Extension
#
# Exposes Burp's internal getProxyHistory() over HTTP on port 9997.
# Load via: Burp > Extensions > Add > Type: Python > Select this file
# Requires Jython JAR configured in Burp: Extensions > Settings > Python environment
#   JAR path: /usr/share/ghidra/Ghidra/Features/Jython/lib/jython-standalone-2.7.4.jar
#
# Endpoints once loaded:
#   GET http://127.0.0.1:9997/history              — all items (last 1000)
#   GET http://127.0.0.1:9997/history?host=target  — filter by hostname substring
#   GET http://127.0.0.1:9997/history?limit=200    — limit count
#   GET http://127.0.0.1:9997/history?host=x&limit=50
#   GET http://127.0.0.1:9997/status               — health check

from burp import IBurpExtender
from java.io import PrintWriter
import socket
import threading
import json
import base64
import sys

LISTEN_PORT = 9997


def _java_bytes_to_b64(java_bytes):
    """Convert Burp's Java byte[] to base64 string (Jython 2.7 safe)."""
    if not java_bytes:
        return ""
    raw = "".join(chr(b & 0xFF) for b in java_bytes)
    return base64.b64encode(raw)


def _java_bytes_to_str(java_bytes):
    """Convert Java byte[] to UTF-8 string, replacing bad bytes."""
    if not java_bytes:
        return ""
    raw = bytearray(b & 0xFF for b in java_bytes)
    return raw.decode("utf-8", errors="replace")


def _parse_query(path):
    """Return (clean_path, dict_of_params) from a URL path."""
    params = {}
    if "?" in path:
        path, qs = path.split("?", 1)
        for pair in qs.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                params[k.strip()] = v.strip()
    return path, params


class BurpExtender(IBurpExtender):

    def registerExtenderCallbacks(self, callbacks):
        self._cb = callbacks
        self._helpers = callbacks.getHelpers()
        self._out = PrintWriter(callbacks.getStdout(), True)
        self._err = PrintWriter(callbacks.getStderr(), True)

        callbacks.setExtensionName("Aegis360 Proxy History API")

        self._out.println("[Aegis360] Extension loaded — starting HTTP server on :%d" % LISTEN_PORT)

        t = threading.Thread(target=self._serve)
        t.daemon = True
        t.start()

        self._out.println("[Aegis360] Ready: http://127.0.0.1:%d/history" % LISTEN_PORT)

    # ------------------------------------------------------------------
    # Internal HTTP server
    # ------------------------------------------------------------------

    def _serve(self):
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", LISTEN_PORT))
            srv.listen(20)
        except Exception as e:
            self._err.println("[Aegis360] Cannot bind port %d: %s" % (LISTEN_PORT, str(e)))
            return

        while True:
            try:
                conn, _ = srv.accept()
                t = threading.Thread(target=self._handle, args=(conn,))
                t.daemon = True
                t.start()
            except Exception:
                pass

    def _handle(self, conn):
        try:
            raw = conn.recv(8192).decode("utf-8", errors="replace")
            if not raw:
                return

            request_line = raw.split("\r\n")[0] if "\r\n" in raw else raw.split("\n")[0]
            parts = request_line.split(" ")
            method = parts[0] if parts else "GET"
            path = parts[1] if len(parts) > 1 else "/"

            path, params = _parse_query(path)

            if path == "/status":
                body = json.dumps({"status": "ok", "port": LISTEN_PORT,
                                   "history_count": len(self._cb.getProxyHistory())})
                self._send(conn, 200, body)

            elif path == "/history":
                host_filter = params.get("host", None)
                limit = int(params.get("limit", 1000))
                body = self._build_history_json(host_filter, limit)
                self._send(conn, 200, body)

            else:
                self._send(conn, 404, '{"error":"not found"}')

        except Exception as e:
            self._err.println("[Aegis360] Handler error: " + str(e))
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _send(self, conn, status, body):
        status_text = {200: "OK", 404: "Not Found", 500: "Internal Server Error"}.get(status, "OK")
        header = (
            "HTTP/1.1 %d %s\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: %d\r\n"
            "Connection: close\r\n"
            "\r\n" % (status, status_text, len(body))
        )
        conn.sendall((header + body).encode("utf-8"))

    # ------------------------------------------------------------------
    # History extraction
    # ------------------------------------------------------------------

    def _build_history_json(self, host_filter, limit):
        try:
            history = self._cb.getProxyHistory()
            items = []

            for item in history:
                try:
                    req_bytes = item.getRequest()
                    resp_bytes = item.getResponse()

                    if not req_bytes:
                        continue

                    req_info = self._helpers.analyzeRequest(item)
                    host = str(item.getHost()) if item.getHost() else ""

                    if host_filter and host_filter.lower() not in host.lower():
                        continue

                    url = str(req_info.getUrl())
                    method = str(req_info.getMethod())
                    port = item.getPort()
                    protocol = str(item.getProtocol()) if item.getProtocol() else "http"

                    # Parse request headers
                    req_headers = {}
                    for h in req_info.getHeaders():
                        h = str(h)
                        if ":" in h:
                            k, v = h.split(":", 1)
                            req_headers[k.strip()] = v.strip()

                    # Response analysis
                    status_code = 0
                    resp_headers = {}
                    resp_mime = ""
                    if resp_bytes:
                        resp_info = self._helpers.analyzeResponse(resp_bytes)
                        status_code = resp_info.getStatusCode()
                        resp_mime = str(resp_info.getStatedMimeType()) if resp_info.getStatedMimeType() else ""
                        for h in resp_info.getHeaders():
                            h = str(h)
                            if ":" in h:
                                k, v = h.split(":", 1)
                                resp_headers[k.strip()] = v.strip()

                    # Encode raw bytes as base64
                    req_b64 = _java_bytes_to_b64(req_bytes)
                    resp_b64 = _java_bytes_to_b64(resp_bytes) if resp_bytes else ""

                    items.append({
                        "url": url,
                        "host": host,
                        "port": port,
                        "protocol": protocol,
                        "method": method,
                        "status": status_code,
                        "mime_type": resp_mime,
                        "req_headers": req_headers,
                        "resp_headers": resp_headers,
                        "request_b64": req_b64,
                        "response_b64": resp_b64,
                        "highlight": str(item.getHighlight()) if item.getHighlight() else "",
                        "comment": str(item.getComment()) if item.getComment() else "",
                    })

                except Exception as ie:
                    self._err.println("[Aegis360] Item error: " + str(ie))
                    continue

            # Return last N items
            items = items[-limit:] if len(items) > limit else items

            return json.dumps({
                "success": True,
                "total_in_history": len(history),
                "returned": len(items),
                "items": items,
            })

        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})
