"""Vercel serverless function: POST /api/analyze  body {"text": "..."} -> ผลทำนายจากโมเดล ML (Python)"""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _ml  # noqa: E402

MAX_BODY = 16 * 1024


class handler(BaseHTTPRequestHandler):
    def _json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._json(200, {"ok": True, "model_loaded": _ml.MODEL is not None, "error": _ml.LOAD_ERROR})

    def do_POST(self):
        if _ml.MODEL is None:
            return self._json(503, {"error": "โหลดโมเดลไม่ได้", "detail": _ml.LOAD_ERROR})
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            n = 0
        if n <= 0 or n > MAX_BODY:
            return self._json(400, {"error": "ขนาดคำขอไม่ถูกต้อง"})
        try:
            text = str(json.loads(self.rfile.read(n).decode("utf-8")).get("text", "")).strip()
        except (ValueError, AttributeError):
            return self._json(400, {"error": "ต้องส่ง JSON รูปแบบ {\"text\": \"...\"}"})
        if not text:
            return self._json(400, {"error": "ข้อความว่าง"})
        return self._json(200, _ml.predict(text))
