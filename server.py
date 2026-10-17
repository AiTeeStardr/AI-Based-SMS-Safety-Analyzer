"""
server.py — Python backend ของ SMS Guard AI (ใช้เฉพาะ standard library + scikit-learn/joblib)

หน้าที่
  1) เสิร์ฟหน้าเว็บ (HTML/CSS/JS) ที่อยู่ในโฟลเดอร์นี้
  2) REST API:
       GET  /api/health    สถานะเซิร์ฟเวอร์และโมเดล
       GET  /api/metrics   ผลทดสอบโมเดล (model/metrics.json)
       POST /api/analyze   body {"text": "..."} -> ผลทำนายจากโมเดล ML + n-gram ที่ส่งผลมากที่สุด

รัน:
  pip install -r requirements.txt
  python train_model.py      # ครั้งแรก (สร้าง model/scam_model.joblib)
  python server.py           # เปิด http://127.0.0.1:8000
"""
import argparse
import json
import os
import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ROOT, "api"))
import _ml  # โค้ดโมเดลที่ใช้ร่วมกับ api/analyze.py (Vercel)

MODEL = _ml.MODEL
METRICS_PATH = os.path.join(ROOT, "model", "metrics.json")
MAX_BODY = 16 * 1024
SERVE_EXT = {".html", ".css", ".js", ".json", ".csv", ".png", ".svg", ".ico", ".md"}

if MODEL is None:
    print(f"[warn] โหลดโมเดลไม่ได้ ({_ml.LOAD_ERROR}) — รัน python train_model.py ก่อน", file=sys.stderr)


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=ROOT, **kw)

    # ---- helpers ----
    def _json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    # ---- static: เฉพาะนามสกุลที่อนุญาต ไม่เสิร์ฟ .py / .joblib / .git ----
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/health":
            return self._json(200, {"ok": True, "model_loaded": MODEL is not None})
        if path == "/api/metrics":
            try:
                with open(METRICS_PATH, encoding="utf-8") as f:
                    return self._json(200, json.load(f))
            except OSError:
                return self._json(404, {"error": "ยังไม่มี model/metrics.json รัน python train_model.py ก่อน"})
        if path.startswith("/api/"):
            return self._json(404, {"error": "ไม่พบ endpoint"})
        ext = os.path.splitext(path)[1].lower()
        if path.endswith("/") or ext == "" :
            return super().do_GET() if path in ("/", "") else self._json(404, {"error": "not found"})
        if ext not in SERVE_EXT or "/." in path:
            return self._json(404, {"error": "not found"})
        return super().do_GET()

    def do_POST(self):
        path = urlparse(self.path).path
        if path != "/api/analyze":
            return self._json(404, {"error": "ไม่พบ endpoint"})
        if MODEL is None:
            return self._json(503, {"error": "ยังไม่มีโมเดล รัน python train_model.py ก่อน"})
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            n = 0
        if n <= 0 or n > MAX_BODY:
            return self._json(400, {"error": "ขนาดคำขอไม่ถูกต้อง"})
        try:
            data = json.loads(self.rfile.read(n).decode("utf-8"))
            text = str(data.get("text", "")).strip()
        except (ValueError, AttributeError):
            return self._json(400, {"error": "ต้องส่ง JSON รูปแบบ {\"text\": \"...\"}"})
        if not text:
            return self._json(400, {"error": "ข้อความว่าง"})
        return self._json(200, _ml.predict(text))

    def log_message(self, fmt, *args):
        sys.stderr.write("[%s] %s\n" % (self.log_date_time_string(), fmt % args))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    a = ap.parse_args()
    srv = ThreadingHTTPServer((a.host, a.port), Handler)
    print(f"SMS Guard AI backend: http://{a.host}:{a.port}  (โมเดล: {'พร้อม' if MODEL else 'ยังไม่ได้ train'})")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nปิดเซิร์ฟเวอร์")


if __name__ == "__main__":
    main()
