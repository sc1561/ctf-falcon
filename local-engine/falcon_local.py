#!/usr/bin/env python3
import base64, json, os, re, shutil, subprocess, tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
HOST="127.0.0.1"; PORT=8765
VERSION="0.3"
def status():
 return {"ok":True,"engine":"Falcon Local Engine","version":VERSION,
 "python":True,"steghide":bool(shutil.which("steghide")),
 "ready":bool(shutil.which("steghide"))}
def dashboard():
 st=status(); sh="جاهز" if st["steghide"] else "غير مثبت"
 ready="جاهز للتحليل" if st["ready"] else "يحتاج تثبيت Steghide"
 return """<!doctype html><meta charset="utf-8"><title>Falcon Local Engine</title>
 <style>body{font-family:Arial;direction:rtl;background:#07111f;color:#eef;padding:40px;max-width:760px;margin:auto}.c{background:#102238;padding:22px;border-radius:16px;margin:14px 0}code{direction:ltr;display:inline-block}</style>
 <h1>🦅 Falcon Local Engine</h1><div class=c><b>حالة المحرك:</b> %s</div>
 <div class=c>🟢 Python جاهز<br>%s Steghide: %s</div>
 <div class=c><b>الخطوة التالية</b><p>%s</p><code>http://127.0.0.1:8765/health</code></div>""" % (
 ready, "🟢" if st["steghide"] else "🔴", sh,
 "يمكنك الآن استخدام أدوات الاستخراج المحلية." if st["ready"] else "ثبّت Steghide ثم أغلق المحرك وأعد تشغيله.")
def reply(h,code,obj):
 b=json.dumps(obj,ensure_ascii=False).encode()
 h.send_response(code); h.send_header("Content-Type","application/json; charset=utf-8")
 h.send_header("Access-Control-Allow-Origin","https://sc1561.github.io")
 h.send_header("Access-Control-Allow-Methods","GET,POST,OPTIONS")
 h.send_header("Access-Control-Allow-Headers","Content-Type")
 h.send_header("Content-Length",str(len(b))); h.end_headers(); h.wfile.write(b)
class H(BaseHTTPRequestHandler):
 def do_OPTIONS(self):
  self.send_response(204); self.send_header("Access-Control-Allow-Origin","https://sc1561.github.io")
  self.send_header("Access-Control-Allow-Methods","GET,POST,OPTIONS"); self.send_header("Access-Control-Allow-Headers","Content-Type"); self.end_headers()
 def do_GET(self):
  path=self.path.split("?",1)[0]
  if path=="/health": return reply(self,200,status())
  if path=="/":
   b=dashboard().encode("utf-8"); self.send_response(200); self.send_header("Content-Type","text/html; charset=utf-8"); self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b); return
  return reply(self,404,{"ok":False})
 def do_POST(self):
  if self.path.split("?",1)[0]!="/steghide/extract": return reply(self,404,{"ok":False})
  n=int(self.headers.get("Content-Length","0")); raw=self.rfile.read(n)
  try:
   data=json.loads(raw); password=str(data["password"])
   if data.get("file_b64"):
    blob=base64.b64decode(data["file_b64"],validate=True)
    if len(blob)>25*1024*1024: return reply(self,413,{"ok":False,"error":"File too large"})
    work=Path(tempfile.mkdtemp(prefix="falcon_")); src=work/Path(data.get("name","upload.jpg")).name; src.write_bytes(blob)
   else: src=Path(data["path"]).expanduser().resolve()
  except Exception: return reply(self,400,{"ok":False,"error":"Invalid request"})
  if not src.is_file(): return reply(self,400,{"ok":False,"error":"File not found"})
  exe=shutil.which("steghide")
  if not exe: return reply(self,503,{"ok":False,"error":"steghide is not installed"})
  out=Path(tempfile.mkdtemp(prefix="falcon_"))
  p=subprocess.run([exe,"extract","-sf",str(src),"-p",password,"-xf",str(out/"payload")],capture_output=True,text=True,timeout=30)
  target=out/"payload"
  flag=None
  if target.exists() and target.stat().st_size<=5*1024*1024:
   try:
    txt=target.read_bytes().decode("utf-8","ignore")
    m=re.search(r"[A-Za-z][A-Za-z0-9_.:-]{1,30}\{[^{}\r\n]{2,200}\}",txt)
    if m: flag=m.group(0)
   except Exception: pass
  payload_b64=base64.b64encode(target.read_bytes()).decode() if target.exists() and target.stat().st_size<=10*1024*1024 else None
  return reply(self,200 if p.returncode==0 else 422,{"ok":p.returncode==0,"output_name":target.name if target.exists() else None,"payload_b64":payload_b64,"flag":flag,"message":(p.stdout+p.stderr)[-1500:]})
 def log_message(self,*a): pass
if __name__=="__main__":
 print("🦅 Falcon Local Engine v"+VERSION)
 print(f"🌐 http://{HOST}:{PORT}")
 print("🟢 Python: ready")
 print(("🟢" if shutil.which("steghide") else "🔴")+" Steghide: "+("ready" if shutil.which("steghide") else "not installed"))
 print("Localhost only. Press Ctrl+C to stop.")
 ThreadingHTTPServer((HOST,PORT),H).serve_forever()
