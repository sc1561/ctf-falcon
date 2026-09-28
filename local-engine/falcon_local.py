#!/usr/bin/env python3
import json, os, shutil, subprocess, tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
HOST="127.0.0.1"; PORT=8765
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
  if self.path=="/health": return reply(self,200,{"ok":True,"engine":"Falcon Local Engine","version":"0.1","steghide":bool(shutil.which("steghide"))})
  return reply(self,404,{"ok":False})
 def do_POST(self):
  if self.path!="/steghide/extract": return reply(self,404,{"ok":False})
  n=int(self.headers.get("Content-Length","0")); raw=self.rfile.read(n)
  try: data=json.loads(raw); src=Path(data["path"]).expanduser().resolve(); password=str(data["password"])
  except Exception: return reply(self,400,{"ok":False,"error":"Invalid request"})
  if not src.is_file(): return reply(self,400,{"ok":False,"error":"File not found"})
  exe=shutil.which("steghide")
  if not exe: return reply(self,503,{"ok":False,"error":"steghide is not installed"})
  out=Path(tempfile.mkdtemp(prefix="falcon_"))
  p=subprocess.run([exe,"extract","-sf",str(src),"-p",password,"-xf",str(out/"payload")],capture_output=True,text=True,timeout=30)
  target=out/"payload"
  return reply(self,200 if p.returncode==0 else 422,{"ok":p.returncode==0,"output":str(target) if target.exists() else None,"message":(p.stdout+p.stderr)[-1500:]})
 def log_message(self,*a): pass
if __name__=="__main__":
 print(f"Falcon Local Engine: http://{HOST}:{PORT}")
 print("Localhost only. Press Ctrl+C to stop.")
 ThreadingHTTPServer((HOST,PORT),H).serve_forever()
