#!/usr/bin/env python3
import base64, json, os, re, shutil, subprocess, tempfile, gzip
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
HOST="127.0.0.1"; PORT=8765
VERSION="0.5"
def find_steghide():
 candidates=[
  shutil.which("steghide"),
  r"C:\\Falcon\\steghide\\steghide.exe",
  str(Path(__file__).resolve().parent/"tools"/"steghide"/"steghide.exe"),
  str(Path(__file__).resolve().parent/"steghide.exe")
 ]
 for c in candidates:
  if c and Path(c).is_file(): return str(Path(c))
 return None
def find_tool(name):\n candidates=[shutil.which(name), shutil.which(name+".exe"), str(Path(r"C:\\Program Files\\sleuthkit\\bin")/(name+".exe")), str(Path(__file__).resolve().parent/"tools"/"sleuthkit"/(name+".exe"))]\n for c in candidates:\n  if c and Path(c).is_file(): return str(Path(c))\n return None\ndef status():
 return {"ok":True,"engine":"Falcon Local Engine","version":VERSION,
 "python":True,"steghide":bool(find_steghide()),"steghide_path":find_steghide(),
 "ready":bool(find_steghide())}
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
  path=self.path.split("?",1)[0]\n  if path=="/timeline/analyze":\n   fls=find_tool("fls"); mt=find_tool("mactime")\n   if not fls or not mt: return reply(self,503,{"ok":False,"error":"Sleuth Kit is not installed","need":["fls","mactime"]})\n   n=int(self.headers.get("Content-Length","0")); name=Path(self.headers.get("X-Filename","timeline.img.gz")).name\n   if n<=0 or n>180*1024*1024: return reply(self,413,{"ok":False,"error":"Compressed image too large"})\n   work=Path(tempfile.mkdtemp(prefix="falcon_timeline_")); gz=work/name\n   with gz.open("wb") as w:\n    left=n\n    while left:\n     chunk=self.rfile.read(min(left,1024*1024))\n     if not chunk: break\n     w.write(chunk); left-=len(chunk)\n   img=work/re.sub(r"\\.gz$","",name,flags=re.I)\n   try:\n    with gzip.open(gz,"rb") as r, img.open("wb") as w: shutil.copyfileobj(r,w,1024*1024)\n    body=work/"bodyfile.txt"\n    with body.open("w",encoding="utf-8",errors="ignore") as w:\n     q=subprocess.run([fls,"-r","-m","/",str(img)],stdout=w,stderr=subprocess.PIPE,text=True,timeout=180)\n    if q.returncode!=0: return reply(self,422,{"ok":False,"error":"fls failed","message":q.stderr[-1500:]})\n    q=subprocess.run([mt,"-b",str(body)],capture_output=True,text=True,errors="ignore",timeout=180)\n    lines=q.stdout.splitlines(); macb=[x for x in lines if "macb" in x.lower()]\n    recent=macb[-80:]; evidence=[]\n    for x in recent:\n     low=x.lower()\n     if any(k in low for k in ["flag","secret","anti","wipe","shred","tmp","home/","root/"]): evidence.append(x)\n    return reply(self,200,{"ok":True,"macb_count":len(macb),"recent":recent,"evidence":evidence[-30:]})\n   except subprocess.TimeoutExpired: return reply(self,504,{"ok":False,"error":"Timeline analysis timed out"})\n   except Exception as e: return reply(self,500,{"ok":False,"error":"Timeline analysis failed","message":str(e)[:500]})\n  if path!="/steghide/extract": return reply(self,404,{"ok":False})
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
  exe=find_steghide()
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
 exe=find_steghide(); print(("🟢" if exe else "🔴")+" Steghide: "+("ready — "+exe if exe else "not installed"))
 print("Localhost only. Press Ctrl+C to stop.")
 ThreadingHTTPServer((HOST,PORT),H).serve_forever()
