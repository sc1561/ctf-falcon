Warning: truncated output (original token count: 9814)
Total output lines: 567

#!/usr/bin/env python3
import base64, json, re, shutil, subprocess, tempfile, gzip
from datetime import datetime
import urllib.request, urllib.parse, http.cookiejar
from http.cookies import SimpleCookie
from email.utils import parsedate_to_datetime
import time
import threading, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HOST="127.0.0.1"; PORT=8765; VERSION="2.34.1"
FALCON_HOME=Path(r"C:\\Falcon")
TEMP_ROOT=FALCON_HOME/"temp"
TEMP_ROOT.mkdir(parents=True,exist_ok=True)
ANALYSIS_ROOT=FALCON_HOME/"analysis"
ANALYSIS_ROOT.mkdir(parents=True,exist_ok=True)
ENGINE_DIR=Path(__file__).resolve().parent
WEB_ROOT=ENGINE_DIR.parent if ENGINE_DIR.name.lower()=="local-engine" else ENGINE_DIR
_CREDENTIAL_JOBS={}
_CREDENTIAL_JOBS_LOCK=threading.Lock()
_FOOL_LOCKOUT_JOBS={}
_FOOL_LOCKOUT_JOBS_LOCK=threading.Lock()

def find_steghide():
    candidates=[shutil.which("steghide"),r"C:\\Falcon\steghide\steghide.exe",
      str(Path(__file__).resolve().parent/"tools"/"steghide"/"steghide.exe"),
      str(Path(__file__).resolve().parent/"steghide.exe")]
    return next((str(Path(c)) for c in candidates if c and Path(c).is_file()),None)

def find_tool(name):
    candidates=[shutil.which(name),shutil.which(name+".exe"),
      str(Path(r"C:\\Falcon\sleuthkit\\bin")/(name+".exe")),
      str(Path(r"C:\\Falcon\sleuthkit")/(name+".exe")),
      str(Path(r"C:\\Program Files\sleuthkit\\bin")/(name+".exe")),
      str(Path(r"C:\\Program Files\Sleuth Kit\\bin")/(name+".exe")),
      str(Path(__file__).resolve().parent/"tools"/"sleuthkit"/"bin"/(name+".exe"))]
    return next((str(Path(c)) for c in candidates if c and Path(c).is_file()),None)

def status():
    fls=find_tool("fls"); icat=find_tool("icat")
    return {"ok":True,"engine":"Falcon Local Engine","version":VERSION,"python":True,
      "steghide":bool(find_steghide()),"steghide_path":find_steghide(),
      "sleuthkit":bool(fls),"fls_path":fls,"icat":bool(icat),"icat_path":icat,
      "…8814 tokens truncated…large"})
                work=Path(tempfile.mkdtemp(prefix="falcon_")); src=work/Path(data.get("name","upload.jpg")).name; src.write_bytes(blob)
            else: src=Path(data["path"]).expanduser().resolve()
        except Exception: return reply(self,400,{"ok":False,"error":"Invalid request"})
        if not src.is_file(): return reply(self,400,{"ok":False,"error":"File not found"})
        exe=find_steghide()
        if not exe: return reply(self,503,{"ok":False,"error":"steghide is not installed"})
        out=Path(tempfile.mkdtemp(prefix="falcon_")); target=out/"payload"
        p=subprocess.run([exe,"extract","-sf",str(src),"-p",password,"-xf",str(target)],capture_output=True,text=True,timeout=30)
        flag=None
        if target.exists() and target.stat().st_size<=5*1024*1024:
            txt=target.read_bytes().decode("utf-8","ignore")
            m=re.search(r"[A-Za-z][A-Za-z0-9_.:-]{1,30}\{[^{}\r\n]{2,200}\}",txt)
            if m: flag=m.group(0)
        payload_b64=base64.b64encode(target.read_bytes()).decode() if target.exists() and target.stat().st_size<=10*1024*1024 else None
        return reply(self,200 if p.returncode==0 else 422,{"ok":p.returncode==0,"output_name":target.name if target.exists() else None,
          "payload_b64":payload_b64,"flag":flag,"message":(p.stdout+p.stderr)[-1500:]})

    def log_message(self,*a): pass

if __name__=="__main__":
    print("🦅 Falcon Local Engine v"+VERSION); print(f"🌐 http://{HOST}:{PORT}"); print("🟢 Python: ready")
    fls=find_tool("fls"); print(("🟢" if fls else "🔴")+" Sleuth Kit / fls: "+(fls or "not found"))
    icat=find_tool("icat"); print(("🟢" if icat else "🔴")+" Sleuth Kit / icat: "+(icat or "not found"))
    print("🟢 Timeline: Falcon Python — mactime.exe not required")
    exe=find_steghide(); print(("🟢" if exe else "🔴")+" Steghide: "+(exe or "not installed"))
    print("Localhost only. Press Ctrl+C to stop.")
    ThreadingHTTPServer((HOST,PORT),H).serve_forever()
