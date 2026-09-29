#!/usr/bin/env python3
import base64, json, re, shutil, subprocess, tempfile, gzip
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HOST="127.0.0.1"; PORT=8765; VERSION="1.4"

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
      "timeline_python":True,"ready":True}

def dashboard():
    st=status()
    return """<!doctype html><meta charset="utf-8"><title>Falcon Local Engine</title>
<style>body{font-family:Arial;direction:rtl;background:#07111f;color:#eef;padding:40px;max-width:760px;margin:auto}.c{background:#102238;padding:22px;border-radius:16px;margin:14px 0}code{direction:ltr;display:inline-block}</style>
<h1>🦅 Falcon Local Engine v%s</h1><div class=c>🟢 Python جاهز<br>%s Sleuth Kit / fls: %s<br>🟢 Timeline: Falcon Python (لا يحتاج mactime.exe)<br>%s Steghide: %s</div>
<div class=c><b>الحالة:</b> %s</div>""" % (VERSION,"🟢" if st["sleuthkit"] else "🔴",st["fls_path"] or "غير موجود",
"🟢" if st["steghide"] else "🔴",st["steghide_path"] or "غير مثبت","جاهز لتحليل Timeline" if st["sleuthkit"] else "يحتاج fls.exe")

def body_macb(path):
    events=[]
    with path.open("r",encoding="utf-8",errors="ignore") as f:
        for line in f:
            parts=line.rstrip("\r\n").split("|")
            if len(parts)<11: continue
            name=parts[1]
            try: times=[int(parts[i] or 0) for i in (7,8,9,10)]
            except ValueError: continue
            if times[0] and len(set(times))==1:
                ts=times[0]
                events.append((ts,name,parts[2],parts[3],parts[6]))
    events.sort(key=lambda x:x[0])
    def render(e):
        ts,name,inode,mode,size=e
        try: stamp=datetime.fromtimestamp(ts).astimezone().isoformat(sep=" ",timespec="seconds")
        except Exception: stamp=str(ts)
        return f"{stamp} macb {size:>10} {inode:>10} {mode} {name}"
    return [render(e) for e in events]

def reply(h,code,obj):
    b=json.dumps(obj,ensure_ascii=False).encode()
    h.send_response(code); h.send_header("Content-Type","application/json; charset=utf-8")
    h.send_header("Access-Control-Allow-Origin","https://sc1561.github.io")
    h.send_header("Access-Control-Allow-Methods","GET,POST,OPTIONS")
    h.send_header("Access-Control-Allow-Headers","Content-Type, X-Filename")
    h.send_header("Content-Length",str(len(b))); h.end_headers(); h.wfile.write(b)

class H(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(204); self.send_header("Access-Control-Allow-Origin","https://sc1561.github.io")
        self.send_header("Access-Control-Allow-Methods","GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers","Content-Type, X-Filename"); self.end_headers()

    def do_GET(self):
        path=self.path.split("?",1)[0]
        if path=="/health": return reply(self,200,status())
        if path=="/":
            b=dashboard().encode("utf-8"); self.send_response(200)
            self.send_header("Content-Type","text/html; charset=utf-8"); self.send_header("Content-Length",str(len(b)))
            self.end_headers(); self.wfile.write(b); return
        return reply(self,404,{"ok":False})

    def do_POST(self):
        path=self.path.split("?",1)[0]
        if path=="/timeline/analyze":
            fls=find_tool("fls")
            if not fls: return reply(self,503,{"ok":False,"error":"fls.exe is not installed","need":["fls"]})
            n=int(self.headers.get("Content-Length","0")); name=Path(self.headers.get("X-Filename","timeline.img.gz")).name
            if n<=0 or n>180*1024*1024: return reply(self,413,{"ok":False,"error":"Compressed image too large"})
            work=Path(tempfile.mkdtemp(prefix="falcon_timeline_")); gz=work/name
            with gz.open("wb") as w:
                left=n
                while left:
                    chunk=self.rfile.read(min(left,1024*1024))
                    if not chunk: break
                    w.write(chunk); left-=len(chunk)
            img=work/re.sub(r"\.gz$","",name,flags=re.I)
            try:
                with gzip.open(gz,"rb") as r, img.open("wb") as w: shutil.copyfileobj(r,w,1024*1024)
                body=work/"bodyfile.txt"
                with body.open("w",encoding="utf-8",errors="ignore") as w:
                    q=subprocess.run([fls,"-r","-m","/",str(img)],stdout=w,stderr=subprocess.PIPE,text=True,timeout=240)
                if q.returncode!=0: return reply(self,422,{"ok":False,"error":"fls failed","message":q.stderr[-1500:]})
                macb=body_macb(body); recent=macb[-120:]\n                years=[int(x[:4]) for x in macb if len(x)>=5 and x[:4].isdigit() and x[4]=="-"]\n                normal_year=max(years) if years else datetime.now().year\n                old_anomalies=[x for x in macb if len(x)>=5 and x[:4].isdigit() and x[4]=="-" and int(x[:4]) < normal_year-5]
                keys=("flag","secret","anti","wipe","shred","tmp","home/","root/","bash","history")
                evidence=[x for x in recent if any(k in x.lower() for k in keys)]
                # Also inspect tiny, very recent regular files: anti-forensic actions often leave a nearby clue.
                tiny=[]
                for x in recent[-60:]:
                    m0=re.search(r"macb\s+(\d+)\s+([^\s]+)\s+(r/[^\s]+)\s+(.+)$",x)
                    if m0 and int(m0.group(1))<=4096: tiny.append(x)
                inspect=list(dict.fromkeys(evidence[-40:]+tiny+old_anomalies[:80]))
                extracted=[]
                icat=find_tool("icat")
                if icat:
                    for line in inspect:
                        # Bodyfile inode can include a sequence suffix (e.g. 4943-128-1); icat accepts the inode token.
                        m=re.search(r"macb\s+\d+\s+([^\s]+)\s+\S+\s+(.+)$",line)
                        if not m: continue
                        inode,name2=m.group(1),m.group(2)
                        if not re.search(r"\s+d/d",line) and not name2.endswith("/"):
                            pass
                        try:
                            q2=subprocess.run([icat,str(img),inode],capture_output=True,timeout=20)
                            raw=q2.stdout[:1024*1024]
                            txt=raw.decode("utf-8","ignore")
                            decoded=[]
                            for tok in re.findall(r"[A-Za-z0-9+/]{12,}={0,2}",txt):
                                try:
                                    z=base64.b64decode(tok,validate=True).decode("utf-8","ignore").strip()
                                    if z and sum(ch.isprintable() for ch in z)/max(1,len(z))>.9: decoded.append(z)
                                except Exception: pass
                            flags=re.findall(r"[A-Za-z][A-Za-z0-9_.:-]{1,30}\\{[^{}\\r\\n]{2,200}\\}",txt)
                            candidates=list(flags)
                            for z in decoded:
                                if re.fullmatch(r"[A-Za-z0-9_@!$%^&*+.=:-]{6,160}",z):
                                    candidates.append("academy{"+z+"}")
                            extracted.append({"path":name2,"inode":inode,"returncode":q2.returncode,
                              "text":txt[-4000:],"decoded":decoded[:20],"flags":flags[:20],"candidates":candidates[:20],"error":q2.stderr.decode("utf-8","ignore")[-500:]})
                        except Exception as ex:
                            extracted.append({"path":name2,"inode":inode,"text":"","flags":[],"error":str(ex)[:500]})
                return reply(self,200,{"ok":True,"engine":"fls + Falcon Python Timeline + icat","macb_count":len(macb),
                  "recent":recent,"evidence":evidence[-40:],"old_anomalies":old_anomalies[:80],"icat_path":icat,"extracted":extracted})
            except subprocess.TimeoutExpired: return reply(self,504,{"ok":False,"error":"Timeline analysis timed out"})
            except Exception as e: return reply(self,500,{"ok":False,"error":"Timeline analysis failed","message":str(e)[:500]})

        if path!="/steghide/extract": return reply(self,404,{"ok":False})
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
