#!/usr/bin/env python3
import base64, json, re, shutil, subprocess, tempfile, gzip
from datetime import datetime
import urllib.request, urllib.parse, http.cookiejar
from http.cookies import SimpleCookie
from email.utils import parsedate_to_datetime
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HOST="127.0.0.1"; PORT=8765; VERSION="2.21.0"
FALCON_HOME=Path(r"C:\\Falcon")
TEMP_ROOT=FALCON_HOME/"temp"
TEMP_ROOT.mkdir(parents=True,exist_ok=True)
ANALYSIS_ROOT=FALCON_HOME/"analysis"
ANALYSIS_ROOT.mkdir(parents=True,exist_ok=True)
ENGINE_DIR=Path(__file__).resolve().parent
WEB_ROOT=ENGINE_DIR.parent if ENGINE_DIR.name.lower()=="local-engine" else ENGINE_DIR

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
      "timeline_python":True,"no_fa_analysis":True,"ready":True}

def dashboard():
    st=status()
    return """<!doctype html><meta charset="utf-8"><title>Falcon Local Engine</title>
<style>body{font-family:Arial;direction:rtl;background:#07111f;color:#eef;padding:40px;max-width:760px;margin:auto}.c{background:#102238;padding:22px;border-radius:16px;margin:14px 0}code{direction:ltr;display:inline-block}</style>
<h1>🦅 Falcon Local Engine v%s</h1><div class=c>🟢 Python جاهز<br>%s Sleuth Kit / fls: %s<br>🟢 Timeline: Falcon Python (لا يحتاج mactime.exe)<br>%s Steghide: %s</div>
<div class=c><b>الحالة:</b> %s</div>""" % (VERSION,"🟢" if st["sleuthkit"] else "🔴",st["fls_path"] or "غير موجود",
"🟢" if st["steghide"] else "🔴",st["steghide_path"] or "غير مثبت","جاهز لتحليل Timeline" if st["sleuthkit"] else "يحتاج fls.exe")

def partition_offsets(img):
    """Return candidate filesystem start sectors without requiring mmls."""
    out=[0]
    mmls=find_tool("mmls")
    if mmls:
        try:
            q=subprocess.run([mmls,str(img)],capture_output=True,text=True,timeout=30)
            for line in q.stdout.splitlines():
                m=re.match(r"\s*\d+:\s+\d+:\s+(\d+)\s+\d+\s+\d+\s+(.+)",line)
                if m and not any(x in m.group(2).lower() for x in ("unallocated","table","metadata")):
                    off=int(m.group(1))
                    if off not in out: out.append(off)
        except Exception: pass
    try:
        with img.open("rb") as fh:
            mbr=fh.read(512)
        if len(mbr)==512 and mbr[510:512]==b"\x55\xaa":
            for i in range(4):
                e=mbr[446+i*16:462+i*16]
                ptype=e[4]; start=int.from_bytes(e[8:12],"little"); size=int.from_bytes(e[12:16],"little")
                if ptype and start and size and start not in out: out.append(start)
    except Exception: pass
    return out

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

def session_audit(url, challenge_text="", email=None):
    u=urllib.parse.urlsplit(url)
    host=(u.hostname or "")
    academy=host.endswith(".cylabacademy.net") or host.endswith(".cylabacademy.org")
    if u.scheme not in ("http","https") or not academy or u.username or u.password:
        raise ValueError("Use a cylabacademy.net/.org CTF instance URL")
    import web_session_audit
    origin=urllib.parse.urlunsplit((u.scheme,u.netloc,"/","",""))
    result=web_session_audit.run_audit(origin,timeout=15,insecure_tls=False,demonstrate_register_requirement=False,challenge_text=challenge_text,email=email)
    result["ok"]=True
    result["engine_version"]=VERSION
    return result

def reply(h,code,obj):
    b=json.dumps(obj,ensure_ascii=False).encode()
    h.send_response(code); h.send_header("Content-Type","application/json; charset=utf-8")
    h.send_header("Access-Control-Allow-Origin","https://sc1561.github.io")
    h.send_header("Access-Control-Allow-Methods","GET,POST,OPTIONS")
    h.send_header("Access-Control-Allow-Headers","Content-Type, X-Filename")
    h.send_header("Access-Control-Allow-Private-Network","true")
    h.send_header("Content-Length",str(len(b))); h.end_headers(); h.wfile.write(b)

class H(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(204); self.send_header("Access-Control-Allow-Origin","https://sc1561.github.io")
        self.send_header("Access-Control-Allow-Methods","GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers","Content-Type, X-Filename")
        self.send_header("Access-Control-Allow-Private-Network","true"); self.end_headers()

    def do_GET(self):
        path=self.path.split("?",1)[0]
        if path=="/health": return reply(self,200,status())
        if path=="/engine":
            b=dashboard().encode("utf-8"); self.send_response(200)
            self.send_header("Content-Type","text/html; charset=utf-8"); self.send_header("Content-Length",str(len(b)))
            self.end_headers(); self.wfile.write(b); return
        # Serve the Falcon frontend from the cloned/downloaded repository so browser and engine share one origin.
        rel="index.html" if path=="/" else path.lstrip("/")
        target=(WEB_ROOT/rel).resolve()
        try: target.relative_to(WEB_ROOT.resolve())
        except ValueError: return reply(self,403,{"ok":False})
        if target.is_file():
            mime={".html":"text/html; charset=utf-8",".js":"text/javascript; charset=utf-8",".css":"text/css; charset=utf-8",
                  ".json":"application/json; charset=utf-8",".png":"image/png",".jpg":"image/jpeg",".jpeg":"image/jpeg",
                  ".svg":"image/svg+xml",".ico":"image/x-icon"}.get(target.suffix.lower(),"application/octet-stream")
            b=target.read_bytes(); self.send_response(200); self.send_header("Content-Type",mime)
            self.send_header("Cache-Control","no-store"); self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b); return
        if path in ("/","/index.html"):
            b=dashboard().encode("utf-8"); self.send_response(200)
            self.send_header("Content-Type","text/html; charset=utf-8"); self.send_header("Cache-Control","no-store")
            self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b); return
        return reply(self,404,{"ok":False})

    def do_POST(self):
        path=self.path.split("?",1)[0]
        if path=="/artifacts/analyze":
            n=int(self.headers.get("Content-Length","0"))
            if n<=0 or n>64*1024*1024: return reply(self,413,{"ok":False,"error":"حجم الملف يجب أن يكون بين 1 بايت و64 ميغابايت."})
            try:
                raw=self.rfile.read(n)
                from artifact_extractor import analyze_artifact
                result=analyze_artifact(raw,Path(self.headers.get("X-Filename","upload.bin")).name)
                result["engine_version"]=VERSION
                return reply(self,200,result)
            except ValueError as e: return reply(self,413,{"ok":False,"error":str(e)[:300]})
            except Exception as e: return reply(self,422,{"ok":False,"error":"تعذر تحليل الملف محليًا","detail":str(e)[:300]})
        if path=="/web/session-audit":
            n=int(self.headers.get("Content-Length","0"))
            if not 0<n<=8192: return reply(self,413,{"ok":False,"error":"Invalid request size"})
            try:
                data=json.loads(self.rfile.read(n))
                return reply(self,200,session_audit(str(data.get("url","")), str(data.get("challenge_text", ""))[:65536], data.get("email")))
            except Exception as e: return reply(self,422,{"ok":False,"error":str(e)[:500]})
        if path=="/no-fa/analyze":
            n=int(self.headers.get("Content-Length","0"))
            if n>8192: return reply(self,413,{"ok":False,"error":"Invalid request size"})
            if n: self.rfile.read(n)  # Request content is ignored; paths are fixed under C:\\Falcon\\analysis.
            try:
                from no_fa_analysis import analyze_artifacts
                return reply(self,200,analyze_artifacts(ANALYSIS_ROOT))
            except Exception as e: return reply(self,500,{"ok":False,"error":str(e)[:300]})
        if path=="/no-fa/decode-session":
            n=int(self.headers.get("Content-Length","0"))
            if not 0<n<=32768: return reply(self,413,{"ok":False,"error":"Invalid request size"})
            try:
                data=json.loads(self.rfile.read(n))
                from no_fa_analysis import decode_flask_session
                return reply(self,200,decode_flask_session(data.get("cookie","")))
            except Exception as e: return reply(self,422,{"ok":False,"error":str(e)[:300]})
        if path=="/timeline/analyze":
            fls=find_tool("fls")
            if not fls: return reply(self,503,{"ok":False,"error":"fls.exe is not installed","need":["fls"]})
            n=int(self.headers.get("Content-Length","0")); name=Path(self.headers.get("X-Filename","timeline.img.gz")).name
            if n<=0 or n>180*1024*1024: return reply(self,413,{"ok":False,"error":"Compressed image too large"})
            # Keep all large forensic temporary data under C:\\Falcon, never the Windows temp directory.
            work=Path(tempfile.mkdtemp(prefix="timeline_",dir=str(TEMP_ROOT))); gz=work/name
            free=shutil.disk_usage(TEMP_ROOT).free
            # gzip ISIZE stores the uncompressed size modulo 2^32; useful for normal CTF disk images.
            expected=0
            try:
                if n>=4:
                    # We do not have the trailer yet, so reserve conservatively before upload.
                    expected=max(n*8,512*1024*1024)
            except Exception: expected=max(n*8,512*1024*1024)
            if free < expected+n:
                shutil.rmtree(work,ignore_errors=True)
                return reply(self,507,{"ok":False,"error":"Not enough free disk space","message":"C:\\\\Falcon needs more free space for the compressed upload and extracted disk image.","free_bytes":free,"recommended_free_bytes":expected+n})
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
                chosen_offset=None; attempts=[]; best_score=-1; best_data=""
                for off in partition_offsets(img):
                    args=[fls,"-r","-m","/"]
                    if off: args += ["-o",str(off)]
                    args.append(str(img))
                    candidate=work/("bodyfile_"+str(off)+".txt")
                    with candidate.open("w",encoding="utf-8",errors="ignore") as w:
                        q=subprocess.run(args,stdout=w,stderr=subprocess.PIPE,text=True,timeout=240)
                    data=candidate.read_text(encoding="utf-8",errors="ignore") if candidate.exists() else ""
                    low=data.lower()
                    # Prefer a real Linux root/data filesystem over a tiny boot partition.
                    score=data.count("\n")
                    for marker,weight in (("/home/",5000),("/root/",5000),("/etc/",2500),("/var/",2000),("/usr/",1000),("flag",8000),("secret",4000)):
                        if marker in low: score+=weight
                    attempts.append({"offset":off,"returncode":q.returncode,"records":data.count("\n"),"score":score,"error":q.stderr[-500:]})
                    if q.returncode==0 and data and score>best_score:
                        best_score=score; chosen_offset=off; best_data=data
                if chosen_offset is None: return reply(self,422,{"ok":False,"error":"fls failed on filesystem and detected partitions","attempts":attempts})
                body.write_text(best_data,encoding="utf-8")
                macb=body_macb(body); recent=macb[-120:]
                years=[int(x[:4]) for x in macb if len(x)>=5 and x[:4].isdigit() and x[4]=="-"]
                normal_year=max(years) if years else datetime.now().year
                old_anomalies=[x for x in macb if len(x)>=5 and x[:4].isdigit() and x[4]=="-" and int(x[:4]) < normal_year-5]
                keys=("flag","secret","anti","wipe","shred","tmp","home/","root/","bash","history","ctf-player","code","killer")
                # Search the full timeline, not only the newest 120 entries.
                evidence=[x for x in macb if any(k in x.lower() for k in keys)]
                evidence.sort(key=lambda x: (0 if any(k in x.lower() for k in ("flag","secret","killer","ctf-player","/home/","/root/")) else 1, x))
                # Also inspect tiny, very recent regular files: anti-forensic actions often leave a nearby clue.
                tiny=[]
                for x in recent[-60:]:
                    m0=re.search(r"macb\s+(\d+)\s+([^\s]+)\s+(r/[^\s]+)\s+(.+)$",x)
                    if m0 and int(m0.group(1))<=4096: tiny.append(x)
                inspect=list(dict.fromkeys(evidence[-40:]+tiny+old_anomalies[:80]))
                extracted=[]
                icat=find_tool("icat")
                # Filesystem Explorer: enumerate regular files under high-value CTF paths
                explorer=[]
                for line in best_data.splitlines():
                    low=line.lower()
                    if not any(p in low for p in ("/home/ctf-player/","/root/","killer-chat-app","flag","secret")): continue
                    parts=line.split("|")
                    if len(parts)<4: continue
                    name3=parts[1]; inode3=parts[2]; mode3=parts[3]
                    if not mode3.startswith("r/"): continue
                    explorer.append({"path":name3,"inode":inode3,"mode":mode3})
                # Prefer challenge application files, then other user evidence.
                explorer.sort(key=lambda x:(0 if "killer-chat-app" in x["path"].lower() else 1,0 if any(k in x["path"].lower() for k in ("flag","secret",".env","config","history")) else 1,x["path"]))
                if icat:
                    seen=set()
                    for item in explorer[:80]:
                        inode,name2=item["inode"],item["path"]
                        key=(inode,name2)
                        if key in seen: continue
                        seen.add(key)
                        try:
                            icat_args=[icat]
                            if chosen_offset: icat_args += ["-o",str(chosen_offset)]
                            icat_args += [str(img),inode]
                            q2=subprocess.run(icat_args,capture_output=True,timeout=20)
                            raw=q2.stdout[:2*1024*1024]
                            # Skip obvious binary payloads unless they contain useful printable text.
                            txt=raw.decode("utf-8","ignore")
                            printable=sum(ch.isprintable() or ch in "\r\n\t" for ch in txt)/max(1,len(txt))
                            if printable < .55 and not re.search(rb"(academy\{|flag\{|secret|password|token)",raw,re.I): continue
                            decoded=[]
                            for tok in re.findall(r"[A-Za-z0-9+/]{12,}={0,2}",txt):
                                try:
                                    z=base64.b64decode(tok,validate=True).decode("utf-8","ignore").strip()
                                    if z and sum(ch.isprintable() for ch in z)/max(1,len(z))>.9: decoded.append(z)
                                except Exception: pass
                            flags=re.findall(r"[A-Za-z][A-Za-z0-9_.:-]{1,30}\\{[^{}\\r\\n]{2,200}\\}",txt)
                            extracted.append({"path":name2,"inode":inode,"returncode":q2.returncode,"text":txt[-12000:],
                              "decoded":decoded[:30],"flags":flags[:30],"candidates":flags[:30],"source":"filesystem-explorer",
                              "error":q2.stderr.decode("utf-8","ignore")[-500:]})
                        except Exception as ex:
                            extracted.append({"path":name2,"inode":inode,"text":"","flags":[],"source":"filesystem-explorer","error":str(ex)[:500]})
                if icat:
                    for line in inspect:
                        # Bodyfile inode can include a sequence suffix (e.g. 4943-128-1); icat accepts the inode token.
                        m=re.search(r"macb\s+\d+\s+([^\s]+)\s+\S+\s+(.+)$",line)
                        if not m: continue
                        inode,name2=m.group(1),m.group(2)
                        # icat extracts regular file content; never feed directory metadata to it.
                        if re.search(r"\s+d/d",line) or name2.endswith("/"):
                            continue
                        try:
                            icat_args=[icat]
                            if chosen_offset: icat_args += ["-o",str(chosen_offset)]
                            icat_args += [str(img),inode]
                            q2=subprocess.run(icat_args,capture_output=True,timeout=20)
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
                  "filesystem_offset":chosen_offset,"partition_attempts":attempts,"filesystem_explorer":explorer[:120],"recent":recent,"evidence":evidence[:80],"old_anomalies":old_anomalies[:80],"icat_path":icat,"extracted":extracted})
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
