#!/usr/bin/env python3
import base64, json, re, shutil, subprocess, tempfile, gzip
from datetime import datetime
import urllib.request, urllib.parse, http.cookiejar
from http.cookies import SimpleCookie
from email.utils import parsedate_to_datetime
import time
import threading, uuid
import importlib.util
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HOST="127.0.0.1"; PORT=8765; VERSION="2.55.0"
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
_SQL_MAP1_JOBS={}
_SQL_MAP1_JOBS_LOCK=threading.Lock()

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
    import pcap_analyzer
    tshark=pcap_analyzer.find_tshark(); wireshark=pcap_analyzer.find_wireshark_gui()
    return {"ok":True,"engine":"Falcon Local Engine","version":VERSION,"python":True,
      "steghide":bool(find_steghide()),"steghide_path":find_steghide(),
      "sleuthkit":bool(fls),"fls_path":fls,"icat":bool(icat),"icat_path":icat,
      "timeline_python":True,"no_fa_analysis":True,"pcap_dns":True,
      "encrypted_zip_detection":True,"zipcrypto_wordlist_recovery":True,
      "zip_evidence_password_recovery":True,\n      "stegorsa_metadata_rsa":True,
      "winzip_aes_wordlist_recovery":importlib.util.find_spec("pyzipper") is not None,
      "wireshark":bool(wireshark),"wireshark_path":wireshark,
      "tshark":bool(tshark),"tshark_path":tshark,
      "tshark_version":pcap_analyzer.tshark_version(tshark) if tshark else None,"ready":True}

def dashboard():
    st=status()
    return """<!doctype html><meta charset="utf-8"><title>Falcon Local Engine</title>
<style>body{font-family:Arial;direction:rtl;background:#07111f;color:#eef;padding:40px;max-width:760px;margin:auto}.c{background:#102238;padding:22px;border-radius:16px;margin:14px 0}code{direction:ltr;display:inline-block}</style>
<h1>🦅 Falcon Local Engine v%s</h1><div class=c>🟢 Python جاهز<br>%s Sleuth Kit / fls: %s<br>🟢 Timeline: Falcon Python (لا يحتاج mactime.exe)<br>%s Steghide: %s<br>%s TShark / Wireshark CLI: %s</div>
<div class=c><b>الحالة:</b> %s</div>""" % (VERSION,"🟢" if st["sleuthkit"] else "🔴",st["fls_path"] or "غير موجود",
"🟢" if st["steghide"] else "🔴",st["steghide_path"] or "غير مثبت",
"🟢" if st["tshark"] else "⚪",st["tshark_path"] or "اختياري — ثبّت Wireshark مع TShark",
"جاهز لتحليل Timeline" if st["sleuthkit"] else "يحتاج fls.exe")

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
    import web_session_audit
    named=web_session_audit.detect_named_challenge(challenge_text)
    if named and named[1]=="credential-stuffing":
        import credential_stuffing
        tcp_target=credential_stuffing.parse_target(challenge_text)
        target=(f"TCP {tcp_target[0]}:{tcp_target[1]}" if tcp_target else "TCP: لم يُعثر على هدف nc صالح")
        return {"ok":True,"engine_version":VERSION,"target":target,
          "challenge":"Credential Stuffing","analyzer":"credential-stuffing","recognized":True,
          "success":False,"steps":[],"discovered":{"protocol":"TCP","file":"creds-dump.txt"},
          "explanation_ar":["هذا التحدي يستخدم اتصال TCP، وليس صفحة ويب. لم يُرسل أي طلب HTTP.",
            "احفظ creds-dump.txt في C:\\Falcon\\analysis، ثم استخدم زر فحص الملف المخصص لهذا التحدي."],
          "warnings":["لم يبدأ اختبار السجلات؛ يلزم تشغيل المسار المخصص بزر الطالب بعد حفظ الملف." if tcp_target else
                      "لم يُعثر في الوصف على أمر nc لهدف داخل نطاق cylabacademy.net/.org."]}
    if named and named[1]=="undo":
        return {"ok":True,"engine_version":VERSION,"target":"TCP: اتصال الطالب عبر Ncat",
          "challenge":"Undo","analyzer":"undo","recognized":True,"success":False,"steps":[],
          "discovered":{"protocol":"TCP","transcript_required":True},
          "explanation_ar":["هذا تحدٍ عبر TCP؛ لا يُرسل طلب HTTP إلى رابط عشوائي.",
            "يمكنك استخدام زر الاتصال في صقر لقراءة خرج الخدمة مباشرة، أو الاتصال يدويًا عبر Ncat.",
            "سيحدد صقر التحويلات التي تدعمها القرائن، ويعرض عكسها بترتيب عكسي.",
            "إذا لم يكن nc مثبتًا في Windows، استخدم Ncat المرفق مع Nmap."],
          "warnings":["لم يتصل صقر بالخدمة بعد؛ راجع الهدف ثم اضغط زر الاتصال وقراءة التلميحات."]}
    u=urllib.parse.urlsplit(url)
    host=(u.hostname or "")
    academy=host.endswith(".cylabacademy.net") or host.endswith(".cylabacademy.org")
    if u.scheme not in ("http","https") or not academy or u.username or u.password:
        raise ValueError("Use a cylabacademy.net/.org CTF instance URL")
    origin=urllib.parse.urlunsplit((u.scheme,u.netloc,"/","",""))
    result=web_session_audit.run_audit(origin,timeout=15,insecure_tls=False,demonstrate_register_requirement=False,challenge_text=challenge_text,email=email)
    result["ok"]=True
    result["engine_version"]=VERSION
    return result

def allowed_origin(h):
    origin=h.headers.get("Origin","")
    if origin=="https://sc1561.github.io": return origin
    try:
        parsed=urllib.parse.urlsplit(origin)
        if parsed.scheme=="http" and parsed.hostname in {"localhost","127.0.0.1","::1"} and not parsed.username and not parsed.password:
            return origin
    except Exception: pass
    return "https://sc1561.github.io"

def reply(h,code,obj):
    b=json.dumps(obj,ensure_ascii=False).encode()
    h.send_response(code); h.send_header("Content-Type","application/json; charset=utf-8")
    h.send_header("Access-Control-Allow-Origin",allowed_origin(h))
    h.send_header("Access-Control-Allow-Methods","GET,POST,OPTIONS")
    h.send_header("Access-Control-Allow-Headers","Content-Type, X-Filename")
    h.send_header("Access-Control-Allow-Private-Network","true")
    h.send_header("Content-Length",str(len(b))); h.end_headers(); h.wfile.write(b)

class H(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(204); self.send_header("Access-Control-Allow-Origin",allowed_origin(self))
        self.send_header("Access-Control-Allow-Methods","GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers","Content-Type, X-Filename")
        self.send_header("Access-Control-Allow-Private-Network","true"); self.end_headers()

    def do_GET(self):
        path=self.path.split("?",1)[0]
        if path=="/health": return reply(self,200,status())
        if path=="/credential-stuffing/status":
            job_id=urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query).get("job_id",[""])[0]
            with _CREDENTIAL_JOBS_LOCK:
                job=_CREDENTIAL_JOBS.get(job_id)
                snapshot=dict(job) if job else None
            if not snapshot: return reply(self,404,{"ok":False,"error":"جلسة الفحص غير موجودة أو انتهت."})
            return reply(self,200,snapshot)
        if path=="/sql-map1/status":
            job_id=urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query).get("job_id",[""])[0]
            with _SQL_MAP1_JOBS_LOCK:
                snapshot=dict(_SQL_MAP1_JOBS.get(job_id,{})) or None
            if not snapshot: return reply(self,404,{"ok":False,"error":"جلسة Sql Map1 غير موجودة أو انتهت."})
            return reply(self,200,snapshot)
        if path=="/fool-lockout/status":
            job_id=urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query).get("job_id",[""])[0]
            with _FOOL_LOCKOUT_JOBS_LOCK:
                job=_FOOL_LOCKOUT_JOBS.get(job_id)
                snapshot=dict(job) if job else None
                if snapshot and snapshot.get("phase")=="waiting":
                    snapshot["wait_seconds"]=max(0,int(snapshot.get("wait_seconds",0)-(time.monotonic()-snapshot.get("updated_at",time.monotonic()))))
            if not snapshot: return reply(self,404,{"ok":False,"error":"جلسة فحص Fool the Lockout غير موجودة أو انتهت."})
            return reply(self,200,snapshot)
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
        if path=="/stego/analyze-local":
            n=int(self.headers.get("Content-Length","0"))
            if not 0<n<=30000: return reply(self,413,{"ok":False,"error":"أرسل اسم ملف وتلميحًا صالحين."})
            try:
                data=json.loads(self.rfile.read(n))
                if data.get("confirm") is not True:
                    return reply(self,400,{"ok":False,"error":"ابدأ الفحص من زر تحليل الملف المحلي."})
                name=str(data.get("filename", "")).strip()
                if not name or name in (".","..") or "/" in name or "\\" in name or Path(name).name!=name:
                    return reply(self,400,{"ok":False,"error":"اكتب اسم ملف فقط دون مسار، مثل flag 2.jpg."})
                root=ANALYSIS_ROOT.resolve()
                target=(root/name).resolve()
                if target.parent!=root:
                    return reply(self,400,{"ok":False,"error":"يسمح فقط بملفات مجلد C:\\Falcon\\analysis."})
                if not target.is_file():
                    return reply(self,404,{"ok":False,"error":"لم يُعثر على الملف داخل C:\\Falcon\\analysis."})
                if target.stat().st_size>32*1024*1024:
                    return reply(self,413,{"ok":False,"error":"حجم الملف يتجاوز 32 ميغابايت."})
                import arabic_stego
                result=arabic_stego.analyze_arabic_challenge(target.read_bytes(),name,
                    str(data.get("challenge_text",""))[:24000],find_steghide())
                result["engine_version"]=VERSION
                result["source"]="C:\\Falcon\\analysis"
                return reply(self,200,result)
            except Exception as e: return reply(self,422,{"ok":False,"error":"تعذر تحليل الملف المحلي","detail":str(e)[:300]})
        if path=="/stego/analyze":
            n=int(self.headers.get("Content-Length","0"))
            if not 0<n<=48*1024*1024: return reply(self,413,{"ok":False,"error":"أرسل ملفًا أو ZIP بحجم لا يتجاوز 48 ميغابايت بعد ترميز النقل."})
            try:
                data=json.loads(self.rfile.read(n))
                if data.get("confirm") is not True:
                    return reply(self,400,{"ok":False,"error":"ابدأ الفحص من زر التحليل بعد اختيار الملف."})
                blob=base64.b64decode(data.get("file_b64",""),validate=True)
                if len(blob)>32*1024*1024: return reply(self,413,{"ok":False,"error":"حجم الملف المفكوك أكبر من 32 ميغابايت."})
                import arabic_stego
                result=arabic_stego.analyze_arabic_challenge(blob,Path(data.get("filename","upload.bin")).name,
                    str(data.get("challenge_text",""))[:24000],find_steghide())
                result["engine_version"]=VERSION
                return reply(self,200,result)
            except Exception as e: return reply(self,422,{"ok":False,"error":"تعذر تحليل التحدي العربي محليًا","detail":str(e)[:300]})
        if path=="/crypto/analyze-files":
            n=int(self.headers.get("Content-Length","0"))
            if not 0<n<=48*1024*1024: return reply(self,413,{"ok":False,"error":"حجم مجموعة الملفات كبير جدًا."})
            work=None
            try:
                data=json.loads(self.rfile.read(n))
                items=data.get("files") or []
                if not isinstance(items,list) or not items or len(items)>12:
                    return reply(self,400,{"ok":False,"error":"اختر من 1 إلى 12 ملفًا للتحليل."})
                work=Path(tempfile.mkdtemp(prefix="falcon_multi_",dir=str(TEMP_ROOT)))
                total=0
                for item in items:
                    name=Path(str(item.get("name","upload.bin"))).name[:180]
                    raw=base64.b64decode(str(item.get("data_b64","")),validate=True)
                    total+=len(raw)
                    if not raw or len(raw)>16*1024*1024 or total>32*1024*1024:
                        raise ValueError("تجاوزت الملفات حدود التحليل المحلي الآمن.")
                    (work/name).write_bytes(raw)
                import crypto_analysis
                result=crypto_analysis.analyze(str(data.get("challenge_text",""))[:22000],work)
                result["engine_version"]=VERSION
                result["uploaded_files"]=[Path(str(x.get("name",""))).name for x in items]
                return reply(self,200,result)
            except Exception as e:
                return reply(self,422,{"ok":False,"error":"تعذر التحليل متعدد الملفات","detail":str(e)[:300]})
            finally:
                if work: shutil.rmtree(work,ignore_errors=True)
        if path=="/crypto/analyze":
            n=int(self.headers.get("Content-Length","0"))
            if not 0<n<=24000: return reply(self,413,{"ok":False,"error":"ألصق وصف تحدي Cryptography صالحًا (بحد أقصى 24 كيلوبايت)."})
            try:
                data=json.loads(self.rfile.read(n))
                if data.get("confirm") is not True:
                    return reply(self,400,{"ok":False,"error":"ابدأ التحليل من زر Cryptography بعد مراجعة الملفات المطلوبة."})
                import crypto_analysis
                result=crypto_analysis.analyze(str(data.get("challenge_text",""))[:22000],ANALYSIS_ROOT)
                result["engine_version"]=VERSION
                return reply(self,200,result)
            except Exception as e: return reply(self,422,{"ok":False,"error":"تعذر تحليل تحدي Cryptography محليًا","detail":str(e)[:300]})
        if path=="/archives/recover":
            n=int(self.headers.get("Content-Length","0"))
            if n<=0 or n>24*1024*1024: return reply(self,413,{"ok":False,"error":"حجم طلب فحص ZIP كبير جدًا (الحد 24 ميغابايت)."})
            try:
                data=json.loads(self.rfile.read(n))
                if data.get("confirm") is not True:
                    return reply(self,400,{"ok":False,"error":"ابدأ البحث التلقائي بعد مراجعة الأرشيف المحدد."})
                archive=base64.b64decode(data.get("archive_b64",""),validate=True)
                if not archive or len(archive)>12*1024*1024:
                    return reply(self,413,{"ok":False,"error":"حجم الأرشيف يجب ألا يتجاوز 12 ميغابايت في مسار الاستعادة."})
                import zip_challenge
                name=Path(str(data.get("filename","challenge.zip"))).name[:180]
                challenge_text=str(data.get("challenge_text",""))[:24000]
                recovered=zip_challenge.recover_zip_auto(archive,name,challenge_text,
                    analysis_root=ANALYSIS_ROOT,falcon_home=FALCON_HOME)
                if recovered.get("success"):
                    from artifact_extractor import analyze_artifact
                    members=recovered.pop("members",[])
                    scanned_flags=[]; scanned_findings=[]; scanned_items=[]
                    for member_name,content in members:
                        analysis=analyze_artifact(content,member_name)
                        scanned_flags.extend(analysis.get("flags",[]))
                        scanned_findings.extend(analysis.get("findings",[]))
                        scanned_items.extend({k:v for k,v in item.items() if k!="download_b64"} for item in analysis.get("artifacts",[]))
                    unique_flags={item.get("flag"):item for item in scanned_flags if item.get("flag")}
                    recovered["members"]=[{"name":str(member_name).replace("\\","/").split("/")[-1][:180],"size":len(content)} for member_name,content in members]
                    recovered["analysis"]={"flags":list(unique_flags.values()),"findings":list(dict.fromkeys(scanned_findings))[:80],"members":scanned_items}
                recovered["filename"]=name
                recovered["engine_version"]=VERSION
                return reply(self,200,recovered)
            except (ValueError, TypeError, json.JSONDecodeError) as e:
                return reply(self,400,{"ok":False,"error":"تعذر قراءة الأرشيف المشفّر.","detail":str(e)[:180]})
            except Exception as e:
                return reply(self,422,{"ok":False,"error":"تعذر تحليل الأرشيف المشفّر.","detail":str(e)[:240]})
        if path=="/archives/crack":
            n=int(self.headers.get("Content-Length","0"))
            if n<=0 or n>24*1024*1024: return reply(self,413,{"ok":False,"error":"حجم طلب فحص ZIP كبير جدًا (الحد 24 ميغابايت)."})
            try:
                data=json.loads(self.rfile.read(n))
                if data.get("confirm") is not True:
                    return reply(self,400,{"ok":False,"error":"ابدأ استعادة كلمة المرور بزر المحاولة بعد مراجعة الملف وقائمة المرشحين."})
                archive=base64.b64decode(data.get("archive_b64",""),validate=True)
                if not archive or len(archive)>12*1024*1024:
                    return reply(self,413,{"ok":False,"error":"حجم الأرشيف يجب ألا يتجاوز 12 ميغابايت في مسار استعادة كلمة المرور."})
                supplied=data.get("candidates",[])
                if not isinstance(supplied,list) or len(supplied)>20000:
                    return reply(self,400,{"ok":False,"error":"أرسل حتى 20,000 كلمة مرشحة، كل واحدة كسطر مستقل."})
                candidates=[str(x)[:128] for x in supplied]
                import zip_challenge
                name=Path(str(data.get("filename","challenge.zip"))).name[:180]
                recovered=zip_challenge.recover_zip(archive,candidates,name)
                if recovered.get("success"):
                    from artifact_extractor import analyze_artifact
                    members=recovered.pop("members",[])
                    scanned_flags=[]; scanned_findings=[]; scanned_items=[]
                    for member_name,content in members:
                        analysis=analyze_artifact(content,member_name)
                        scanned_flags.extend(analysis.get("flags",[]))
                        scanned_findings.extend(analysis.get("findings",[]))
                        scanned_items.extend({k:v for k,v in item.items() if k!="download_b64"} for item in analysis.get("artifacts",[]))
                    unique_flags={item.get("flag"):item for item in scanned_flags if item.get("flag")}
                    recovered["members"]=[{"name":str(member_name).replace("\\","/").split("/")[-1][:180],"size":len(content)} for member_name,content in members]
                    recovered["analysis"]={"flags":list(unique_flags.values()),"findings":list(dict.fromkeys(scanned_findings))[:80],"members":scanned_items}
                recovered["filename"]=name
                recovered["engine_version"]=VERSION
                return reply(self,200,recovered)
            except (ValueError, TypeError, json.JSONDecodeError) as e:
                return reply(self,400,{"ok":False,"error":"تعذر قراءة الأرشيف أو قائمة الكلمات المرشحة.","detail":str(e)[:180]})
            except Exception as e:
                return reply(self,422,{"ok":False,"error":"تعذر تحليل الأرشيف المشفّر.","detail":str(e)[:240]})
        if path=="/artifacts/analyze":
            n=int(self.headers.get("Content-Length","0"))
            if n<=0 or n>64*1024*1024: return reply(self,413,{"ok":False,"error":"حجم الملف يجب أن يكون بين 1 بايت و64 ميغابايت."})
            try:
                raw=self.rfile.read(n)
                encoded_name=self.headers.get("X-Filename","upload.bin")
                name=Path(urllib.parse.unquote(encoded_name)).name
                import pcap_analyzer
                if pcap_analyzer.is_capture(raw,name):
                    result=pcap_analyzer.analyze_pcap(raw,name)
                else:
                    from artifact_extractor import analyze_artifact
                    result=analyze_artifact(raw,name)
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
        if path=="/credential-stuffing/solve":
            n=int(self.headers.get("Content-Length","0"))
            if not 0<n<=8192: return reply(self,413,{"ok":False,"error":"Invalid request size"})
            try:
                data=json.loads(self.rfile.read(n))
                if data.get("confirm") is not True:
                    return reply(self,400,{"ok":False,"error":"ابدأ المحاولة من زر التحدي بعد مراجعة الهدف والملف."})
                import web_session_audit, credential_stuffing
                challenge_text=str(data.get("challenge_text", ""))[:65536]
                named=web_session_audit.detect_named_challenge(challenge_text)
                target=credential_stuffing.parse_target(challenge_text)
                if not named or named[1]!="credential-stuffing" or not target:
                    return reply(self,400,{"ok":False,"error":"يلزم وصف Credential Stuffing وأمر nc صالح ضمن نطاق Cylab Academy."})
                result=credential_stuffing.solve(ANALYSIS_ROOT/"creds-dump.txt",*target)
                result["engine_version"]=VERSION
                return reply(self,200,result)
            except Exception as e: return reply(self,500,{"ok":False,"error":str(e)[:300]})
        if path=="/credential-stuffing/start":
            n=int(self.headers.get("Content-Length","0"))
            if not 0<n<=8192: return reply(self,413,{"ok":False,"error":"وصف التحدي غير صالح أو كبير جدًا."})
            try:
                data=json.loads(self.rfile.read(n))
                if data.get("confirm") is not True:
                    return reply(self,400,{"ok":False,"error":"ابدأ الفحص من الزر بعد مراجعة الملف والهدف."})
                import web_session_audit, credential_stuffing
                challenge_text=str(data.get("challenge_text", ""))[:65536]
                named=web_session_audit.detect_named_challenge(challenge_text)
                target=credential_stuffing.parse_target(challenge_text)
                if not named or named[1]!="credential-stuffing" or not target:
                    return reply(self,400,{"ok":False,"error":"يلزم وصف Credential Stuffing وأمر nc صالح ضمن نطاق Cylab Academy."})
                job_id=uuid.uuid4().hex
                host,port=target
                with _CREDENTIAL_JOBS_LOCK:
                    if len(_CREDENTIAL_JOBS)>64:
                        for old_id,old_job in list(_CREDENTIAL_JOBS.items()):
                            if old_job.get("state") in ("done","error"):
                                _CREDENTIAL_JOBS.pop(old_id,None)
                            if len(_CREDENTIAL_JOBS)<=32: break
                    _CREDENTIAL_JOBS[job_id]={"ok":True,"job_id":job_id,"state":"running",
                        "attempts":0,"entries":0,"target":f"{host}:{port}","result":None}
                def run_job():
                    def update_progress(attempts,entries):
                        with _CREDENTIAL_JOBS_LOCK:
                            current=_CREDENTIAL_JOBS.get(job_id)
                            if current:
                                current["attempts"]=attempts;current["entries"]=entries
                    try:
                        result=credential_stuffing.solve(ANALYSIS_ROOT/"creds-dump.txt",host,port,progress=update_progress)
                        with _CREDENTIAL_JOBS_LOCK:
                            current=_CREDENTIAL_JOBS.get(job_id)
                            if current:
                                current["state"]="done" if result.get("ok") else "error"
                                current["attempts"]=result.get("attempts",current["attempts"])
                                current["entries"]=result.get("entries",current["entries"])
                                current["result"]=result
                    except Exception as exc:
                        with _CREDENTIAL_JOBS_LOCK:
                            current=_CREDENTIAL_JOBS.get(job_id)
                            if current:
                                current["state"]="error";current["result"]={"ok":False,"error":str(exc)[:300]}
                threading.Thread(target=run_job,name="falcon-credential-stuffing",daemon=True).start()
                return reply(self,202,{"ok":True,"job_id":job_id,"state":"running","target":f"{host}:{port}"})
            except Exception as e: return reply(self,500,{"ok":False,"error":str(e)[:300]})
        if path=="/undo/connect":
            n=int(self.headers.get("Content-Length","0"))
            if not 0<n<=70000: return reply(self,413,{"ok":False,"error":"وصف التحدي غير صالح أو كبير جدًا."})
            try:
                data=json.loads(self.rfile.read(n))
                if data.get("confirm") is not True:
                    return reply(self,400,{"ok":False,"error":"راجع عنوان خدمة CTF ثم ابدأ الاتصال من زر التحدي."})
                import web_session_audit, undo_challenge
                challenge_text=str(data.get("challenge_text", ""))[:65536]
                named=web_session_audit.detect_named_challenge(challenge_text)
                if not named or named[1]!="undo":
                    return reply(self,400,{"ok":False,"error":"لم أتعرف على وصف تحدي Undo."})
                result=undo_challenge.connect_transcript(challenge_text)
                result["engine_version"]=VERSION
                return reply(self,200,result)
            except Exception as e: return reply(self,422,{"ok":False,"error":str(e)[:300]})
        if path=="/undo/solve":
            n=int(self.headers.get("Content-Length","0"))
            if not 0<n<=70000: return reply(self,413,{"ok":False,"error":"وصف التحدي غير صالح أو كبير جدًا."})
            try:
                data=json.loads(self.rfile.read(n))
                if data.get("confirm") is not True:
                    return reply(self,400,{"ok":False,"error":"ابدأ الحل من زر التحدي بعد مراجعة عنوان الخدمة."})
                import web_session_audit, undo_challenge
                challenge_text=str(data.get("challenge_text", ""))[:65536]
                named=web_session_audit.detect_named_challenge(challenge_text)
                if not named or named[1]!="undo":
                    return reply(self,400,{"ok":False,"error":"لم أتعرف على وصف تحدي Undo."})
                result=undo_challenge.solve_interactive(challenge_text)
                result["engine_version"]=VERSION
                return reply(self,200,result)
            except Exception as e: return reply(self,422,{"ok":False,"error":str(e)[:300]})
        if path=="/undo/analyze":
            n=int(self.headers.get("Content-Length","0"))
            if not 0<n<=70000: return reply(self,413,{"ok":False,"error":"الصق نصًا لا يتجاوز 70 كيلوبايت."})
            try:
                data=json.loads(self.rfile.read(n))
                import web_session_audit, undo_challenge
                challenge_text=str(data.get("challenge_text", ""))[:65536]
                if not (web_session_audit.detect_named_challenge(challenge_text) or (None,None))[1]=="undo":
                    return reply(self,400,{"ok":False,"error":"لم أتعرف على عنوان تحدي Undo في النص."})
                result=undo_challenge.analyze(challenge_text,str(data.get("transcript", ""))[:65536])
                result["engine_version"]=VERSION
                return reply(self,200,result)
            except Exception as e: return reply(self,422,{"ok":False,"error":str(e)[:300]})
        if path=="/secret-box/solve":
            n=int(self.headers.get("Content-Length","0"))
            if not 0<n<=16000: return reply(self,413,{"ok":False,"error":"وصف التحدي غير صالح أو كبير جدًا."})
            try:
                data=json.loads(self.rfile.read(n))
                if data.get("confirm") is not True:
                    return reply(self,400,{"ok":False,"error":"راجع عنوان المثيل ثم ابدأ الحل من زر Secret Box."})
                challenge_text=str(data.get("challenge_text",""))[:12000]
                import web_session_audit, secret_box
                named=web_session_audit.detect_named_challenge(challenge_text)
                described=bool(re.search(r"this secret box is designed to conceal your secrets",challenge_text,re.I))
                if not ((named and named[1]=="secret-box") or described):
                    return reply(self,400,{"ok":False,"error":"لم أتعرف على وصف تحدي Secret Box."})
                result=secret_box.solve(challenge_text)
                result["engine_version"]=VERSION
                return reply(self,200,result)
            except Exception as e: return reply(self,422,{"ok":False,"error":str(e)[:300]})
        if path=="/sql-map1/start":
            n=int(self.headers.get("Content-Length","0"))
            if not 0<n<=16000: return reply(self,413,{"ok":False,"error":"وصف التحدي غير صالح أو كبير جدًا."})
            try:
                data=json.loads(self.rfile.read(n))
                if data.get("confirm") is not True:
                    return reply(self,400,{"ok":False,"error":"راجع عنوان المثيل ثم ابدأ الحل من زر Sql Map1."})
                import web_session_audit, sql_map1
                challenge_text=str(data.get("challenge_text",""))[:14000]
                named=web_session_audit.detect_named_challenge(challenge_text)
                target=sql_map1.parse_target(challenge_text)
                if not named or named[1]!="sql-map1" or not target:
                    return reply(self,400,{"ok":False,"error":"يلزم عنوان Sql Map1 ورابط مثيل Cylab Academy صالح."})
                job_id=uuid.uuid4().hex
                with _SQL_MAP1_JOBS_LOCK:
                    for old_id,old_job in list(_SQL_MAP1_JOBS.items()):
                        if old_job.get("state") in ("done","error"):
                            _SQL_MAP1_JOBS.pop(old_id,None)
                    _SQL_MAP1_JOBS[job_id]={"ok":True,"job_id":job_id,"state":"running","phase":"inspect",
                        "message":"بدأ فحص صفحة التحدي.","updated_at":time.monotonic()}
                def update_progress(phase,message):
                    with _SQL_MAP1_JOBS_LOCK:
                        current=_SQL_MAP1_JOBS.get(job_id)
                        if current: current.update(phase=phase,message=message,updated_at=time.monotonic())
                def run_job():
                    try:
                        result=sql_map1.solve(challenge_text,ANALYSIS_ROOT,progress=update_progress)
                        with _SQL_MAP1_JOBS_LOCK:
                            current=_SQL_MAP1_JOBS.get(job_id)
                            if current: current.update(state="done" if result.get("ok") else "error",phase="done",result=result,updated_at=time.monotonic())
                    except Exception as exc:
                        with _SQL_MAP1_JOBS_LOCK:
                            current=_SQL_MAP1_JOBS.get(job_id)
                            if current: current.update(state="error",phase="error",result={"ok":False,"error":str(exc)[:300]})
                threading.Thread(target=run_job,name="falcon-sql-map1",daemon=True).start()
                return reply(self,202,{"ok":True,"job_id":job_id,"state":"running","target":target})
            except Exception as e: return reply(self,500,{"ok":False,"error":str(e)[:300]})
        if path=="/fool-lockout/start":
            n=int(self.headers.get("Content-Length","0"))
            if not 0<n<=20000: return reply(self,413,{"ok":False,"error":"وصف التحدي غير صالح أو كبير جدًا."})
            try:
                data=json.loads(self.rfile.read(n))
                if data.get("confirm") is not True:
                    return reply(self,400,{"ok":False,"error":"راجع هدف المثيل وابدأ الفحص من زر Fool the Lockout."})
                import web_session_audit, fool_lockout
                challenge_text=str(data.get("challenge_text",""))[:18000]
                named=web_session_audit.detect_named_challenge(challenge_text)
                target=fool_lockout.parse_target(challenge_text)
                source_url,creds_url=fool_lockout._artifact_urls(challenge_text)
                if not named or named[1]!="fool-the-lockout" or not target or not source_url or not creds_url:
                    return reply(self,400,{"ok":False,"error":"يلزم وصف Fool the Lockout ورابط مثيل Cylab Academy ورابطا app.py وcreds-dump.txt."})
                job_id=uuid.uuid4().hex
                with _FOOL_LOCKOUT_JOBS_LOCK:
                    for old_id,old_job in list(_FOOL_LOCKOUT_JOBS.items()):
                        if old_job.get("state") in ("done","error"):
                            _FOOL_LOCKOUT_JOBS.pop(old_id,None)
                    _FOOL_LOCKOUT_JOBS[job_id]={"ok":True,"job_id":job_id,"state":"running","phase":"downloading",
                        "attempts":0,"checked":0,"entries":0,"wait_seconds":0,"updated_at":time.monotonic(),
                        "target":target}
                def update_progress(attempts,checked,entries,phase,wait_seconds):
                    with _FOOL_LOCKOUT_JOBS_LOCK:
                        current=_FOOL_LOCKOUT_JOBS.get(job_id)
                        if current:
                            current.update(attempts=attempts,checked=checked,entries=entries,phase=phase,
                                           wait_seconds=wait_seconds,updated_at=time.monotonic())
                def run_job():
                    try:
                        result=fool_lockout.solve(challenge_text,ANALYSIS_ROOT,progress=update_progress)
                        with _FOOL_LOCKOUT_JOBS_LOCK:
                            current=_FOOL_LOCKOUT_JOBS.get(job_id)
                            if current:
                                current.update(state="done" if result.get("ok") else "error",phase="done",result=result,
                                  attempts=result.get("attempts",current["attempts"]),checked=result.get("checked",current["checked"]),
                                  entries=result.get("entries",current["entries"]),wait_seconds=0,updated_at=time.monotonic())
                    except Exception as exc:
                        with _FOOL_LOCKOUT_JOBS_LOCK:
                            current=_FOOL_LOCKOUT_JOBS.get(job_id)
                            if current: current.update(state="error",phase="error",result={"ok":False,"error":str(exc)[:300]})
                threading.Thread(target=run_job,name="falcon-fool-lockout",daemon=True).start()
                return reply(self,202,{"ok":True,"job_id":job_id,"state":"running","target":target})
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
            n=int(self.headers.get("Content-Length","0")); encoded_name=self.headers.get("X-Filename","timeline.img.gz"); name=Path(urllib.parse.unquote(encoded_name)).name
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
