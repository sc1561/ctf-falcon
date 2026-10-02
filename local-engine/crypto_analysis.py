"""Local, bounded cryptography challenge helpers for CTF Falcon.

Only reads explicitly named files from the analysis directory and never runs
challenge-provided Python. Hard lattice/oracle tasks are identified and given
evidence-based next steps instead of being guessed.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import html
import math
import re
import hashlib
import subprocess
from pathlib import Path
from urllib.parse import unquote

FLAG_RE = re.compile(rb"(?:picoCTF|academy|flag|CTF)\{[^{}\r\n]{1,240}\}", re.I)
CHALLENGES = {
    "stegorsa": ("StegoRSA", ["flag.enc", "image.jpg"]),
    "shared secrets": ("Shared Secrets", ["message.txt", "encryption.py"]),
    "hashcrack": ("hashcrack", []),
    "interencdec": ("interencdec", ["enc_flag"]),
    "mod 26": ("Mod 26", ["values.txt"]),
    "the numbers": ("The Numbers", ["the_numbers.png"]),
    "timestamped secrets": ("Timestamped Secrets", ["message.txt", "encryption.py"]),
    "small trouble": ("Small Trouble", ["message.txt", "encryption.py"]),
    "shift registers": ("shift registers", ["chall.py", "output.txt"]),
    "related messages": ("Related Messages", ["chall.py", "output.txt"]),
    "not true": ("Not TRUe", ["encrypt.py", "public.txt"]),
    "cryptomaze": ("cryptomaze", ["output.txt"]),
    "clusterrsa": ("ClusterRSA", ["message.txt"]),
    "black cobra pepper": ("Black Cobra Pepper", ["chall.py", "output.txt"]),
    "crack the power": ("Crack the Power", ["message.txt"]),
    "guess my cheese (part 2)": ("Guess My Cheese (Part 2)", ["cheese_list.txt"]),
    "guess my cheese (part 1)": ("Guess My Cheese (Part 1)", []),
    "rsa_oracle": ("rsa_oracle", ["secret.enc", "password.enc"]),
    "custom encryption": ("Custom encryption", ["enc_flag", "custom_encryption.py"]),
    "c3": ("C3", ["ciphertext", "convert.py"]),
    "rotation": ("rotation", ["encrypted.txt"]),
    "13": ("13", []),
}
GUIDES = {
    "hashcrack": "تحدٍ تفاعلي: افتح المثيل أولًا وأرسل تفاصيله التي تظهر بعد التشغيل؛ يحتاج المحلل أسماء الحقول والخوارزمية/السجلات الفعلية.",
    "the numbers": "يحوّل صقر أرقام A1Z26 (1=A … 26=Z). إذا لم يستطع قراءة الأرقام من الصورة، أرفق صورة واضحة أو ارفع ملفها بعد حفظه في مجلد التحليل.",
    "timestamped secrets": "يفحص صقر وقت التشفير المقرّب وطريقة اشتقاق المفتاح في encryption.py، ثم يجرب نطاق الوقت المحدود. لا يجرّب فضاء مفاتيح AES عشوائيًا.",
    "small trouble": "يختبر صقر هجوم Wiener عندما تكون الأسس الخاصة صغيرة. تلميح Boneh–Durfee يتطلب SageMath/خفضًا شبكيًا؛ إن لم تتوفر المكتبة سيعرض الدليل بدل ادعاء فك التشفير.",
    "shift registers": "يفحص بنية LFSR وبيانات الخرج؛ استعادة الحالة تعتمد على التنفيذ والـoutput.txt المحددين. لا يخمّن حالات عشوائية.",
    "related messages": "يتحقق من علاقة رسالتي RSA لاستخدام Franklin–Reiter. يتطلب ذلك الأعداد والمعاملات الفعلية من الملفين.",
    "not true": "تحدٍ شبكي من عائلة lattice. يحتاج خوارزمية/مكتبة مناسبة مثل SageMath؛ لا ينفذ صقر النص المرفق ولا يقدّم حلًا مزعومًا.",
    "guess my cheese (part 1)": "تحدٍ تفاعلي Squeexy. شغّل المثيل وأرفق سؤال الخادم/تفاصيله؛ بعد ذلك يحلل صقر معادلات التحويل قبل إرسال الإجابة.",
    "rsa_oracle": "يتطلب خدمة TCP حية. لا يستنتج صقر العلم من ملفات ciphertext وحدها؛ زوّده برسالة الخدمة/تفاصيل oracle التي تظهر عند الاتصال.",
    "custom encryption": "يقرأ صقر التحويلات من الملف ويرجعها بالعكس. يرفض تشغيل custom_encryption.py؛ مصدر التحدي يعامل كبيانات غير موثوقة.",
    "c3": "تحدٍ باستبدال دوري مخصص. يحلل صقر convert.py والنص المشفر؛ يجب أن تؤكد نتيجة الفحص تطابقها مع صيغة العلم academy{...}.",
}


def _slug(text: str) -> str | None:
    t = (text or "").lower()
    for name in sorted(CHALLENGES, key=len, reverse=True):
        if re.search(r"(?im)^\s*(?:#{1,6}\s*)?" + re.escape(name) + r"(?=\s|$|[—(-])", t):
            return name
    return None


def _files(root: Path) -> dict[str, Path]:
    out = {}
    try:
        for p in root.iterdir():
            if p.is_file(): out[p.name.lower()] = p
    except OSError:
        pass
    return out


def _valid_flag(raw: bytes) -> str | None:
    m = FLAG_RE.search(raw)
    if not m: return None
    return html.unescape(m.group(0).decode("utf-8", "replace"))


def _text_decodes(raw: bytes):
    """Small bounded decoder graph; retain only printable intermediate text."""
    todo = [(raw, "original", 0)]
    seen = {raw}
    while todo and len(seen) < 250 and len(todo) < 300:
        data, label, depth = todo.pop(0)
        flag = _valid_flag(data)
        if flag: return flag, label
        if depth >= 7: continue
        candidates = []
        try:
            s = data.decode("utf-8").strip()
        except UnicodeDecodeError:
            continue
        candidates.append((codecs.decode(s, "rot_13").encode(), "ROT13"))
        candidates.append((s[::-1].encode(), "reverse"))
        candidates.append((unquote(s).encode(), "URL decode"))
        compact = re.sub(r"\s+", "", s)
        if len(compact) >= 4 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact):
            for decoder, name in ((base64.b64decode, "Base64"), (base64.urlsafe_b64decode, "Base64url")):
                try: candidates.append((decoder(compact + "=" * ((-len(compact)) % 4)), name))
                except (ValueError, binascii.Error): pass
        if re.fullmatch(r"(?:0x)?[0-9a-fA-F\s]+", s) and len(re.sub(r"\W", "", s)) % 2 == 0:
            try: candidates.append((bytes.fromhex(re.sub(r"0x|\s", "", s, flags=re.I)), "Hex"))
            except ValueError: pass
        # Caesar rotations help the classic rotation challenge; ROT13 is also
        # covered above, and the flag regex selects a unique recognizable output.
        for k in range(1, 26):
            out = []
            for ch in s:
                if "a" <= ch <= "z": out.append(chr((ord(ch)-97-k)%26+97))
                elif "A" <= ch <= "Z": out.append(chr((ord(ch)-65-k)%26+65))
                else: out.append(ch)
            candidates.append(("".join(out).encode(), f"Caesar shift {k}"))
        for nxt, op in candidates:
            if nxt in seen or len(nxt) > 2_000_000: continue
            # Avoid branching on binary garbage or empty output.
            if nxt and sum(32 <= b < 127 or b in (9, 10, 13) for b in nxt) / len(nxt) < .78: continue
            seen.add(nxt); todo.append((nxt, label + " → " + op, depth + 1))
    return None, None


def _a1z26(raw: bytes) -> str | None:
    try: s = raw.decode("ascii")
    except UnicodeDecodeError: return None
    nums = re.findall(r"\d+|[{}]", s)
    if len(nums) < 10 or sum(x.isdigit() for x in nums) < 8: return None
    out = []
    for token in nums:
        if token in "{}": out.append(token)
        elif 1 <= int(token) <= 26: out.append(chr(96 + int(token)))
        else: return None
    value = "".join(out)
    if value.startswith("picoctf{") or value.startswith("PICOCTF{") or _valid_flag(value.encode()): return value
    # Try the conventional uppercase picoCTF prefix as well.
    return None


def _assignment_map(blob: str) -> dict[str, str]:
    vals = {}
    for m in re.finditer(r"(?im)^\s*([A-Za-z_][\w]*)\s*[:=]\s*([^\r\n#]+)", blob):
        vals[m.group(1).lower()] = m.group(2).strip().strip("'\"")
    return vals


def _first_int(vals: dict[str, str], *names: str) -> int | None:
    for name in names:
        raw = vals.get(name.lower())
        if raw:
            m = re.search(r"-?0x[0-9a-f]+|-?\d+", raw, re.I)
            if m:
                try: return int(m.group(0), 0)
                except ValueError: pass
    return None


def _shared_secrets(text: str) -> tuple[str | None, list[str]]:
    vals = _assignment_map(text)
    p = _first_int(vals, "p"); A = _first_int(vals, "a_pub", "A", "public_a", "server_public"); b = _first_int(vals, "b", "private_b", "client_private")
    enc = None
    for key in ("enc", "ciphertext", "encrypted", "message"):
        v = vals.get(key, "")
        hx = re.search(r"[0-9a-fA-F]{20,}", v)
        if hx and len(hx.group(0)) % 2 == 0:
            try: enc = bytes.fromhex(hx.group(0)); break
            except ValueError: pass
    if not all(x is not None for x in (p, A, b)) or not enc:
        return None, ["لم يعثر المحلل على p وA وb وenc بصيغ قابلة للتحليل في message.txt."]
    key = pow(A, b, p) & 255
    flag = bytes(x ^ key for x in enc)
    return _valid_flag(flag), ["أعاد صقر حساب shared = A^b mod p ثم عكس XOR بمفتاح shared mod 256."]


def _wiener(n: int, e: int, c: int) -> bytes | None:
    # Continued-fraction Wiener attack. Return plaintext only after confirming
    # the resulting private exponent reproduces a valid integer root.
    a, b = e, n
    conv = []
    while b:
        q, a, b = a // b, b, a % b
        conv.append(q)
    p0, p1, q0, q1 = 0, 1, 1, 0
    for x in conv:
        k, d = x * p1 + p0, x * q1 + q0
        p0, p1, q0, q1 = p1, k, q1, d
        if k == 0: continue
        ed1 = e * d - 1
        if ed1 % k: continue
        phi = ed1 // k
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc < 0: continue
        r = math.isqrt(disc)
        if r * r == disc and (s + r) % 2 == 0:
            m = pow(c, d, n)
            return m.to_bytes((m.bit_length()+7)//8, "big")
    return None


def _rsa_simple(text: str) -> tuple[str | None, list[str]]:
    vals = _assignment_map(text)
    n = _first_int(vals, "n", "modulus"); e = _first_int(vals, "e", "exponent", "public_exponent"); c = _first_int(vals, "c", "ct", "ciphertext", "encrypted")
    if not all(x is not None for x in (n,e,c)): return None, []
    p = _first_int(vals, "p"); q = _first_int(vals, "q")
    if not p or not q:
        if n.bit_length() < 64:
            for d in range(2, min(math.isqrt(n)+1, 2_000_001)):
                if n % d == 0: p,q=d,n//d; break
    if p and q:
        phi=(p-1)*(q-1); d=pow(e,-1,phi); m=pow(c,d,n)
        out=m.to_bytes((m.bit_length()+7)//8,"big")
        flag=_valid_flag(out)
        if flag:return flag,["استخرج صقر عوامل RSA صغيرة/مكشوفة وحسب المفتاح الخاص محليًا."]
    out=_wiener(n,e,c)
    if out and _valid_flag(out):return _valid_flag(out),["نجح اختبار Wiener على الأس الخاص الصغير."]
    # textbook RSA small-message integer root, without modular wraparound.
    if 2 <= e <= 7:
        lo,hi=0,1 << ((c.bit_length()+e-1)//e+1)
        while lo+1<hi:
            mid=(lo+hi)//2
            if pow(mid,e)<=c:lo=mid
            else:hi=mid
        if pow(lo,e)==c:
            out=lo.to_bytes((lo.bit_length()+7)//8,"big")
            if _valid_flag(out):return _valid_flag(out),["فك صقر textbook RSA بأخذ الجذر الصحيح لرسالة صغيرة."]
    return None,["استخرج صقر n/e/c لكن لم يثبت عاملًا أو مفتاحًا قابلًا للاستخدام. لا يدعي نجاح تحليل Coppersmith/Franklin–Reiter دون البيانات والأدوات المناسبة."]


def _aes_ecb(key: bytes, ciphertext: bytes) -> bytes | None:
    if len(key) not in (16, 24, 32) or not ciphertext or len(ciphertext) % 16:
        return None
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
        raw = dec.update(ciphertext) + dec.finalize()
    except ImportError:
        return None
    if raw:
        pad = raw[-1]
        if 1 <= pad <= 16 and raw.endswith(bytes([pad]) * pad): return raw[:-pad]
    return raw.rstrip(b"\x00")


def _hex_values(text: str) -> list[bytes]:
    out=[]
    for value in re.findall(r"(?<![0-9A-Fa-f])(?:0x)?([0-9A-Fa-f]{32,})(?![0-9A-Fa-f])", text):
        if len(value)%2==0:
            try: out.append(bytes.fromhex(value))
            except ValueError: pass
    return out


def _timestamped(text: str) -> tuple[str | None,list[str]]:
    times=[int(x) for x in re.findall(r"(?:around|timestamp|time|unix)\D{0,40}(1\d{8,11})",text,re.I)]
    cts=_hex_values(text)
    if not times or not cts:return None,["لم يعثر صقر على وقت تقريبي ونص مشفر hex صالحين."]
    ct=max(cts,key=len)
    # Match the redacted challenge KDF: first 16 bytes of SHA-256(decimal Unix time).
    for center in times:
        for ts in range(max(0,center-10000),center+10001):
            key=hashlib.sha256(str(ts).encode()).digest()[:16]
            pt=_aes_ecb(key,ct)
            if pt and _valid_flag(pt):return _valid_flag(pt),["جرّب صقر نافذة محدودة حول الطابع الزمني باستخدام SHA-256 ثم AES-ECB."]
    return None,["لم يظهر علم مؤكد ضمن ±10,000 ثانية من الطابع الزمني المذكور."]


def _cryptomaze(text: str) -> tuple[str | None,list[str]]:
    m=re.search(r"(?:initial[_ ]state|state)\s*[:=]\s*\[([\s\S]{1,4096}?)\]",text,re.I)
    t=re.search(r"taps\s*[:=]\s*\[([\d,\s]+)\]",text,re.I)
    if not m or not t:return None,["لم يعثر صقر على حالة LFSR وقائمة taps في output.txt."]
    state=[int(x) for x in re.findall(r"\b[01]\b",m.group(1))]
    taps=[int(x) for x in re.findall(r"\d+",t.group(1))]
    cts=_hex_values(text)
    if len(state)<8 or not taps or not cts:return None,["قيم LFSR أو ciphertext غير مكتملة."]
    bits=[]
    for _ in range(128):
        bits.append(state[0])
        feedback=0
        for i in taps:
            if 0<=i<len(state):feedback^=state[i]
        state=state[1:]+[feedback]
    key=bytes(int("".join(map(str,bits[i:i+8])),2) for i in range(0,128,8))
    pt=_aes_ecb(key,max(cts,key=len))
    if pt and _valid_flag(pt):return _valid_flag(pt),["ولّد صقر 128 بت من LFSR حسب الحالة ومواضع taps ثم فك AES-ECB."]
    return None,["أُعيد توليد المفتاح حسب ترتيب state[0]/taps، لكن AES لم ينتج علمًا؛ تحقق من ترتيب البتات والمكتبة."]


def _jpeg_comments(raw: bytes) -> list[bytes]:
    """Extract JPEG COM (0xFFFE) segments without relying on EXIF/Pillow."""
    out=[]; i=2 if raw.startswith(b"\\xff\\xd8") else 0
    while i+4 <= len(raw):
        if raw[i] != 0xFF:
            i += 1; continue
        while i < len(raw) and raw[i] == 0xFF: i += 1
        if i >= len(raw): break
        marker=raw[i]; i += 1
        if marker in (0xD8,0xD9) or 0xD0 <= marker <= 0xD7: continue
        if marker == 0xDA: break
        if i+2 > len(raw): break
        seglen=int.from_bytes(raw[i:i+2],"big")
        if seglen < 2 or i+seglen > len(raw): break
        payload=raw[i+2:i+seglen]
        if marker == 0xFE: out.append(payload)
        i += seglen
    return out


def _metadata_payloads(image: Path) -> tuple[list[bytes], list[str]]:
    raw=image.read_bytes()
    payloads=list(_jpeg_comments(raw))
    notes=[]
    if payloads: notes.append(f"اكتشف صقر {len(payloads)} حقل JPEG Comment (COM) مباشرة من بنية الملف.")
    try:
        from PIL import Image
        with Image.open(image) as im:
            for value in im.getexif().values():
                if isinstance(value,bytes): payloads.append(value)
                elif isinstance(value,str): payloads.append(value.encode("utf-8","ignore"))
            for value in (im.info or {}).values():
                if isinstance(value,bytes): payloads.append(value)
                elif isinstance(value,str): payloads.append(value.encode("utf-8","ignore"))
    except Exception:
        # Raw JPEG COM parsing above remains available when Pillow is absent.
        pass
    return payloads,notes


def _key_candidates(payloads: list[bytes]) -> list[tuple[bytes,str]]:
    out=[]; seen=set()
    for raw in payloads:
        candidates=[(raw.strip(),"metadata")]
        text=raw.decode("ascii","ignore").strip()
        compact=re.sub(r"\\s+","",text)
        if len(compact)>=100 and len(compact)%2==0 and re.fullmatch(r"[0-9a-fA-F]+",compact):
            try:candidates.append((bytes.fromhex(compact),"hex"))
            except ValueError:pass
        if len(compact)>=100 and re.fullmatch(r"[A-Za-z0-9+/=_-]+",compact):
            try:candidates.append((base64.b64decode(compact+"="*((-len(compact))%4)),"base64"))
            except Exception:pass
        for data,label in candidates:
            if b"-----BEGIN " not in data or b"PRIVATE KEY-----" not in data: continue
            if data not in seen:
                seen.add(data);out.append((data,label))
    return out


def _stegorsa(root: Path, files: dict[str,Path]) -> tuple[str | None,list[str]]:
    image=files.get("image.jpg"); enc=files.get("flag.enc")
    if not image or not enc:return None,["يلزم image.jpg وflag.enc داخل مجلد التحليل."]
    try:payloads,notes=_metadata_payloads(image)
    except Exception as exc:return None,["تعذر قراءة Metadata للصورة: "+str(exc)[:120]]
    keys=_key_candidates(payloads)
    if not keys:return None,notes+["فُحصت JPEG Comments وEXIF/XMP المتاحة، لكن لم يُستخرج PEM private key من Hex/Base64."]
    try:
        from cryptography.hazmat.primitives import serialization, hashes
        from cryptography.hazmat.primitives.asymmetric import padding
    except ImportError:return None,notes+["استُخرج مرشح مفتاح، لكن فك RSA يحتاج مكتبة cryptography."]
    ct=enc.read_bytes()
    paddings=[
        ("PKCS#1 v1.5",padding.PKCS1v15()),
        ("OAEP-SHA1",padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),algorithm=hashes.SHA1(),label=None)),
        ("OAEP-SHA256",padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None)),
    ]
    for keydata,encoding in keys:
        try:key=serialization.load_pem_private_key(keydata,password=None)
        except Exception:continue
        bits=getattr(key,"key_size",None)
        for pad_name,pad in paddings:
            try:pt=key.decrypt(ct,pad)
            except Exception:continue
            flag=_valid_flag(pt)
            if flag:
                notes.extend([
                    f"حوّل صقر Metadata من {encoding} إلى PEM private key صالح.",
                    f"تعرّف على RSA{('-'+str(bits)) if bits else ''} ونجح فك التشفير باستخدام {pad_name}.",
                    "مرّر النص الناتج إلى Flag Hunter وتحقق من صيغة العلم قبل إعلان النجاح.",
                ])
                return flag,notes
    return None,notes+["استُخرج PEM private key، لكن PKCS#1 v1.5 وOAEP-SHA1 وOAEP-SHA256 لم تنتج علمًا مؤكدًا."]

def _c3(contents: list[tuple[str,bytes]]) -> tuple[str | None,list[str]]:
    import ast
    source=next((d.decode("utf-8","ignore") for n,d in contents if n.lower()=="convert.py"),"")
    cipher=next((d.decode("utf-8","ignore").strip() for n,d in contents if n.lower()=="ciphertext"),"")
    if not (source and cipher):return None,["تعذر العثور على ciphertext وconvert.py."]
    # Parse source syntax but inspect only literal table assignments; never run it.
    try:
        tree=ast.parse(source); tables={}
        for node in tree.body:
            if isinstance(node,ast.Assign):
                for target in node.targets:
                    if isinstance(target,ast.Name) and target.id in {"lookup1","lookup2"}:
                        value=ast.literal_eval(node.value)
                        if isinstance(value,str):tables[target.id]=value
        l1=tables.get("lookup1","");l2=tables.get("lookup2","")
    except Exception:return None,["تعذر قراءة lookup tables بأمان من convert.py."]
    if not (l1 and l2):return None,["تعذر العثور على جدولي lookup1/lookup2 في convert.py."]
    if len(l1)!=40 or len(l2)!=40:return None,["طول lookup tables لا يطابق صيغة C3 المتوقعة (40)."]
    out=[];prev=0
    try:
        for ch in cipher:
            idx=l2.index(ch);idx1=(idx+prev)%40;out.append(l1[idx1]);prev=idx1
    except ValueError:return None,["احتوى ciphertext على محرف غير موجود في lookup2."]
    stage2="".join(out)
    # The recovered second stage samples its own source at perfect-cube indices.
    sampled=[];k=1
    while k*k*k<len(stage2):sampled.append(stage2[k*k*k]);k+=1
    inner="".join(sampled)
    wrapper="academy{"+inner+"}"
    return (wrapper,["فك صقر جدولَي الاستبدال دوريًا، ثم حاكى بأمان أخذ محارف stage2 عند مؤشرات المكعبات الكاملة."]) if inner else (None,["فُكّت المرحلة الأولى لكن لم ينتج نصًا للعلم."])


def analyze(challenge_text: str, analysis_dir: Path | str) -> dict:
    slug = _slug(challenge_text)
    if not slug:
        return {"ok":False,"recognized":False,"error":"لم يتعرف صقر على تحدي Cryptography من العنوان."}
    title, required = CHALLENGES[slug]
    root=Path(analysis_dir); present=_files(root)
    missing=[name for name in required if name.lower() not in present]
    result={"ok":True,"recognized":True,"challenge":title,"analyzer":"cryptography","category":("crypto/stego_rsa" if slug=="stegorsa" else "cryptography"),"success":False,
            "flag":None,"files_found":[n for n in required if n.lower() in present],"missing_files":missing,
            "steps":[],"explanation_ar":[],"warnings":[]}
    inline = "\n".join(re.findall(r"`([^`]{8,20000})`", challenge_text or ""))
    contents=[]
    for name in required:
        p=present.get(name.lower())
        if p:
            try:
                data=p.read_bytes()
                if len(data)<=64*1024*1024:
                    contents.append((name,data))
            except OSError: result["warnings"].append(f"تعذر قراءة {name} من مجلد التحليل.")
    result["steps"].append({"phase":"file-scan","count":len(contents)})
    if missing:
        result["warnings"].append("الملفات المطلوبة غير موجودة: "+", ".join(missing)+". احفظها بأسمائها الإنجليزية داخل C:\\Falcon\\analysis ثم أعد الفحص.")
    flag=None
    if slug=="13" and inline:
        flag,_=_text_decodes(inline.encode())
    elif slug in ("rotation","mod 26","interencdec","custom encryption"):
        sources=([(n,d) for n,d in contents if not n.lower().endswith((".py",".jpg",".png"))])
        if inline:sources.append(("challenge text",inline.encode()))
        for name,data in sources:
            flag,_=_text_decodes(data)
            if not flag:flag=_a1z26(data)
            if flag:result["explanation_ar"].append(f"حلّل صقر {name} بتحويلات نصية محدودة وتحقق من صيغة العلم.");break
    elif slug=="the numbers":
        for name,data in contents:
            flag=_a1z26(data)
            if flag:break
        if not flag:result["explanation_ar"].append("الصورة موجودة، لكن لا يتوفر OCR مدمج لقراءة الأرقام تلقائيًا؛ أرفق صورة واضحة أو استخدم OCR محليًا ثم أعد التحليل.")
    elif slug=="stegorsa":
        flag,notes=_stegorsa(root,present);result["explanation_ar"].extend(notes)
    elif slug=="c3":
        flag,notes=_c3(contents);result["explanation_ar"].extend(notes)
    elif slug=="shared secrets":
        text="\n".join(d.decode("utf-8","ignore") for n,d in contents if n.lower().endswith(".txt"))
        flag,notes=_shared_secrets(text);result["explanation_ar"].extend(notes)
    elif slug in ("small trouble","crack the power","cluster rsa"):
        text="\n".join(d.decode("utf-8","ignore") for _,d in contents)
        flag,notes=_rsa_simple(text);result["explanation_ar"].extend(notes)
    elif slug=="timestamped secrets":
        text="\n".join(d.decode("utf-8","ignore") for _,d in contents)
        flag,notes=_timestamped(text);result["explanation_ar"].extend(notes)
    elif slug=="cryptomaze":
        text="\n".join(d.decode("utf-8","ignore") for _,d in contents)
        flag,notes=_cryptomaze(text);result["explanation_ar"].extend(notes)
    else:
        for name,data in contents:
            if data[:200000].find(b"{")>=0:
                flag=_valid_flag(data)
                if flag:break
    if flag:
        result.update(success=True,flag=flag)
        result["explanation_ar"].append("تحقق صقر من وجود صيغة علم معروفة في الناتج المفكوك.")
    elif slug in GUIDES:
        result["explanation_ar"].append(GUIDES[slug])
    else:
        result["warnings"].append("لم يظهر علم مؤكد. راجع شرح الخطوات والأدلة بدل اعتماد تخمين.")
    return result
