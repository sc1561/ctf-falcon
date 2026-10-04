"""Bounded dictionary recovery for authorized, interactive CTF hash services."""
import hashlib
import re
import socket
import time
from pathlib import Path

ALGORITHMS = {32: ('md5',), 40: ('sha1',), 56: ('sha224',), 64: ('sha256',), 96: ('sha384',), 128: ('sha512',)}
HASH = re.compile(r'(?<![A-Za-z0-9])[a-fA-F0-9]{32,128}(?![A-Za-z0-9])')
FLAG = re.compile(r'(?:picoCTF|academy|flag|CTF)\{[^\r\n{}]{1,512}\}')
COMMON = ('123456','password','123456789','12345678','12345','qwerty','abc123','1234567','111111','123123','admin','letmein','welcome','monkey','dragon','sunshine','football','iloveyou','princess','rockyou')

def endpoint(text):
    m = re.search(r'\bnc\s+([A-Za-z0-9_.-]+)\s+(\d{1,5})\b', text)
    if not m:
        m = re.search(r'tcp://([A-Za-z0-9_.-]+):(\d{1,5})\b', text)
    if m and 0 < int(m[2]) < 65536:
        return m[1], int(m[2])

def hashes(text):
    return [(m[0].lower(), ALGORITHMS[len(m[0])]) for m in HASH.finditer(text) if len(m[0]) in ALGORITHMS]

def words(root):
    yield from (w.encode() for w in COMMON)
    root = Path(root)
    paths = [root/'rockyou.txt', root/'wordlists'/'rockyou.txt', root.parent/'wordlists'/'rockyou.txt', root/'passwords.txt']
    seen = set()
    for p in paths:
        if p in seen: continue
        seen.add(p)
        try:
            with p.open('rb') as f:
                for line in f:
                    word = line.rstrip(b'\r\n')
                    if word and len(word) <= 256: yield word
        except OSError: continue

def recover(digest, algorithms, root, deadline):
    count = 0
    for count, word in enumerate(words(root), 1):
        if count > 2000000 or time.monotonic() >= deadline: break
        for algorithm in algorithms:
            if hashlib.new(algorithm, word).hexdigest() == digest:
                return word, algorithm, count
    return None, None, count

def analyze(text, root, timeout=30, _connection=None, _initial=b''):
    target = endpoint(text)
    result = dict(ok=True, recognized=True, challenge='Interactive hash recovery', analyzer='hashcrack-tcp', success=False, flag=None, files_found=[], missing_files=[], steps=[], explanation_ar=[], warnings=[], recognized_from='tcp-output', live_verified=False)
    deadline = time.monotonic() + timeout
    def crack(digest, algorithms):
        word, algorithm, count = recover(digest, algorithms, root, deadline)
        result['steps'].append(dict(phase='hash-recovery', hash=digest, candidate_algorithms=list(algorithms), algorithm=algorithm, matched=word is not None, attempts=count))
        return word
    if not target:
        for digest, algorithms in hashes(text):
            word = crack(digest, algorithms)
            if word is not None:
                result['steps'][-1]['plaintext'] = word.decode('utf-8', 'replace')
        result['explanation_ar'].append('طول التجزئة يرشّح الخوارزمية ولا يثبتها؛ المطابقة المحلية تتحقق من المرشح. استعادة كلمة لا تعني استخراج العلم.')
        return result
    result['endpoint'] = '%s:%s' % target
    buffer = ''
    rounds = 0
    total = 0
    try:
        with (_connection or socket.create_connection(target, timeout=min(8, timeout))) as sock:
            while time.monotonic() < deadline and rounds < 16:
                sock.settimeout(min(2, max(.05, deadline-time.monotonic())))
                try:
                    if _initial:
                        chunk, _initial = _initial, b''
                    else:
                        chunk = sock.recv(8192)
                except socket.timeout: continue
                if not chunk: break
                total += len(chunk)
                if total > 262144:
                    result['warnings'].append('تجاوزت مخرجات الخدمة الحد المحدد.'); break
                buffer += chunk.decode('utf-8', 'replace')
                flag = FLAG.search(buffer)
                if flag:
                    result.update(success=True, flag=flag[0], live_verified=True); break
                # Wait for a password prompt, including prompts without a newline.
                prompt = re.search(r'(?:password|plaintext|original\s+(?:text|value)|answer)[^\r\n]{0,160}[:?>]\s*$', buffer, re.I)
                candidates = hashes(buffer)
                if not prompt or not candidates: continue
                digest, algorithms = candidates[-1]
                word = crack(digest, algorithms)
                if word is None:
                    result['warnings'].append('لم توجد مطابقة في الكلمات والقوائم المحلية ضمن حدود البحث.'); break
                sock.sendall(word+b'\n')
                result['steps'][-1]['sent'] = True
                rounds += 1
                buffer = ''
    except OSError as e:
        result['ok'] = False
        result['warnings'].append('تعذر الاتصال بالخدمة: '+str(e))
    if not result['success']:
        result['warnings'].append('لم يُستخرج علم مؤكد من الخدمة؛ قد يكون المثيل منتهيًا أو البروتوكول غير مدعوم.')
    result['explanation_ar'].append('اكتشاف التجزئة من مخرجات TCP ثم مطابقة قاموس محلي وإرسال الإجابة ومتابعة المراحل. لا يعتمد على اسم التحدي.')
    return result
