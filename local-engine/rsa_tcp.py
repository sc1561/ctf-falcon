"""RSA transcript recovery and bounded protocol-based TCP dispatch for CTFs."""
import math
import re
import socket
import time
import hashcrack_tcp as hc

FIELD = re.compile(r'^\s*(N|modulus|e|exponent|c|ct|ciphertext|cyphertext|encrypted)\s*[:=]\s*(0[xX][0-9a-fA-F]+|[0-9]+)\s*$', re.I | re.M)

def records(text):
    rows=[]; row={}
    for m in FIELD.finditer(text):
        key=m[1].lower()
        key='n' if key in ('n','modulus') else 'e' if key in ('e','exponent') else 'c'
        if key in row:
            if all(k in row for k in ('n','e','c')): rows.append(row)
            row={}
        raw=m[2]
        # Limit integer parsing and expensive modular arithmetic on hostile output.
        if len(raw)>2500: continue
        row[key]=int(raw,16 if raw.lower().startswith('0x') else 10)
        if all(k in row for k in ('n','e','c')):
            if 2 < row['n'] and row['n'].bit_length()<=8192 and 1<row['e']<row['n'] and 0<=row['c']<row['n']:
                rows.append(row)
            row={}
    return rows[:8]

def probable_prime(n):
    if n<2:return False
    for p in (2,3,5,7,11,13,17,19,23,29,31,37):
        if n%p==0:return n==p
    d=n-1;s=0
    while d%2==0:d//=2;s+=1
    for a in (2,3,5,7,11,13,17):
        x=pow(a,d,n)
        if x in (1,n-1):continue
        for _ in range(s-1):
            x=pow(x,2,n)
            if x==n-1:break
        else:return False
    return True

def result():
    return dict(ok=True,recognized=True,challenge='Weak RSA',analyzer='rsa-tcp',success=False,flag=None,files_found=[],missing_files=[],steps=[],explanation_ar=[],warnings=[],recognized_from='rsa-fields',live_verified=False)

def solve(rows, out=None):
    out=out if out is not None else result()
    out['samples']=len(rows)
    for i,row in enumerate(rows):
        n,e,c=row['n'],row['e'],row['c'];p=None;method=None
        for small in (2,3,5,7,11,13,17,19,23,29,31,37):
            if n%small==0:p=small;method='small-factor';break
        if p is None:
            for j,other in enumerate(rows):
                if j==i:continue
                g=math.gcd(n,other['n'])
                if 1<g<n:p=g;method='shared-factor-gcd';break
        if p is None:continue
        q=n//p
        if not probable_prime(p) or not probable_prime(q):
            out['warnings'].append('عُثر على عامل لكن لم تثبت بنية حاصل ضرب عددين أوليين.');continue
        phi=p*(p-1) if p==q else (p-1)*(q-1)
        if math.gcd(e,phi)!=1:
            out['warnings'].append('لا يوجد معكوس للأس العام مع قيمة phi المستعادة.');continue
        d=pow(e,-1,phi);m=pow(c,d,n)
        checked=pow(m,e,n)==c
        step=dict(phase='rsa-decrypt',sample=i+1,method=method,n=str(n),e=e,p=str(p),q=str(q),prime_check='probable-prime',reencryption_verified=checked)
        out['steps'].append(step)
        if not checked:continue
        raw=m.to_bytes(max(1,(m.bit_length()+7)//8),'big')
        decoded=raw.decode('utf-8','replace');step['plaintext']=decoded
        flag=hc.FLAG.search(decoded)
        if flag:
            out.update(success=True,flag=flag[0]);break
    if out['success']:
        out['explanation_ar'].append('استعاد صقر عاملًا ضعيفًا أو مشتركًا، وحسب phi ثم d وفك الرسالة وتحقق بإعادة التشفير. لم يعتمد على اسم التحدي.')
    return out

def analyze_text(text):
    out=solve(records(text))
    if not out['success']:out['warnings'].append('لم يُستخرج علم مؤكد من قيم RSA؛ يلزم عامل قابل للاستعادة أو عينات إضافية.')
    return out

def analyze_tcp(text,root,timeout=30):
    target=hc.endpoint(text);out=result();out['recognized']=False
    if not target:
        out['ok']=False;out['warnings'].append('لم يوجد عنوان TCP صالح.');return out
    out['endpoint']='%s:%s'%target
    deadline=time.monotonic()+timeout;rows=[];total=0
    try:
        for request in range(4):
            remaining=deadline-time.monotonic()
            if remaining<=0:break
            sock=socket.create_connection(target,timeout=min(8,remaining))
            with sock:
                data=b''
                while time.monotonic()<deadline:
                    sock.settimeout(min(2,max(.05,deadline-time.monotonic())))
                    try:chunk=sock.recv(8192)
                    except socket.timeout:
                        if records(data.decode('utf-8','replace')):break
                        continue
                    if not chunk:break
                    data+=chunk;total+=len(chunk)
                    if total>262144:raise ValueError('تجاوزت مخرجات الخدمة حد القراءة.')
                    decoded=data.decode('utf-8','replace')
                    # Dispatch by actual output, retaining the SAME socket and bytes.
                    if request==0 and hc.hashes(decoded) and not re.search(r'^\s*(?:N|modulus)\s*[:=]',decoded,re.I|re.M):
                        return hc.analyze(text,root,timeout=max(.05,deadline-time.monotonic()),_connection=sock,_initial=data)
                    # Require newline after numeric fields while stream is open.
                    completed=decoded[:decoded.rfind('\n')+1]
                    if records(completed):data=completed.encode();break
                current=records(data.decode('utf-8','replace'))
                if not current:
                    out['warnings'].append('لم تظهر حقول N وe وciphertext/cyphertext كاملة.');break
                rows.extend(current);rows=rows[:8]
                out['recognized']=True
                solve(rows,out)
                if out['success']:
                    out['live_verified']=True;return out
                if len(rows)>=8:break
    except (OSError,ValueError) as exc:
        out['ok']=False;out['warnings'].append('تعذر إكمال تحليل TCP: '+str(exc))
    if not out['success']:out['warnings'].append('لم يُستخرج علم مؤكد؛ الاتصال محدود بأربع عينات و30 ثانية، ولا يُفترض أن كل RSA قابل للكسر.')
    return out
