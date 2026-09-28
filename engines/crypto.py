import base64,binascii,re,urllib.parse
from .flag_hunter import hunt
def decode_candidates(s):
    s=(s or '').strip(); out=[]
    def add(kind,val):
        if val and val!=s and all(x['value']!=val for x in out): out.append({'type':kind,'value':val[:4000],'flags':hunt(val)})
    try:
        if re.fullmatch(r'[A-Za-z0-9+/=\s]+',s) and len(s.replace(' ',''))>=8:
            add('Base64',base64.b64decode(s+'===').decode('utf-8','replace'))
    except: pass
    try:
        if re.fullmatch(r'(?:[0-9A-Fa-f]{2}\s*){4,}',s): add('Hex',bytes.fromhex(s).decode('utf-8','replace'))
    except: pass
    try: add('URL Decode',urllib.parse.unquote(s))
    except: pass
    try:
        if re.fullmatch(r'[01\s]{8,}',s):
            b=''.join(s.split()); add('Binary',''.join(chr(int(b[i:i+8],2)) for i in range(0,len(b)-7,8)))
    except: pass
    return out
