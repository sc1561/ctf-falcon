from pathlib import Path
import hashlib,mimetypes,re,subprocess
from .flag_hunter import hunt
from .crypto import decode_candidates

def strings(data,minlen=4):
    return '\n'.join(x.decode('utf-8','replace') for x in re.findall(rb'[\x20-\x7e]{%d,}'%minlen,data))
def analyze(path=None,text=''):
    result={'mode':'competition','flags':[],'decodes':[],'findings':[]}
    if path:
        p=Path(path); data=p.read_bytes(); txt=strings(data)
        result.update({'name':p.name,'size':len(data),'sha256':hashlib.sha256(data).hexdigest(),'mime':mimetypes.guess_type(p.name)[0] or 'application/octet-stream'})
        result['flags']=hunt(txt)
        result['findings'].append(f'تم استخراج {len(txt.splitlines())} سلسلة نصية قابلة للقراءة')
        for line in txt.splitlines()[:1000]:
            for d in decode_candidates(line):
                if d['flags'] or len(d['value'])<300: result['decodes'].append(d)
        ext=p.suffix.lower()
        if ext in {'.pcap','.pcapng'}: result['route']='PCAP'; result['findings'].append('ملف شبكة: سيُمرر في الإصدار التالي إلى محلل PCAP المتخصص')
        elif ext in {'.jpg','.jpeg','.png','.gif','.bmp'}: result['route']='STEGO'; result['findings'].append('صورة: تم تفعيل مسار فحص الإخفاء والبيانات المضمنة')
        else: result['route']='FORENSICS'
    else:
        result.update({'name':'نص ملصق','route':'CRYPTO/TEXT'})
        result['flags']=hunt(text); result['decodes']=decode_candidates(text)
    for d in result['decodes']:
        for f in d.get('flags',[]):
            if f not in result['flags']: result['flags'].append(f)
    result['status']='FLAG_FOUND' if result['flags'] else 'NO_FLAG_YET'
    return result
