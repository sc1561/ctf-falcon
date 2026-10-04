"""Bounded local glyph OCR for separated numeric A1Z26 image puzzles.

Uses generic rendered digit/brace templates, not challenge-specific strings.
"""
import base64
import io
import json
import re
import statistics
import zlib
from pathlib import Path

def decode_tokens(text):
    tokens=re.findall(r'\d+|[{}]',text)
    if re.sub(r'[\d{}\s]','',text):return None,[]
    mapping=[];out=[]
    for token in tokens:
        if token in '{}':out.append(token)
        elif 1<=int(token)<=26:
            letter=chr(64+int(token));out.append(letter);mapping.append({'number':int(token),'letter':letter})
        else:return None,[]
    value=''.join(out)
    if not re.fullmatch(r'(?:PICOCTF|ACADEMY|FLAG|CTF)\{[A-Z]{1,200}\}',value):return None,mapping
    return value,mapping

def read_image(path):
    from PIL import Image,ImageChops
    with Image.open(path) as source:
        if source.width*source.height>2_000_000:raise ValueError('الصورة أكبر من حد قارئ الأرقام المحلي (مليونا بكسل).')
        im=source.convert('RGB')
    w,h=im.size;pix=im.load()
    points={(x,y) for y in range(h) for x in range(w) if max(pix[x,y])<100}
    boxes=[];clean=Image.new('L',(w,h),255);cp=clean.load()
    while points:
        queue=[points.pop()];component=[]
        while queue:
            x,y=queue.pop();component.append((x,y))
            for p in ((x-1,y),(x+1,y),(x,y-1),(x,y+1)):
                if p in points:points.remove(p);queue.append(p)
        if len(component)<40:continue
        xs=[p[0] for p in component];ys=[p[1] for p in component]
        box=(min(xs),min(ys),max(xs)+1,max(ys)+1)
        if box[3]-box[1]<max(8,h*.035):continue
        boxes.append(box)
        if len(boxes)>180:raise ValueError('رموز كثيرة أو خلفية غير مدعومة؛ يلزم OCR عام أو صورة أوضح.')
        for x,y in component:cp[x,y]=0
    if not boxes:raise ValueError('لم تُكتشف رموز داكنة منفصلة قابلة للقراءة.')
    heights=[b[3]-b[1] for b in boxes];median_h=statistics.median(heights)
    widths=[b[2]-b[0] for b in boxes if b[3]-b[1]<median_h*1.2];median_w=statistics.median(widths or [median_h*.6])
    templates=json.loads(Path(__file__).with_name('numeral_templates.json').read_text())
    template_images={char:[Image.frombytes('L',(32,48),zlib.decompress(base64.b64decode(raw))) for raw in variants] for char,variants in templates.items()}
    glyphs=[]
    for box in boxes:
        crop=clean.crop(box).point(lambda v:255 if v<128 else 0).resize((32,48))
        scores=[]
        for char,variants in template_images.items():
            error=min(sum(ImageChops.difference(crop,t).tobytes())/(255*32*48) for t in variants)
            scores.append((error,char))
        scores.sort();best,char=scores[0];margin=scores[1][0]-best
        if best>.24 or margin<.025:
            raise ValueError('رمز غير واضح؛ لم يعتمد صقر قراءة تخمينية. جرّب صورة أوضح أو OCR عام.')
        glyphs.append({'char':char,'box':list(box),'match_error':round(best,4),'separation_margin':round(margin,4)})
    lines=[]
    for g in sorted(glyphs,key=lambda a:(a['box'][1]+a['box'][3])/2):
        cy=(g['box'][1]+g['box'][3])/2
        for line in lines:
            if abs(cy-line['cy'])<median_h*.5:line['glyphs'].append(g);break
        else:lines.append({'cy':cy,'glyphs':[g]})
    rows=[]
    for line in lines:
        parts=[];previous=None
        for g in sorted(line['glyphs'],key=lambda a:a['box'][0]):
            if previous and (g['box'][0]-previous['box'][2]>median_w*.55 or g['char'] in '{}' or previous['char'] in '{}'):parts.append(' ')
            parts.append(g['char']);previous=g
        rows.append(''.join(parts))
    return '\n'.join(rows),glyphs

def analyze_image(path):
    out={'ok':True,'recognized':True,'challenge':'The Numbers','analyzer':'numbers-ocr','success':False,'flag':None,'files_found':[Path(path).name],'missing_files':[], 'steps':[],'explanation_ar':[],'warnings':[],'recognized_from':'image'}
    try:
        text,glyphs=read_image(path)
        out['steps'].append({'phase':'image-ocr','method':'local-numeral-template-matching','source':Path(path).name,'output':text,'glyphs':glyphs})
        flag,mapping=decode_tokens(text)
        out['steps'].append({'phase':'a1z26','input':text,'mapping':mapping,'output':flag,'case':'uppercase'})
        if flag:
            out.update(success=True,flag=flag)
            out['explanation_ar'].append('قرأ صقر أشكال الأرقام والأقواس محليًا، ثم حوّل الأعداد من 1 إلى 26 إلى حروف كبيرة وحافظ على الأقواس. القراءة من الصورة؛ قبول المنصة يثبت صحة العلم.')
        else:out['warnings'].append('الأرقام المقروءة لم تعطِ صيغة علم مؤكدة؛ راجع القراءة قبل اعتمادها.')
    except (OSError,ValueError,ImportError) as e:
        out['warnings'].append('تعذر إكمال قراءة الأرقام: '+str(e))
    return out
