import re
DEFAULT=[r'(?i)(?:flag|ctf|moe)[_\- ]?\{[^\r\n{}]{1,200}\}',r'(?i)(?:flag|ctf|moe)\{[^\r\n{}]{1,200}\}']
def hunt(text):
    found=[]
    for pat in DEFAULT:
        for m in re.finditer(pat,text or ''):
            v=m.group(0)
            if v not in found: found.append(v)
    return found[:30]
