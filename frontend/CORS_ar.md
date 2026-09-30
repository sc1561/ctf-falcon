# ربط الواجهة بالمحرك: CORS و Private Network Access (مهم)

الواجهة تعمل على `https://sc1561.github.io` بينما المحرك على
`http://127.0.0.1:8765`. هذا طلب **عابر للأصل** (cross-origin)، وإرسال JSON
يجعل المتصفح ينفّذ **preflight** من نوع `OPTIONS` أولًا. بدون الترويسات
التالية سيفشل الطلب بصمت (يظهر كخطأ شبكة في الواجهة).

## ما يجب أن يضيفه معالج المحرك

على مسار `/web/session-audit` أضِف ترويسات CORS في كل استجابة، وعالِج
طلب `OPTIONS` (preflight) بالرد التالي:

```python
ALLOWED_ORIGIN = "https://sc1561.github.io"   # أو "*" أثناء التطوير

def _cors(self):
    origin = self.headers.get("Origin", "")
    allow = ALLOWED_ORIGIN if origin == ALLOWED_ORIGIN else ALLOWED_ORIGIN
    self.send_header("Access-Control-Allow-Origin", allow)
    self.send_header("Vary", "Origin")
    self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
    self.send_header("Access-Control-Allow-Headers", "Content-Type")
    # مطلوب في Chrome عند وصول أصل عام إلى عنوان محلي (loopback):
    self.send_header("Access-Control-Allow-Private-Network", "true")
    self.send_header("Access-Control-Max-Age", "600")

def do_OPTIONS(self):
    if self.path.split("?", 1)[0] == "/web/session-audit":
        self.send_response(204)
        self._cors()
        self.end_headers()
    else:
        self.send_response(404); self.end_headers()
```

وفي `_send_json` (رد POST) استدعِ `self._cors()` قبل `end_headers()`:

```python
def _send_json(self, status, obj):
    data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    self.send_response(status)
    self.send_header("Content-Type", "application/json; charset=utf-8")
    self.send_header("Content-Length", str(len(data)))
    self._cors()                     # <-- أضِف هذا
    self.end_headers()
    self.wfile.write(data)
```

> إن كان محرّكك يخدم أدوات V138 الأخرى عبر الواجهة، فغالبًا لديك CORS بالفعل؛
> تأكّد فقط من إضافة `Access-Control-Allow-Private-Network: true` ومن معالجة
> `OPTIONS`، فهما أكثر ما يُنسى.

## إن استمر المنع (mixed content)

بعض المتصفحات تمنع صفحة https من الاتصال بـ http محلي رغم CORS. الحلول:

1. **الأضمن:** افتح الواجهة محليًا عبر http بدل https — مثلًا اجعل المحرك
   يخدم `index.html` نفسه من `http://127.0.0.1:8765/`، فيصبح الأصل والمحرك
   على http محلي واحد بلا mixed content.
2. أو شغّل خادمًا محليًا بسيطًا للواجهة:
   `python -m http.server 8000` ثم افتح `http://127.0.0.1:8000/`.
3. في Chrome يُسمح عادةً بالوصول إلى loopback من https مع ترويسات PNA أعلاه؛
   جرّب أولًا، فإن مُنع فاستخدم الخيار 1.

## اختبار سريع للـ CORS بعد التعديل

```bash
curl -i -X OPTIONS http://127.0.0.1:8765/web/session-audit \
  -H "Origin: https://sc1561.github.io" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: content-type"
# يجب أن ترى 204 مع ترويسات Access-Control-Allow-* ومنها Allow-Private-Network: true
```
