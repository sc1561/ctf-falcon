# دمج مدقّق الجلسات في CTF Falcon — دليل عربي

الهدف: جعل مسار **Old Sessions** يكتمل تلقائيًا واستخراج العلم، دون المساس
ببقية تحسينات `falcon_local.py`. الملف الجديد `web_session_audit.py` **مستقل**
ولا يحتاج أي مكتبة خارجية (Python 3.8+).

## 1) أين تضع الملفات

```
local-engine/
  ├─ falcon_local.py         (ملفك الحالي — نعدّل فيه دالة المعالج فقط)
  └─ web_session_audit.py    (الملف الجديد — انسخه كما هو)
tests/
  ├─ mock_old_sessions.py
  └─ test_web_session_audit.py
Falcon.bat                    (مشغّل ويندوز — بجوار falcon_local.py أو في جذر المشروع)
```

على جهاز الطالب المسار المعتاد: `C:\Falcon\falcon_local.py` و`C:\Falcon\web_session_audit.py`.

## 2) حارس نسخة Python (أعلى `falcon_local.py`)

أضِف هذا في بداية `falcon_local.py` ليعطي رسالة مفهومة إذا شُغّل بنسخة قديمة:

```python
import sys
if sys.version_info < (3, 8):
    sys.stderr.write(
        "[Falcon] يتطلب المحرك Python 3.8 أو أحدث.\n"
        "         شغّله عبر Falcon.bat أو بالمسار الكامل لـ python.exe\n"
    )
    raise SystemExit(1)
```

## 3) استبدال جسم معالج `POST /web/session-audit`

معالجك الحالي يستقبل JSON فيه `url` وينفّذ طلبين GET. استبدل **جسم** المعالج
باستدعاء `run_audit`. أبقِ اسم المسار والعقد كما هو (`POST /web/session-audit`,
JSON فيه `url`). مثال متوافق مع `http.server`:

```python
import json
import web_session_audit  # الملف الجديد بجوار falcon_local.py

# داخل do_POST، عند المسار /web/session-audit:
def handle_web_session_audit(self):
    length = int(self.headers.get("Content-Length", 0) or 0)
    raw = self.rfile.read(length) if length else b"{}"
    try:
        payload = json.loads(raw or b"{}")
    except json.JSONDecodeError:
        return self._send_json(400, {"error": "JSON غير صالح"})

    url = (payload.get("url") or "").strip()
    if not url:
        return self._send_json(400, {"error": "الحقل url مطلوب"})

    try:
        result = web_session_audit.run_audit(
            url,
            # خيارات اختيارية:
            flag_patterns=payload.get("flag_patterns"),          # قائمة أنماط مخصّصة
            timeout=payload.get("timeout", 15),
            demonstrate_register_requirement=payload.get("demo_400", True),
        )
    except Exception as e:  # noqa: BLE001 — نعيد الخطأ كـ JSON للواجهة
        return self._send_json(502, {
            "error": f"تعذّر فحص الهدف: {e}",
            "hint": "تأكد أن رابط الـ Instance ما زال فعّالًا.",
        })

    return self._send_json(200, result)
```

> إذا لم تكن لديك دالة `_send_json`، فهي ببساطة:
> ```python
> def _send_json(self, status, obj):
>     data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
>     self.send_response(status)
>     self.send_header("Content-Type", "application/json; charset=utf-8")
>     self.send_header("Content-Length", str(len(data)))
>     self.end_headers()
>     self.wfile.write(data)
> ```

## 4) شكل الاستجابة (لتحديث الواجهة `frontend/js/web-sessions.js`)

`run_audit` يعيد JSON بهذا الشكل (المفاتيح المهمة للعرض):

```jsonc
{
  "success": true,
  "flag": "picoCTF{...}",
  "flag_source": "step9:GET /",
  "target": "http://host:port/",
  "discovered": {
    "register_fields": ["username","password","conf_password"],
    "sessions_hint": "/sessions",
    "sessions_count": 3,
    "own_session_token": "usr_...",
    "admin_session_token": "adm_...",
    "admin_session_decoded": "{'_permanent': True, 'username': 'admin', 'admin': True}"
  },
  "steps": [
    {
      "n": 1, "method": "GET", "url": "...", "status": 302, "location": "/login",
      "set_cookies": [ { "name": "session", "intent": "set", "notes_ar": [...],
                         "hardening_ar": [...] } ],
      "body_snippet": "…", "notes_ar": [ "…" ]
    }
    // ... بقية الخطوات، ومنها خطوة /login التي تُظهر intent = "deletion"
  ],
  "explanation_ar": [ "1) …", "2) …", "…" ],
  "warnings": []
}
```

اقتراح للواجهة: اعرض `steps` كجدول زمني (كل خطوة: الطريقة/المسار/الحالة/التحويل)،
وأبرِز `set_cookies[].intent` بلونين (`set` أخضر، `deletion` أحمر)، ثم اعرض
`explanation_ar` كشرح مبسّط، وأخيرًا `flag` مع زر نسخ (الطالب ينسخ بنفسه).

> أرسِل لي `frontend/js/web-sessions.js` الحالي وسأعدّله ليقرأ هذا الشكل مباشرةً.

## 5) التشغيل والاختبار

اختبار محلي كامل (يحاكي التحدي ويثبت استخراج العلم):

```bash
python tests/test_web_session_audit.py
```

تشغيل مباشر على Instance حقيقي (سطر أوامر، بدون الواجهة):

```bash
python local-engine/web_session_audit.py http://<host>:<port>/
```

عبر الواجهة: شغّل المحرك بـ `Falcon.bat`، ثم استخدم صفحة Web Sessions كالمعتاد.

## 6) ما الذي تغيّر فعليًا

- إكمال مسار Old Sessions: تسجيل → دخول → اكتشاف `/sessions` → قراءة تسريب
  الجلسات → انتحال جلسة المشرف → استخراج العلم — كله تلقائيًا.
- **حفظ سلسلة الاستجابات كاملة** بلا اتباع تلقائي للتحويلات، لأن إنشاء الكوكي
  في `/` وحذفها في `/login` دليلان يظهران فقط في الاستجابات الوسيطة.
- **إبقاء تصحيح الكوكيز**: `Max-Age <= 0` = طلب حذف؛ Expires ماضٍ = انتهاء؛
  تاريخ بعيد وحده لا يثبت خلود جلسة الخادم؛ غياب HttpOnly/Secure/SameSite
  ملاحظات منفصلة لا تثبت وحدها استخراج العلم.
- **لا قيم مثبّتة**: المضيف/المنفذ/الرموز كلها من الرابط المُدخل، فيقبل أي
  Instance جديدة.
```
