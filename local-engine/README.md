# Falcon Local Engine v2.20.0

محرك محلي اختياري لـ CTF Falcon. يعمل على الجهاز فقط على `127.0.0.1:8765` ولا يفتح خادمًا على الشبكة.

## التشغيل
1. ثبّت Python 3.
2. ثبّت `steghide` على جهاز التدريب.
3. شغّل:
   `python falcon_local.py`
4. اختبار الاتصال:
   افتح `http://127.0.0.1:8765/health`

## تحليل تحدي No FA

ضع `app.py` و`users.db` داخل `C:\Falcon\analysis`. يقرأ الإصدار 2.20.0 هذين الملفين محليًا عبر `POST /no-fa/analyze`، ويفحص قاعدة البيانات للعثور على حساب admin والتحقق من مرشحات SHA-256 المعروفة. لا يرسل بيانات اعتماد إلى المثيل.

بعد تسجيل الدخول في المثيل، يمكن لصق cookie `session` في أداة صقر المحلية. يقرأ `POST /no-fa/decode-session` حقول cookie الموقعة من Flask، ومنها `otp_secret`، من دون التحقق من التوقيع؛ استخدم النتيجة فقط في مختبر CTF المصرح به.

## الواجهات
- `GET /health`
- `POST /no-fa/analyze`
- `POST /no-fa/decode-session`
- `POST /web/session-audit`
- `POST /timeline/analyze`
- `POST /steghide/extract`

الإصدار الأول مقصود أن يكون صغيرًا وآمنًا: لا يوجد endpoint لتنفيذ أوامر عامة، ولا فحص شبكات، ولا رفع ملفات للإنترنت. واجهة CTF Falcon V58 لم يتم تعديلها بعد.


## v0.2 — Browser bridge
يمكن للواجهة إرسال ملف CTF إلى المحرك المحلي بصيغة Base64 بدل الاعتماد على مسار ملف محلي، بحد أقصى 25 MB. عند نجاح Steghide يعيد المحرك:
- اسم الـpayload المستخرج.
- محتوى الـpayload بصيغة Base64 إذا كان حجمه حتى 10 MB.
- Flag مرشح تلقائيًا إذا كان نصيًا.

هذا يمهد لربط GitHub Pages بالمحرك عبر localhost دون إعطاء الواجهة صلاحية تنفيذ أوامر عامة.
