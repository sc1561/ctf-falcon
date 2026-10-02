# CTF Falcon 🛡️
مساعد عربي محلي لتسريع تحليل تحديات CTF التعليمية والمصرح بها.

## V190 — PCAP وWireshark المحلي
- تعرض واجهة GitHub Pages حالة Falcon Local Engine وTShark عند تشغيل الصفحة.
- عند تحليل PCAP/PCAPNG، يرسل المتصفح نسخة الملف إلى `127.0.0.1:8765` فقط؛ لا يغادر الملف جهاز الطالب.
- يستخدم المحرك TShark اختياريًا لإثراء أدلة DNS والبروتوكولات وHTTP Host وTLS SNI، مع بقاء محلل المتصفح كخيار احتياطي.
- يتطلب ذلك Falcon Local Engine 2.50.0 أو أحدث وWireshark مع TShark. تعليمات Windows في `local-engine/WIRESHARK_WINDOWS_ar.md`.

## V1
- واجهة عربية RTL ووضع مسابقة.
- رفع الملفات أو لصق النص.
- Auto-Triage.
- Flag Hunter.
- Base64 / Hex / Binary / URL decoding.
- استخراج strings من الملفات.
- توجيه أولي لمسارات PCAP / Stego / Forensics.

## التشغيل
```bash
chmod +x start.sh
./start.sh
```
ثم افتح `http://127.0.0.1:8000`.

> لا يتصل CTF Falcon بمنصة المسابقة ولا يرسل Flags تلقائيًا؛ الطالب ينسخ العلم بنفسه.
