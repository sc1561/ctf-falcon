/* ==========================================================================
 * CTF Falcon — Web Sessions panel  (frontend/js/web-sessions.js)  v164
 * --------------------------------------------------------------------------
 * وحدة واجهة مستقلة تستدعي المحرك المحلي على /web/session-audit وتعرض:
 *   - جدولًا زمنيًا لكل خطوة (الطريقة/المسار/الحالة/التحويل)
 *   - كوكيز Set-Cookie ملوّنة حسب النية (set أخضر / deletion أحمر) مع ملاحظات
 *   - شرحًا عربيًا مبسّطًا
 *   - العلم مع زر نسخ (الطالب ينسخ بنفسه — لا إرسال تلقائي)
 *
 * الاستخدام:
 *   <div id="falcon-web-sessions"></div>
 *   <script src="frontend/js/web-sessions.js?v=139"></script>
 * أو يدويًا:
 *   FalconWebSessions.mount(document.querySelector('#mycontainer'),
 *                           { engine: 'http://127.0.0.1:8765' });
 * لعرض شكل النتائج بلا محرك (تجريبي):
 *   FalconWebSessions.renderResult(el, FalconWebSessions.SAMPLE);
 * ========================================================================== */
(function (global) {
  "use strict";

  var DEFAULT_ENGINE = "http://127.0.0.1:8765";
  var AUDIT_PATH = "/web/session-audit";

  // ---- حقن التنسيقات مرة واحدة ------------------------------------------- //
  var CSS = `
  .fws{--fws-bg:#07111f;--fws-panel:#0e1c2e;--fws-panel2:#12243a;--fws-line:#1e3a57;
    --fws-txt:#e6f0fa;--fws-muted:#8aa0b8;--fws-green:#1dd3a7;--fws-red:#ff5c7a;
    --fws-amber:#ffcf5c;--fws-accent:#39a0ff;
    direction:rtl;text-align:right;color:var(--fws-txt);
    font-family:"Segoe UI",Tahoma,system-ui,sans-serif;line-height:1.6}
  .fws *{box-sizing:border-box}
  .fws-card{background:var(--fws-panel);border:1px solid var(--fws-line);
    border-radius:14px;padding:16px;margin:12px 0}
  .fws-row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
  .fws-input{flex:1;min-width:220px;background:var(--fws-panel2);color:var(--fws-txt);
    border:1px solid var(--fws-line);border-radius:10px;padding:11px 12px;font-size:15px;
    direction:ltr;text-align:left}
  .fws-area{width:100%;min-height:180px;background:var(--fws-panel2);color:var(--fws-txt);
    border:1px solid var(--fws-line);border-radius:10px;padding:12px;font:14px/1.6 Consolas,monospace;
    direction:auto;text-align:left;resize:vertical}
  .fws-btn{background:var(--fws-accent);color:#04121f;border:0;border-radius:10px;
    padding:11px 18px;font-weight:700;cursor:pointer;font-size:15px}
  .fws-btn:disabled{opacity:.55;cursor:progress}
  .fws-btn.ghost{background:transparent;color:var(--fws-txt);border:1px solid var(--fws-line)}
  .fws-muted{color:var(--fws-muted);font-size:13px}
  .fws-observed{white-space:pre-wrap;overflow-wrap:anywhere;max-height:320px;overflow:auto;
    background:var(--fws-panel2);border:1px solid var(--fws-line);border-radius:8px;padding:12px;
    direction:ltr;text-align:left;font:13px/1.5 Consolas,monospace}
  .fws-flag{background:linear-gradient(90deg,rgba(29,211,167,.16),transparent);
    border:1px solid var(--fws-green);border-radius:12px;padding:14px 16px;margin:12px 0}
  .fws-flag.fail{background:linear-gradient(90deg,rgba(255,92,122,.14),transparent);
    border-color:var(--fws-red)}
  .fws-flag code{font-family:"Cascadia Code",Consolas,monospace;font-size:16px;
    direction:ltr;unicode-bidi:embed}
  .fws-copy{background:var(--fws-green);color:#04121f;border:0;border-radius:8px;
    padding:6px 12px;font-weight:700;cursor:pointer;margin-inline-start:10px}
  .fws-step{border:1px solid var(--fws-line);border-radius:12px;margin:10px 0;overflow:hidden}
  .fws-step-h{display:flex;gap:10px;align-items:center;flex-wrap:wrap;
    padding:10px 12px;background:var(--fws-panel2);cursor:pointer}
  .fws-n{width:26px;height:26px;border-radius:50%;background:var(--fws-line);
    display:flex;align-items:center;justify-content:center;font-weight:700;font-size:13px}
  .fws-method{font-family:monospace;font-weight:700;letter-spacing:.5px}
  .fws-path{font-family:monospace;direction:ltr}
  .fws-status{margin-inline-start:auto;font-weight:700;font-family:monospace}
  .fws-2xx{color:var(--fws-green)} .fws-3xx{color:var(--fws-amber)}
  .fws-4xx{color:var(--fws-red)} .fws-5xx{color:var(--fws-red)}
  .fws-loc{color:var(--fws-muted);font-family:monospace;font-size:13px}
  .fws-step-b{padding:10px 12px;display:none}
  .fws-step.open .fws-step-b{display:block}
  .fws-chip{display:inline-flex;align-items:center;gap:6px;border-radius:999px;
    padding:3px 10px;font-size:12px;font-weight:700;margin:3px 4px 3px 0}
  .fws-chip.set{background:rgba(29,211,167,.15);color:var(--fws-green);
    border:1px solid var(--fws-green)}
  .fws-chip.del{background:rgba(255,92,122,.15);color:var(--fws-red);
    border:1px solid var(--fws-red)}
  .fws-note{color:var(--fws-muted);font-size:13px;margin:3px 0}
  .fws-note::before{content:"•  ";color:var(--fws-accent)}
  .fws-ul{margin:6px 0;padding:0 18px 0 0}
  .fws-ul li{margin:4px 0}
  .fws-warn{color:var(--fws-amber);font-size:13px}
  .fws-err{border:1px solid var(--fws-red);background:rgba(255,92,122,.08);
    border-radius:12px;padding:14px;margin:12px 0}
  .fws-err h4{margin:0 0 8px;color:var(--fws-red)}
  .fws-h{display:flex;align-items:center;gap:8px;font-size:18px;font-weight:800;margin:0 0 4px}
  .fws-block{display:block;white-space:pre-wrap;word-break:break-word;direction:ltr;text-align:left;
    background:rgba(255,255,255,.05);border-radius:8px;padding:8px 10px;margin:4px 0 8px;
    font-family:monospace;font-size:13px;color:var(--fws-txt)}
  `;

  function injectCSS() {
    if (document.getElementById("fws-styles")) return;
    var s = document.createElement("style");
    s.id = "fws-styles";
    s.textContent = CSS;
    document.head.appendChild(s);
  }

  // ---- أدوات صغيرة ------------------------------------------------------- //
  function el(tag, cls, txt) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (txt != null) e.textContent = txt;
    return e;
  }
  function pathOf(u) { try { return new URL(u).pathname || "/"; } catch (e) { return u; } }
  function statusClass(s) {
    if (s >= 200 && s < 300) return "fws-2xx";
    if (s >= 300 && s < 400) return "fws-3xx";
    if (s >= 400 && s < 500) return "fws-4xx";
    return "fws-5xx";
  }

  // ---- عرض العلم --------------------------------------------------------- //
  function renderFlag(res) {
    if (!res.success && res.recognized === false) {
      var info = el("div", "fws-flag fail");
      info.appendChild(el("strong", null, "ℹ️ لم يتعرف صقر على نمط التحدي."));
      info.appendChild(el("div", "fws-muted", "عُرضت المكتشفات الفعلية أدناه، ولم يُنفَّذ أي مسار تلقائيًا."));
      return info;
    }
    var box = el("div", "fws-flag" + (res.success ? "" : " fail"));
    if (res.success) {
      var head = el("div", null);
      head.appendChild(el("strong", null, "✅ العلم المستخرج:"));
      box.appendChild(head);
      var line = el("div", "fws-row");
      var code = el("code", null, res.flag);
      var copy = el("button", "fws-copy", "نسخ");
      copy.onclick = function () {
        navigator.clipboard && navigator.clipboard.writeText(res.flag);
        copy.textContent = "تم النسخ ✓";
        setTimeout(function () { copy.textContent = "نسخ"; }, 1500);
      };
      line.appendChild(code); line.appendChild(copy);
      box.appendChild(line);
      if (res.flag_source)
        box.appendChild(el("div", "fws-muted", "المصدر: " + res.flag_source + " — انسخ العلم بنفسك إلى منصة المسابقة."));
    } else {
      box.appendChild(el("strong", null, "❌ لم يُستخرج العلم تلقائيًا."));
      box.appendChild(el("div", "fws-muted", res.analyzer === "north-south" ? "وصل الطلب إلى الخادم البديل لأن عنوان اتصال المحرك ليس آيسلنديًا. فعّل VPN آيسلنديًا على مستوى الجهاز ثم أعد الفحص." : "راجِع الخطوات أدناه؛ قد يكون شكل التحدي مختلفًا عن Old Sessions."));
    }
    return box;
  }

  // ---- عرض خطوة واحدة ---------------------------------------------------- //
  function renderStep(step) {
    var wrap = el("div", "fws-step");
    var h = el("div", "fws-step-h");
    h.appendChild(el("span", "fws-n", String(step.n)));
    h.appendChild(el("span", "fws-method", step.method));
    h.appendChild(el("span", "fws-path", pathOf(step.url)));
    var st = el("span", "fws-status " + statusClass(step.status),
               step.status + " " + (step.reason || ""));
    h.appendChild(st);
    if (step.location) h.appendChild(el("span", "fws-loc", "→ " + step.location));
    wrap.appendChild(h);

    var b = el("div", "fws-step-b");
    (step.set_cookies || []).forEach(function (c) {
      var del = c.intent === "deletion";
      var chip = el("span", "fws-chip " + (del ? "del" : "set"),
                    "Set-Cookie: " + c.name + " — " + (del ? "حذف" : "تخزين"));
      b.appendChild(chip);
      (c.notes_ar || []).forEach(function (n) { b.appendChild(el("div", "fws-note", n)); });
      (c.hardening_ar || []).forEach(function (n) { b.appendChild(el("div", "fws-note", n)); });
    });
    (step.notes_ar || []).forEach(function (n) { b.appendChild(el("div", "fws-note", n)); });
    wrap.appendChild(b);

    h.onclick = function () { wrap.classList.toggle("open"); };
    return wrap;
  }

  // Read downloadable challenge artifacts from the pasted challenge text.
  // Keep the URL's filename as supplied; students use it when saving locally.
  function challengeArtifacts(text) {
    text = String(text || "");
    var entries = [], seen = Object.create(null);
    var md = /\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/gi, match;
    var links = [];
    while ((match = md.exec(text))) links.push({label: match[1], url: match[2]});
    var bare = /https?:\/\/[^\s<>\]"')]+/gi;
    while ((match = bare.exec(text))) links.push({label: "", url: match[0]});
    links.forEach(function (item) {
      try {
        var url = new URL(item.url.replace(/[.,;!?]+$/, ""));
        if (url.protocol !== "http:" && url.protocol !== "https:") return;
        var path = url.pathname || "";
        var filename = "";
        try { filename = decodeURIComponent(path.split("/").filter(Boolean).pop() || ""); }
        catch (_) { filename = path.split("/").filter(Boolean).pop() || ""; }
        var label = item.label.trim();
        var labelLooksLikeFile = /[\w-]+\.[a-z0-9]{1,8}$/i.test(label);
        var fileLike = url.hostname.toLowerCase().startsWith("challenge-files.") ||
          /\.(?:db|sqlite3?|py|zip|7z|rar|gz|tgz|tar|pcapng?|cap|img|raw|dump|bin|txt|json|log|pdf|docx?|xlsx?)$/i.test(path) ||
          labelLooksLikeFile || /\b(?:download|attachment|file)\b/i.test(label);
        if (!fileLike) return;
        if (!filename || /^(?:download|file|attachment)$/i.test(filename)) filename = labelLooksLikeFile ? label : "ملف مرفق";
        var key = url.href;
        if (seen[key]) return;
        seen[key] = true;
        entries.push({name: filename, url: url.href});
      } catch (_) {}
    });
    // picoCTF 2026 No FA attachments are often pasted as plain "here" labels,
    // with their targets stripped by the textarea. Keep their documented names.
    if (/(?:^|\n)\s*(?:#{1,6}\s*)?No\s*FA(?=\s|$|[—-])/im.test(text)) {
      ["app.py", "users.db"].forEach(function (name) {
        if (!entries.some(function (item) { return item.name.toLowerCase() === name; }))
          entries.push({name: name, url: null});
      });
    }
    return entries;
  }

  function renderArtifactGuidance(text) {
    var files = challengeArtifacts(text);
    if (!files.length) return null;
    var card = el("div", "fws-card fws-artifacts");
    card.appendChild(el("div", "fws-h", "📥 ملفات التحدي المطلوبة"));
    card.appendChild(el("p", null, "نزّل ملفات التحدي من روابطه، ثم احفظها داخل المجلد C:\\Falcon\\analysis بأسمائها وامتداداتها الإنجليزية كما تظهر أدناه. استخدم الملفات من هذا المجلد عند تشغيل التحليل المحلي أو ارفعها في صقر إذا طلب ذلك."));
    var list = el("ul", "fws-ul");
    files.forEach(function (file) {
      var item = el("li");
      if (file.url) {
        var link = el("a", null, file.name);
        link.href = file.url;
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        item.appendChild(link);
      } else {
        item.appendChild(el("code", null, file.name));
      }
      list.appendChild(item);
    });
    card.appendChild(list);
    return card;
  }

  // ---- عرض النتيجة كاملةً ------------------------------------------------ //
  function renderResult(container, res) {
    injectCSS();
    container.classList.add("fws");
    container.innerHTML = "";

    if (res.challenge) {
      var typ = el("div", "fws-card");
      typ.appendChild(el("div", "fws-h", "🎯 نوع التحدي"));
      typ.appendChild(el("div", null, res.challenge + (res.analyzer && res.analyzer !== "none" ? "  (المحلل: " + res.analyzer + ")" : "")));
      container.appendChild(typ);
    }

    if (res.analyzer === "north-south" && !res.success) {
      var geo = el("div", "fws-card");
      geo.appendChild(el("div", "fws-h", "🌍 تجاوز التوجيه الجغرافي"));
      geo.appendChild(el("p", null, "يكشف nginx.conf أن الخادم يوجّه إلى العلم عندما يكون عنوان IP الذي يراه من آيسلندا (IS). طلبات المحرك المحلي تمر عبر اتصال Windows، لذلك إضافة VPN للمتصفح وحده قد لا تكفي."));
      var how = el("ol", "fws-ul");
      ["شغّل VPN يدعم اختيار Iceland / آيسلندا.", "اتصل عبر VPN على مستوى الجهاز، وتأكد أن اتصال الإنترنت في Windows يمر من خلاله.", "ارجع إلى صقر واضغط إعادة الفحص؛ سيعيد المحرك المحلي طلبًا واحدًا إلى المثيل."].forEach(function (s) { how.appendChild(el("li", null, s)); });
      geo.appendChild(how);
      geo.appendChild(el("p", "fws-muted", "تغيير X-Forwarded-For لا يغيّر عنوان IP الذي يستخدمه GeoIP2."));
      var retry = el("button", "fws-btn", "↻ أعد الفحص بعد الاتصال بآيسلندا");
      retry.onclick = function () { global.FalconWebSessionRun(); };
      geo.appendChild(retry);
      container.appendChild(geo);
    }

    var artifactGuidance = renderArtifactGuidance(document.getElementById("text") && document.getElementById("text").value);
    if (artifactGuidance) container.appendChild(artifactGuidance);

    container.appendChild(renderFlag(res));

    // كتلة التعليق: الأصلي + بعد فك ROT13 (لتحديات مثل Crack the Gate)
    var dd = res.discovered || {};
    if (dd.comment_raw || dd.comment_decoded) {
      var cm = el("div", "fws-card");
      cm.appendChild(el("div", "fws-h", "🧩 تعليق المطوّر"));
      if (dd.comment_raw) { cm.appendChild(el("div", "fws-muted", "الأصلي (مُرمّز):")); cm.appendChild(el("code", "fws-block", dd.comment_raw)); }
      if (dd.comment_decoded) { cm.appendChild(el("div", "fws-muted", "بعد فك ROT13:")); cm.appendChild(el("code", "fws-block", dd.comment_decoded)); }
      container.appendChild(cm);
    }

    if (res.discovered) {
      var d = res.discovered, meta = el("div", "fws-card");
      meta.appendChild(el("div", "fws-h", "🔎 ما اكتُشف"));
      var ul = el("ul", "fws-ul");
      // Old Sessions
      if (d.register_fields) ul.appendChild(el("li", null, "حقول التسجيل: " + d.register_fields.join(", ")));
      if (d.sessions_hint) ul.appendChild(el("li", null, "الصفحة المسرِّبة: " + d.sessions_hint + " (عدد الجلسات: " + (d.sessions_count || 0) + ")"));
      if (d.admin_session_decoded) ul.appendChild(el("li", null, "جلسة المشرف: " + d.admin_session_decoded));
      // Crack the Gate
      if (d.dev_header) ul.appendChild(el("li", null, "ترويسة المطوّر: " + d.dev_header.name + ": " + d.dev_header.value));
      if (d.login_path) ul.appendChild(el("li", null, "مسار الدخول: " + d.login_path + (d.response_status ? " (الحالة: " + d.response_status + ")" : "")));
      if (d.email_used) ul.appendChild(el("li", null, "البريد المستخدم: " + d.email_used));
      // n0s4n1ty 1 upload flow
      if (d.file_field) ul.appendChild(el("li", null, "حقل الملف المكتشف: " + d.file_field));
      if (d.upload_status) ul.appendChild(el("li", null, "حالة رفع الملف: HTTP " + d.upload_status));
      if (d.upload_blocked_by_security) ul.appendChild(el("li", null, "اعتراض أمني محلي: " + d.upload_blocked_by_security));
      if (d.upload_path) ul.appendChild(el("li", null, "مسار الملف المرفوع: " + d.upload_path));
      if (d.web_user) ul.appendChild(el("li", null, "مستخدم خادم الويب: " + d.web_user));
      if (typeof d.sudo_nopasswd === "boolean") ul.appendChild(el("li", null, "sudo بلا كلمة مرور: " + (d.sudo_nopasswd ? "نعم" : "لا")));
      // head-dump
      if (d.documentation_link) ul.appendChild(el("li", null, "رابط توثيق API المكتشف: " + d.documentation_link));
      if (d.swagger_source) ul.appendChild(el("li", null, "مصدر تعريف Swagger: " + d.swagger_source));
      if (d.heapdump_path) ul.appendChild(el("li", null, "مسار heapdump الموثق: " + d.heapdump_path));
      if (d.heapdump_status) ul.appendChild(el("li", null, "حالة تنزيل heap snapshot: HTTP " + d.heapdump_status + (d.heapdump_bytes ? " (" + d.heapdump_bytes + " bytes)" : "")));
      if (d.artifact_filename) ul.appendChild(el("li", null, "اسم الملف: " + d.artifact_filename));
      // غير معروف
      if (d.emails && d.emails.length) ul.appendChild(el("li", null, "عناوين بريد في الصفحة: " + d.emails.join(", ")));
      if (d.decoded_comments && d.decoded_comments.length)
        d.decoded_comments.forEach(function (c) { ul.appendChild(el("li", null, "تعليق (ROT13): " + c)); });
      if (ul.childNodes.length) { meta.appendChild(ul); container.appendChild(meta); }
    }

    var steps = el("div", "fws-card");
    steps.appendChild(el("div", "fws-h", "🧭 سلسلة الاستجابات (بلا اتباع تلقائي للتحويلات)"));
    (res.steps || []).forEach(function (s) { steps.appendChild(renderStep(s)); });
    container.appendChild(steps);

    if (res.explanation_ar && res.explanation_ar.length) {
      var ex = el("div", "fws-card");
      ex.appendChild(el("div", "fws-h", "📘 الشرح"));
      var ul2 = el("ul", "fws-ul");
      res.explanation_ar.forEach(function (line) { ul2.appendChild(el("li", null, line)); });
      ex.appendChild(ul2);
      container.appendChild(ex);
    }

    if (res.warnings && res.warnings.length) {
      var w = el("div", "fws-card");
      w.appendChild(el("div", "fws-h", "⚠️ تنبيهات"));
      res.warnings.forEach(function (line) { w.appendChild(el("div", "fws-warn", "! " + line)); });
      container.appendChild(w);
    }
  }

  // ---- رسالة خطأ الاتصال بالمحرك ----------------------------------------- //
  function renderEngineError(container, engine, detail) {
    container.innerHTML = "";
    var box = el("div", "fws-err");
    box.appendChild(el("h4", null, "تعذّر الاتصال بالمحرك المحلي"));
    box.appendChild(el("div", null, "الواجهة حاولت الوصول إلى: " + engine + AUDIT_PATH));
    var ul = el("ul", "fws-ul");
    ul.appendChild(el("li", null, "تأكّد أن المحرك يعمل: شغّل Falcon.bat (يستمع على 127.0.0.1:8765)."));
    ul.appendChild(el("li", null, "إن كانت الواجهة على https (GitHub Pages)، فقد يمنع المتصفح الاتصال بـ http المحلي — يحتاج المحرك إلى ترويسات CORS و Access-Control-Allow-Private-Network (انظر INTEGRATION_ar.md)."));
    ul.appendChild(el("li", null, "بديل مضمون: افتح الواجهة محليًا عبر http بدل https، أو اجعل المحرك يخدم الواجهة نفسها."));
    box.appendChild(ul);
    if (detail) box.appendChild(el("div", "fws-muted", "التفاصيل: " + detail));
    container.appendChild(box);
  }

  // ---- الاستدعاء الفعلي للمحرك ------------------------------------------- //
  function audit(engine, url, opts) {
    opts = opts || {};
    var body = { url: url, challenge_text: opts.challenge_text || "" };
    if(opts.email) body.email = opts.email;
    if (opts.flag_patterns) body.flag_patterns = opts.flag_patterns;
    return fetch(engine.replace(/\/+$/, "") + AUDIT_PATH, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    }).then(function (r) {
      return r.json().then(function (j) {
        if (!r.ok && !j.steps) throw new Error(j.error || ("HTTP " + r.status));
        return j;
      });
    });
  }

  // ---- تركيب اللوحة ------------------------------------------------------ //
  function mount(root, opts) {
    opts = opts || {};
    injectCSS();
    var engine = opts.engine || DEFAULT_ENGINE;

    root.classList.add("fws");
    root.innerHTML = "";

    var card = el("div", "fws-card");
    card.appendChild(el("div", "fws-h", "🌐 Web Sessions — تدقيق الجلسات (Old Sessions)"));
    card.appendChild(el("div", "fws-muted", "أدخل رابط الـ Instance للتحدي المصرّح به، وسيُكمل صقر المسار ويستخرج العلم. لا يُرسل العلم تلقائيًا."));

    var row = el("div", "fws-row");
    row.style.marginTop = "10px";
    var input = el("input", "fws-input");
    input.type = "text";
    input.placeholder = "http://host:port/";
    var btn = el("button", "fws-btn", "🚀 افحص");
    row.appendChild(input); row.appendChild(btn);
    card.appendChild(row);

    var out = el("div", null);
    card.appendChild(out);
    root.appendChild(card);

    function run() {
      var url = (input.value || "").trim();
      if (!url) { input.focus(); return; }
      btn.disabled = true; btn.textContent = "…جارٍ الفحص";
      out.innerHTML = '<div class="fws-muted" style="margin-top:12px">يفحص صقر التحدي…</div>';
      audit(engine, url, opts)
        .then(function (res) { renderResult(out, res); })
        .catch(function (e) {
          // فشل fetch الشبكي يظهر عادةً كـ TypeError
          renderEngineError(out, engine, e && e.message);
        })
        .then(function () { btn.disabled = false; btn.textContent = "🚀 افحص"; });
    }
    btn.onclick = run;
    input.addEventListener("keydown", function (ev) { if (ev.key === "Enter") run(); });

    return { run: run, setEngine: function (u) { engine = u; } };
  }

  // ---- التركيب التلقائي إن وُجد الحاوي ------------------------------------ //
  function auto() {
    var host = document.getElementById("falcon-web-sessions");
    if (host) mount(host, {});
  }
  if (document.readyState === "loading")
    document.addEventListener("DOMContentLoaded", auto);
  else auto();

  // ---- عيّنة لعرض الشكل بلا محرك ----------------------------------------- //
  var SAMPLE = {
    success: true,
    flag: "picoCTF{c00ki3s_4nd_s3ssi0ns_2058}",
    flag_source: "step9:GET /",
    discovered: {
      register_fields: ["username", "password", "conf_password"],
      sessions_hint: "/sessions", sessions_count: 3,
      admin_session_decoded: "{'_permanent': True, 'username': 'admin', 'admin': True}"
    },
    steps: [
      { n: 1, method: "GET", url: "http://host/", status: 302, reason: "Found", location: "/login",
        set_cookies: [{ name: "session", intent: "set",
          notes_ar: ["Expires في المستقبل (~31 سنة): كوكي دائمة على المتصفح.",
                     "تنبيه: التاريخ البعيد وحده لا يثبت أن جلسة المصادقة لا تنتهي على الخادم."],
          hardening_ar: [] }],
        notes_ar: ["طلب الصفحة الرئيسية دون جلسة: نتوقع تحويلًا إلى /login وإنشاء كوكي."] },
      { n: 2, method: "GET", url: "http://host/login", status: 200, reason: "OK", location: null,
        set_cookies: [{ name: "session", intent: "deletion",
          notes_ar: ["Max-Age <= 0: هذا طلب حذف للكوكي (وليست دائمة).",
                     "القيمة فارغة مع نية الحذف: إزالة واضحة."], hardening_ar: [] }],
        notes_ar: ["صفحة /login تحذف كوكي الجلسة — دليل يظهر فقط بلا اتباع تلقائي للتحويل."] },
      { n: 3, method: "GET", url: "http://host/register", status: 200, reason: "OK", location: null,
        set_cookies: [], notes_ar: ["الحقول المكتشفة: username, password, conf_password."] },
      { n: 4, method: "POST", url: "http://host/register", status: 400, reason: "Bad Request",
        location: null, set_cookies: [], notes_ar: ["إثبات المتطلب: بدون conf_password → 400."] },
      { n: 5, method: "POST", url: "http://host/register", status: 302, reason: "Found",
        location: "/login", set_cookies: [], notes_ar: ["تسجيل صحيح → تحويل إلى /login."] },
      { n: 6, method: "POST", url: "http://host/login", status: 302, reason: "Found", location: "/",
        set_cookies: [{ name: "session", intent: "set", notes_ar: ["كوكي جلسة طويلة للحساب التجريبي."], hardening_ar: [] }],
        notes_ar: ["تسجيل الدخول ناجح."] },
      { n: 7, method: "GET", url: "http://host/", status: 200, reason: "OK", location: null,
        set_cookies: [], notes_ar: ["التلميح المكتشف: /sessions."] },
      { n: 8, method: "GET", url: "http://host/sessions", status: 200, reason: "OK", location: null,
        set_cookies: [], notes_ar: ["تسريب جلسات الخادم (3 إدخالات) ومنها جلسة المشرف."] },
      { n: 9, method: "GET", url: "http://host/", status: 200, reason: "OK", location: null,
        set_cookies: [], notes_ar: ["انتحال جلسة المشرف بضبط كوكي session على رمزه ثم طلب /."] }
    ],
    explanation_ar: [
      "1) الصفحة الرئيسية تُنشئ كوكي جلسة ثم تُحوّل إلى /login.",
      "2) /login تحذف الكوكي (Max-Age=0) — لهذا لا نتبع التحويلات تلقائيًا.",
      "3) أنشأنا حسابًا تجريبيًا (conf_password مطلوب، وإلا 400).",
      "4) سجّلنا الدخول وحصلنا على كوكي جلسة طويلة.",
      "5) الصفحة الرئيسية تكشف تلميحًا لصفحة /sessions.",
      "6) /sessions تسرّب جلسات الخادم ومنها جلسة المشرف.",
      "7) استبدلنا كوكي جلستنا برمز جلسة المشرف فأصبحنا مشرفين.",
      "8) استُخرج العلم من صفحة / بصفة مشرف."
    ],
    warnings: []
  };

  global.FalconWebSessions = {
    mount: mount, renderResult: renderResult, audit: audit,
    DEFAULT_ENGINE: DEFAULT_ENGINE, SAMPLE: SAMPLE,
    challengeArtifacts: challengeArtifacts,
    renderArtifactGuidance: renderArtifactGuidance
  };

  var previous = global.FalconRogueTowerRun || global.FalconSmartRun;
  var busy = false;
  function challengeUrl() {
    var input = document.getElementById('text');
    var pasted = ((input && input.value) || '').replace(/(https?)\\:/gi, '$1:');
    var matches = pasted.match(/https?:\/\/[^\s<>\]"')]+/gi) || [];
    var artifactFallback = null;
    for (var i=0; i<matches.length; i++) {
      try {
        var u = new URL(matches[i]);
        if (!(u.hostname.endsWith('.cylabacademy.net') || u.hostname.endsWith('.cylabacademy.org'))) continue;
        if (u.hostname.toLowerCase().startsWith('challenge-files.')) {
          if (!artifactFallback) artifactFallback = u.href;
          continue;
        }
        return u.href;
      } catch (_) {}
    }
    return artifactFallback;
  }
  function isHashgatePrompt(text) {
    return /(?:^|\n)\s*(?:#{1,6}\s*)?Hashgate(?=\s|$|[—-])/im.test(String(text || '')) &&
      /(?:picoCTF|Web\s+Exploitation|employee|organisation|organization)/i.test(String(text || ''));
  }
  function isCredentialStuffingPrompt(text) {
    text=String(text||'');
    return /(?:^|\n)\s*(?:#{1,6}\s*)?Credential\s+Stuffing(?=\s|$|[—-])/im.test(text) &&
      /creds-dump\.txt/i.test(text) && /\bnc\s+[a-z0-9.-]+\.cylabacademy\.(?:net|org)\s+\d{1,5}\b/i.test(text);
  }
  function isUndoPrompt(text) {
    text=String(text||'');
    var titled=/(?:^|\n)\s*(?:#{1,6}\s*)?Undo(?=\s|$|[—-])/im.test(text) &&
      /(?:picoCTF|chatelaine\.cylabacademy|transformation|transform|\bnc\s)/i.test(text);
    var announcement=/reverse\s+a\s+series\s+of\s+Linux\s+text\s+transformations/i.test(text) &&
      /\bnc\s+[a-z0-9.-]+\.cylabacademy\.(?:net|org)\s+\d{1,5}\b/i.test(text) &&
      /\btr\b.{0,120}(?:command\s+documentation|man7\.org)|(?:documentation|man7\.org).{0,120}\btr\b/is.test(text);
    return titled||announcement;
  }
  function isSecretBoxPrompt(text) {
    text=String(text||'').replace(/(https?)\\:/gi,'$1:');
    return /this secret box is designed to conceal your secrets/i.test(text) &&
      /https?:\/\/[a-z0-9.-]+\.cylabacademy\.(?:net|org)(?::\d+)?\//i.test(text);
  }
  function isSqlMap1Prompt(text) {
    text=String(text||'').replace(/(https?)\\:/gi,'$1:');
    return /(?:^|\n)\s*(?:#{1,6}\s*)?Sql\s+Map1(?=\s|$|[—-])/im.test(text) &&
      /md5/i.test(text) && /search/i.test(text) &&
      /https?:\/\/[a-z0-9.-]+\.cylabacademy\.(?:net|org)(?::\d+)?\//i.test(text);
  }
  function isFoolLockoutPrompt(text) {
    text=String(text||'').replace(/(https?)\\:/gi,'$1:');
    return /(?:^|\n)\s*(?:#{1,6}\s*)?Fool\s+the\s+Lockout(?=\s|$|[—-])/im.test(text) &&
      /creds-dump\.txt/i.test(text) && /app\.py/i.test(text) &&
      /https?:\/\/[a-z0-9.-]+\.cylabacademy\.(?:net|org)(?::\d+)?\//i.test(text);
  }
  function undoTarget(text) {
    var m=String(text||'').match(/\b(?:nc|ncat)\s+([a-z0-9.-]+)\s+(\d{1,5})\b/i);
    return m?{host:m[1].toLowerCase(),port:Number(m[2])}:null;
  }
  async function runUndoChallenge(text) {
    if(busy)return false;
    busy=true;
    var out=document.getElementById('result');out.classList.remove('hidden');out.classList.add('fws');injectCSS();out.innerHTML='';
    var card=el('div','fws-card');
    card.appendChild(el('div','fws-h','🧭 شرح تحدي TCP: Undo'));
    card.appendChild(el('p',null,'هذا التحدي يطلب عكس تحويلات نصية. يستطيع المحرك المحلي الاتصال بخدمة التحدي والإجابة عن التحويلات المعروفة مرحلةً مرحلة، ثم يعرض سجل الحل.'));
    var target=undoTarget(text);
    var command=target?'ncat '+target.host+' '+target.port:'ncat اسم_الخادم رقم_المنفذ';
    if(target)card.appendChild(el('p','fws-muted','الهدف الذي سيستخدمه صقر: '+target.host+':'+target.port+'. صقر يرسل فقط أوامر التحويل المعروفة كإجابات لتحدي CTF؛ لا يشغّلها على جهازك.'));
    card.appendChild(el('p','fws-muted','إذا احتجت الاتصال اليدوي في Windows: ثبّت Nmap مع Ncat ثم نفّذ '+command+'.'));
    var area=el('textarea','fws-area');area.placeholder='الصق هنا خرج الاتصال وتعليمات المراحل…';
    var connect=el('button','fws-btn','🔌 اتصل واجلب خرج الخدمة');
    var button=el('button','fws-btn','🧠 اشرح التحويلات واعكس ترتيبها');
    var status=el('div','fws-note','يتطلب Falcon Local Engine 2.32.0 أو أحدث.');
    card.appendChild(connect);card.appendChild(area);card.appendChild(button);card.appendChild(status);out.appendChild(card);
    connect.onclick=async function(){
      if(!target){status.textContent='لم يجد صقر هدف nc في وصف التحدي.';return;}
      connect.disabled=true;button.disabled=true;status.textContent='يتصل بالخدمة ويجيب عن التحويلات المعروفة مرحلةً مرحلة…';
      try {
        var engine=(location.hostname==='127.0.0.1'||location.hostname==='localhost')?location.origin:DEFAULT_ENGINE;
        var health=await fetch(engine+'/health',{cache:'no-store'}).then(function(r){return r.json();});
        var v=(health.version||'0.0.0').split('.').map(Number);
        if(v[0]<2||(v[0]===2&&v[1]<32))throw new Error('حدّث المحرك المحلي إلى 2.32.0 ثم أعد تشغيله.');
        var response=await fetch(engine+'/undo/solve',{method:'POST',headers:{'Content-Type':'application/json'},
          body:JSON.stringify({confirm:true,challenge_text:text}),cache:'no-store'});
        var data=await response.json();if(!response.ok||!data.ok)throw new Error(data.error||'تعذر حل مراحل الخدمة.');
        button.hidden=true;
        area.value=data.transcript||'';area.readOnly=true;
        status.textContent=data.flag?'✅ أكمل صقر المراحل واستخرج العلم من '+data.target+'.':(data.error||'وصل صقر إلى نهاية الخرج دون ظهور العلم.');
        (data.steps||[]).forEach(function(step){var row=el('div','fws-step open');var head=el('div','fws-step-h');head.appendChild(el('span','fws-n',String(step.stage)));head.appendChild(el('strong',null,'التحويل: '+step.operation));row.appendChild(head);var body=el('div','fws-step-b');body.style.display='block';body.appendChild(el('p',null,'أرسل صقر الأمر التالي كإجابة لمرحلة التحدي:'));body.appendChild(el('code','fws-path',step.command));row.appendChild(body);out.appendChild(row);});
        if(data.flag){var flagBox=el('div','fws-flag');flagBox.appendChild(el('strong',null,'🚩 العلم المستخرج:'));var flagRow=el('div','fws-row');flagRow.appendChild(el('code',null,data.flag));var copy=el('button','fws-copy','نسخ');copy.onclick=function(){navigator.clipboard&&navigator.clipboard.writeText(data.flag);copy.textContent='تم النسخ ✓';};flagRow.appendChild(copy);flagBox.appendChild(flagRow);out.appendChild(flagBox);}
        var details=el('details','fws-card');details.appendChild(el('summary',null,'عرض سجل الجلسة'));var raw=el('pre','fws-observed');raw.textContent=data.transcript||'';details.appendChild(raw);out.appendChild(details);
      }catch(e){status.textContent='تعذر الحل تلقائيًا: '+e.message+' — يمكنك استخدام أمر Ncat أعلاه ولصق الخرج هنا.';connect.disabled=false;button.disabled=false;button.hidden=false;}
    };
    button.onclick=async function(){
      if(!area.value.trim()){status.textContent='الصق رسائل الخادم أولًا حتى يشرح صقر التحويلات الموجودة فعلًا.';return;}
      button.disabled=true;status.textContent='يجري تحليل التلميحات محليًا…';
      try {
        var engine=(location.hostname==='127.0.0.1'||location.hostname==='localhost')?location.origin:DEFAULT_ENGINE;
        var health=await fetch(engine+'/health',{cache:'no-store'}).then(function(r){return r.json();});
        var v=(health.version||'0.0.0').split('.').map(Number);
        if(v[0]<2||(v[0]===2&&v[1]<32))throw new Error('حدّث المحرك المحلي إلى 2.32.0 ثم أعد تشغيله.');
        var response=await fetch(engine+'/undo/analyze',{method:'POST',headers:{'Content-Type':'application/json'},
          body:JSON.stringify({challenge_text:text,transcript:area.value}),cache:'no-store'});
        var data=await response.json();if(!response.ok||!data.ok)throw new Error(data.error||'تعذر تحليل النص.');
        status.textContent=data.flag?'✅ استخرج صقر العلم بتطبيق التحويلات العكسية محليًا.':(data.inverse_steps.length?'رتّب صقر التحويلات المعروفة لعكسها من الأخيرة إلى الأولى.':'لم تظهر أسماء تحويلات واضحة في النص بعد.');
        data.inverse_steps.forEach(function(step){
          var row=el('div','fws-step open');var head=el('div','fws-step-h');
          head.appendChild(el('span','fws-n',String(step.stage)));head.appendChild(el('strong',null,'اعكس: '+step.operation));
          row.appendChild(head);var body=el('div','fws-step-b');body.style.display='block';
          body.appendChild(el('p',null,step.explanation_ar));
          if(step.inverse_command)body.appendChild(el('code','fws-path',step.inverse_command));
          row.appendChild(body);out.appendChild(row);
        });
        (data.explanation_ar||[]).forEach(function(t){out.appendChild(el('p','fws-muted',t));});
        (data.warnings||[]).forEach(function(t){out.appendChild(el('p','fws-note',t));});
        if(data.flag){
          var flagBox=el('div','fws-flag');flagBox.appendChild(el('strong',null,'🚩 العلم المستخرج:'));
          var flagRow=el('div','fws-row');flagRow.appendChild(el('code',null,data.flag));
          var copy=el('button','fws-copy','نسخ');copy.onclick=function(){navigator.clipboard&&navigator.clipboard.writeText(data.flag);copy.textContent='تم النسخ ✓';};
          flagRow.appendChild(copy);flagBox.appendChild(flagRow);out.appendChild(flagBox);
        }else if(data.recovered_text){
          var recovered=el('div','fws-card');recovered.appendChild(el('strong',null,'النص بعد عكس التحويلات المعروفة:'));
          var decoded=el('pre','fws-observed');decoded.textContent=data.recovered_text;recovered.appendChild(decoded);out.appendChild(recovered);
        }
        if(data.transcript_preview){
          var details=el('details','fws-card');details.appendChild(el('summary',null,'عرض خرج الخدمة الذي حلّله صقر'));
          var raw=el('pre','fws-observed');raw.textContent=data.transcript_preview;details.appendChild(raw);out.appendChild(details);
        }
      }catch(e){status.textContent='تعذر إكمال الشرح: '+e.message;button.disabled=false;}
    };
    out.scrollIntoView({behavior:'smooth',block:'start'});busy=false;return false;
  }
  async function runSecretBoxChallenge(text) {
    if(busy)return false;
    busy=true;
    var out=document.getElementById('result');out.classList.remove('hidden');out.classList.add('fws');injectCSS();out.innerHTML='';
    var card=el('div','fws-card');card.appendChild(el('div','fws-h','🔐 تحدي Secret Box'));
    card.appendChild(el('p',null,'قرأ صقر مصدر التطبيق المرفق وحدد مسار التسجيل والدخول وإنشاء السر. بعد ضغط الزر سينشئ حسابًا تدريبيًا مؤقتًا على المثيل المحدد، ثم يستخرج سر المشرف إن ظهر في حسابك.'));
    card.appendChild(el('p','fws-muted','يستخدم صقر عنوان Cylab Academy الوارد في وصف التحدي فقط. لا يعرض كلمة مرور الحساب المؤقت أو رمز الجلسة.'));
    var button=el('button','fws-btn','▶ ابدأ استخراج سر المشرف');var status=el('div','fws-note','يتطلب Falcon Local Engine 2.33.0 أو أحدث.');
    card.appendChild(button);card.appendChild(status);out.appendChild(card);
    button.onclick=async function(){
      button.disabled=true;status.textContent='يسجل حسابًا تدريبيًا ويختبر مسار إنشاء السر في المثيل…';
      try {
        var engine=(location.hostname==='127.0.0.1'||location.hostname==='localhost')?location.origin:DEFAULT_ENGINE;
        var health=await fetch(engine+'/health',{cache:'no-store'}).then(function(r){return r.json();});
        var v=(health.version||'0.0.0').split('.').map(Number);
        if(v[0]<2||(v[0]===2&&v[1]<33))throw new Error('حدّث المحرك المحلي إلى 2.33.0 ثم أعد تشغيله.');
        var response=await fetch(engine+'/secret-box/solve',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({confirm:true,challenge_text:text}),cache:'no-store'});
        var data=await response.json();if(!response.ok||!data.ok)throw new Error(data.error||'تعذر إكمال مسار Secret Box.');
        status.textContent=data.flag?'✅ استخرج صقر العلم من '+data.target+'.':(data.error||'اكتمل الفحص دون ظهور العلم.');
        (data.steps||[]).forEach(function(step){var row=el('p','fws-muted');row.textContent=step.method+' '+step.path+' — HTTP '+step.status;out.appendChild(row);});
        (data.explanation_ar||[]).forEach(function(line){out.appendChild(el('p','fws-muted',line));});
        if(data.flag){var box=el('div','fws-flag');box.appendChild(el('strong',null,'🚩 العلم المستخرج:'));var r=el('div','fws-row');r.appendChild(el('code',null,data.flag));var copy=el('button','fws-copy','نسخ');copy.onclick=function(){navigator.clipboard&&navigator.clipboard.writeText(data.flag);copy.textContent='تم النسخ ✓';};r.appendChild(copy);box.appendChild(r);out.appendChild(box);}
        (data.warnings||[]).forEach(function(w){out.appendChild(el('p','fws-note',w));});
      }catch(e){status.textContent='تعذر الحل: '+e.message;button.disabled=false;}
    };
    busy=false;out.scrollIntoView({behavior:'smooth',block:'start'});return false;
  }
  async function runSqlMap1Challenge(text) {
    if(busy)return false;
    busy=true;
    var out=document.getElementById('result');out.classList.remove('hidden');out.classList.add('fws');injectCSS();out.innerHTML='';
    var card=el('div','fws-card');card.appendChild(el('div','fws-h','🗄️ تحدي Sql Map1'));
    card.appendChild(el('p',null,'يفحص صقر نموذج الدخول والبحث في المثيل، ينشئ حسابًا تدريبيًا، ثم يختبر حقن SQL المحدود لاستخراج تجزئة حساب ctf-player ومطابقتها محليًا.'));
    card.appendChild(el('p','fws-muted','يرسل صقر الطلبات إلى مثيل Cylab Academy المذكور فقط. لا يرسل تجزئات إلى CrackStation أو خدمة خارجية ولا يعرض كلمات المرور أو معرّفات الجلسات.'));
    var button=el('button','fws-btn','▶ حلّل البحث واستخرج العلم');var status=el('div','fws-note','يتطلب Falcon Local Engine 2.35.0 أو أحدث.');
    card.appendChild(button);card.appendChild(status);out.appendChild(card);
    button.onclick=async function(){
      button.disabled=true;status.textContent='يتحقق صقر من الهدف ويبدأ فحص النماذج…';
      try {
        var engine=(location.hostname==='127.0.0.1'||location.hostname==='localhost')?location.origin:DEFAULT_ENGINE;
        var health=await fetch(engine+'/health',{cache:'no-store'}).then(function(r){return r.json();});
        var v=(health.version||'0.0.0').split('.').map(Number);
        if(v[0]<2||(v[0]===2&&v[1]<35))throw new Error('حدّث المحرك المحلي إلى 2.35.0 ثم أعد تشغيله.');
        var response=await fetch(engine+'/sql-map1/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({confirm:true,challenge_text:text}),cache:'no-store'});
        var started=await response.json();if(!response.ok||!started.ok)throw new Error(started.error||'تعذر بدء تحليل Sql Map1.');
        var data=null,deadline=Date.now()+8*60*1000;
        while(Date.now()<deadline){
          await new Promise(function(resolve){setTimeout(resolve,900);});
          var poll=await fetch(engine+'/sql-map1/status?job_id='+encodeURIComponent(started.job_id),{cache:'no-store'});
          var job=await poll.json();if(!poll.ok||!job.ok)throw new Error(job.error||'انقطع تحديث حالة التحليل.');
          if(job.state==='running'){status.textContent=job.message||'يجري فحص البحث…';continue;}
          data=job.result;break;
        }
        if(!data)throw new Error('تجاوز التحليل المهلة؛ تحقق من اتصال المثيل ثم أعد المحاولة.');
        if(!data.ok)throw new Error(data.error||'تعذر إكمال تحليل Sql Map1.');
        status.textContent=data.success?'✅ استخرج صقر العلم من صفحة السر.':'اكتمل التحليل دون استخراج كلمة مرور محليًا.';
        (data.explanation_ar||[]).forEach(function(t){out.appendChild(el('p','fws-muted',t));});
        (data.warnings||[]).forEach(function(t){out.appendChild(el('p','fws-note',t));});
        if(data.discovered){var d=el('div','fws-card');d.appendChild(el('div','fws-h','🔎 ما اكتشفه صقر'));d.appendChild(el('p',null,'SQLite · UNION SQLi · '+data.discovered.columns+' أعمدة · MD5 · المستخدم المستهدف '+data.discovered.account));out.appendChild(d);}
        if(data.steps&&data.steps.length){var log=el('details','fws-card');log.appendChild(el('summary',null,'عرض خطوات التحليل'));data.steps.forEach(function(s,i){log.appendChild(el('p','fws-muted',(i+1)+'. '+s.method+' '+s.path+' — HTTP '+s.status+' — '+s.detail));});out.appendChild(log);}
        if(data.flag){var box=el('div','fws-flag');box.appendChild(el('strong',null,'🚩 العلم المستخرج:'));var row=el('div','fws-row');row.appendChild(el('code',null,data.flag));var copy=el('button','fws-copy','نسخ');copy.onclick=function(){navigator.clipboard&&navigator.clipboard.writeText(data.flag);copy.textContent='تم النسخ ✓';};row.appendChild(copy);box.appendChild(row);box.appendChild(el('div','fws-muted','انسخ العلم بنفسك إلى منصة المسابقة.'));out.appendChild(box);}
      }catch(e){status.textContent='تعذر الحل: '+e.message;button.disabled=false;}
    };
    busy=false;out.scrollIntoView({behavior:'smooth',block:'start'});return false;
  }
  async function runFoolLockoutChallenge(text) {
    if(busy)return false;
    busy=true;
    var out=document.getElementById('result');out.classList.remove('hidden');out.classList.add('fws');injectCSS();out.innerHTML='';
    var card=el('div','fws-card');card.appendChild(el('div','fws-h','🔓 تحدي Fool the Lockout'));
    card.appendChild(el('p',null,'ينزّل صقر app.py وcreds-dump.txt من روابط التحدي ويحفظهما في مجلد محلي خاص، ثم يتحقق من حدّ المحاولات في المصدر قبل تجربة السجلات على صفحة الدخول.'));
    card.appendChild(el('p','fws-muted','يتبع صقر عدد المحاولات ونافذة إعادة الضبط المكتوبة في المصدر، ويوقف الفحص بعد سجلات الملف المقدمة. قد يستغرق الفحص عدة دقائق بسبب الانتظار بين الدفعات.'));
    var button=el('button','fws-btn','▶ حلّل المصدر وابدأ الفحص');var status=el('div','fws-note','يتطلب Falcon Local Engine 2.34.0 أو أحدث.');
    card.appendChild(button);card.appendChild(status);out.appendChild(card);
    button.onclick=async function(){
      button.disabled=true;status.textContent='يتحقق صقر من الهدف وروابط الملفين ثم يبدأ…';
      try {
        var engine=(location.hostname==='127.0.0.1'||location.hostname==='localhost')?location.origin:DEFAULT_ENGINE;
        var health=await fetch(engine+'/health',{cache:'no-store'}).then(function(r){return r.json();});
        var v=(health.version||'0.0.0').split('.').map(Number);
        if(v[0]<2||(v[0]===2&&v[1]<34))throw new Error('حدّث المحرك المحلي إلى 2.34.0 ثم أعد تشغيله.');
        var response=await fetch(engine+'/fool-lockout/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({confirm:true,challenge_text:text}),cache:'no-store'});
        var started=await response.json();if(!response.ok||!started.ok)throw new Error(started.error||'تعذر تشغيل فحص Fool the Lockout.');
        var job=null,data=null,deadline=Date.now()+12*60*1000;
        while(Date.now()<deadline){
          await new Promise(function(resolve){setTimeout(resolve,1000);});
          var poll=await fetch(engine+'/fool-lockout/status?job_id='+encodeURIComponent(started.job_id),{cache:'no-store'});
          job=await poll.json();if(!poll.ok||!job.ok)throw new Error(job.error||'انقطع تحديث حالة الفحص.');
          if(job.state==='running'){
            if(job.phase==='waiting')status.textContent='انتظار نافذة إعادة العداد — تبقّى نحو '+job.wait_seconds+' ثانية؛ '+job.checked+' من '+job.entries+' سجلات تمت مراجعتها.';
            else if(job.phase==='downloading')status.textContent='ينزّل app.py وcreds-dump.txt ويتحقق من كود حدّ المحاولات…';
            else status.textContent='يفحص '+job.target+' — تمت مراجعة '+job.checked+' من '+job.entries+' سجلًا.';
            continue;
          }
          data=job.result;break;
        }
        if(!data)throw new Error('تجاوز الفحص المهلة. تحقق من اتصال المثيل ثم أعد المحاولة.');
        if(!data.ok)throw new Error(data.error||'تعذر إكمال تحليل المصدر.');
        status.textContent=data.success?'✅ عُثر على العلم بعد مراجعة '+data.checked+' سجلًا.':'انتهت سجلات الملف دون العثور على العلم.';
        if(data.files_saved_to)out.appendChild(el('p','fws-muted','حُفظ app.py وcreds-dump.txt في: '+data.files_saved_to));
        (data.explanation_ar||[]).forEach(function(t){out.appendChild(el('p','fws-muted',t));});
        (data.warnings||[]).forEach(function(t){out.appendChild(el('p','fws-note',t));});
        if(data.flag){var box=el('div','fws-flag');box.appendChild(el('strong',null,'🚩 العلم المستخرج:'));var row=el('div','fws-row');row.appendChild(el('code',null,data.flag));var copy=el('button','fws-copy','نسخ');copy.onclick=function(){navigator.clipboard&&navigator.clipboard.writeText(data.flag);copy.textContent='تم النسخ ✓';};row.appendChild(copy);box.appendChild(row);out.appendChild(box);}
      }catch(e){status.textContent='تعذر الحل: '+e.message;button.disabled=false;}
    };
    busy=false;out.scrollIntoView({behavior:'smooth',block:'start'});return false;
  }
  function credentialTarget(text) {
    var m=String(text||'').match(/\bnc\s+([a-z0-9.-]+\.cylabacademy\.(?:net|org))\s+(\d{1,5})\b/i);
    return m?{host:m[1].toLowerCase(),port:Number(m[2])}:null;
  }
  async function runCredentialStuffing(text) {
    if(busy)return false;
    busy=true;
    var out=document.getElementById('result');out.classList.remove('hidden');out.classList.add('fws');injectCSS();out.innerHTML='';
    var artifacts=renderArtifactGuidance(text);if(artifacts)out.appendChild(artifacts);
    var target=credentialTarget(text);
    var card=el('div','fws-card');
    card.appendChild(el('div','fws-h','🧭 تحدي TCP: Credential Stuffing'));
    card.appendChild(el('p',null,'احفظ الملف creds-dump.txt داخل C:\\Falcon\\analysis. بعد ذلك اضغط الزر ليجرب صقر سجلات الملف على خدمة هذا التحدي فقط: '+(target?target.host+':'+target.port:'الهدف المذكور مع nc في الوصف')+'.'));
    card.appendChild(el('p','fws-muted','الحد الأقصى 1500 سجل؛ يفحصها صقر على دفعات مرتبة، بحد أقصى 3 اتصالات متزامنة وفاصل قصير بين الدفعات. لا يرسل صقر الطلب إلى رابط الملف ولا إلى أي موقع آخر، ولا يعرض كلمات المرور في النتيجة.'));
    var button=el('button','fws-btn','▶ ابدأ فحص ملف التحدي');
    var status=el('div','fws-note','المحرك المحلي مطلوب: Falcon Local Engine 2.32.0 أو أحدث.');
    card.appendChild(button);card.appendChild(status);out.appendChild(card);
    button.onclick=async function(){
      button.disabled=true;status.textContent='يجري فحص الملف والاتصال بخدمة CTF المحددة…';
      try {
        var engine=(location.hostname==='127.0.0.1'||location.hostname==='localhost')?location.origin:DEFAULT_ENGINE;
        var health=await fetch(engine+'/health',{cache:'no-store'}).then(function(r){return r.json();});
        var v=(health.version||'0.0.0').split('.').map(Number);
        if(v[0]<2||(v[0]===2&&v[1]<32))throw new Error('حدّث المحرك المحلي إلى الإصدار 2.32.0 ثم أعد تشغيله.');
        var response=await fetch(engine+'/credential-stuffing/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({confirm:true,challenge_text:text}),cache:'no-store'});
        var started=await response.json();
        if(!response.ok||!started.ok)throw new Error(started.error||'تعذر تشغيل فحص ملف الاعتمادات.');
        var data=null,deadline=Date.now()+7*60*1000;
        while(Date.now()<deadline){
          await new Promise(function(resolve){setTimeout(resolve,800);});
          var poll=await fetch(engine+'/credential-stuffing/status?job_id='+encodeURIComponent(started.job_id),{cache:'no-store'});
          var job=await poll.json();
          if(!poll.ok||!job.ok)throw new Error(job.error||'انقطع تحديث حالة الفحص.');
          if(job.state==='running'){
            status.textContent='يجري الفحص على '+job.target+' — تمت مراجعة '+job.attempts+' من '+job.entries+' سجلًا…';
            continue;
          }
          data=job.result;
          if(job.state==='error'||!data||!data.ok)throw new Error((data&&data.error)||'توقف الفحص بسبب خطأ.');
          break;
        }
        if(!data)throw new Error('تجاوز الفحص المهلة المحددة. تحقق من حالة المحرك وأعد المحاولة.');
        status.textContent=data.success?'✅ عُثر على العلم بعد '+data.attempts+' محاولة.':'انتهى الفحص دون العثور على العلم بعد '+data.attempts+' محاولة.';
        if(data.success){
          var flag=el('div','fws-flag');flag.appendChild(el('strong',null,'✅ العلم المستخرج:'));
          var row=el('div','fws-row');row.appendChild(el('code',null,data.flag));
          var copy=el('button','fws-copy','نسخ');copy.onclick=function(){navigator.clipboard&&navigator.clipboard.writeText(data.flag);copy.textContent='تم النسخ ✓';};
          row.appendChild(copy);flag.appendChild(row);flag.appendChild(el('div','fws-muted','اسم المستخدم المطابق: '+(data.username||'غير معروض')+' — انسخ العلم بنفسك إلى منصة المسابقة.'));
          out.appendChild(flag);
        }
      }catch(e){status.textContent='تعذر إكمال التحليل: '+e.message;button.disabled=false;}
    };
    out.scrollIntoView({behavior:'smooth',block:'start'});
    busy=false;
    return false;
  }
  global.FalconWebSessions.challengeUrl = challengeUrl;
  global.FalconWebSessions.isHashgatePrompt = isHashgatePrompt;
  global.FalconWebSessions.isCredentialStuffingPrompt = isCredentialStuffingPrompt;
  global.FalconWebSessions.runCredentialStuffing = runCredentialStuffing;
  global.FalconWebSessions.isUndoPrompt = isUndoPrompt;
  global.FalconWebSessions.undoTarget = undoTarget;
  global.FalconWebSessions.runUndoChallenge = runUndoChallenge;
  global.FalconWebSessions.isSecretBoxPrompt = isSecretBoxPrompt;
  global.FalconWebSessions.runSecretBoxChallenge = runSecretBoxChallenge;
  global.FalconWebSessions.isFoolLockoutPrompt = isFoolLockoutPrompt;
  global.FalconWebSessions.runFoolLockoutChallenge = runFoolLockoutChallenge;
  global.FalconWebSessionRun = async function() {
    // Route the picoCTF No FA prompt to its artifact guidance before generic
    // web-session auditing sees the instance URL as the challenge target.
    if (global.FalconNoFaRun && await global.FalconNoFaRun()) return false;
    var pastedText=(document.getElementById('text')||{}).value||'';
    if(isSqlMap1Prompt(pastedText))return runSqlMap1Challenge(pastedText);
    if(isFoolLockoutPrompt(pastedText))return runFoolLockoutChallenge(pastedText);
    if(isUndoPrompt(pastedText))return runUndoChallenge(pastedText);
    if(isSecretBoxPrompt(pastedText))return runSecretBoxChallenge(pastedText);
    if(isCredentialStuffingPrompt(pastedText))return runCredentialStuffing(pastedText);
    var url=challengeUrl();
    if(!url && isHashgatePrompt(pastedText)) {
      var missingUrl=document.getElementById('result');
      if(missingUrl){missingUrl.classList.remove('hidden');missingUrl.textContent='🦅 تعرّف صقر على Hashgate. لم يجد رابط Instance صالحًا في النص؛ الصق رابط المثيل كاملًا مثل http://xebec.cylabacademy.net:29063/ ثم اضغط «حلّل التحدي». لن يحلل وصف التحدي كـ ROT13.';}
      return false;
    }
    if(!url) return previous ? previous() : false;
    if(busy) return false;
    busy=true;
    var out=document.getElementById('result');out.classList.remove('hidden');out.classList.add('fws');injectCSS();
      out.textContent='🔎 جارٍ فحص التحدي عبر المحرك المحلي v2.28.0…';
    try {
      var engine=(location.hostname==='127.0.0.1'||location.hostname==='localhost') ? location.origin : DEFAULT_ENGINE;
      var health=await fetch(engine+'/health',{cache:'no-store'}).then(function(r){return r.json();});
      var version=(health.version||'0.0.0').split('.').map(Number);
      if(version[0]<2||(version[0]===2&&version[1]<25))
        throw new Error('حدّث Falcon Local Engine إلى الإصدار 2.28.0 ثم أعد تشغيل المحرك.');
      var context = {challenge_text: document.getElementById('text').value || ''};
      var res=await audit(engine,url,context);
      if(!Array.isArray(res.steps)) throw new Error(res.error||'استجابة المحرك غير متوافقة مع صقر.');
      renderResult(out,res);
      if(res.needs_input && res.needs_input.length) {
        var card=el('div','fws-card');
        card.appendChild(el('p',null,'أدخل بريد التحدي لإكمال التحليل. كلمة المرور المجهولة غير مطلوبة لهذا النمط.'));
        var emailInput=el('input','fws-input');emailInput.type='email';emailInput.placeholder='البريد المذكور في نص التحدي';
        var confirm=el('button','fws-btn','متابعة التحليل');
        card.appendChild(emailInput);card.appendChild(confirm);out.appendChild(card);
        confirm.onclick=async function(){
          if(!emailInput.value || !emailInput.checkValidity()){emailInput.reportValidity();return;}
          confirm.disabled=true;
          try {context.email=emailInput.value.trim();var next=await audit(engine,url,context);renderResult(out,next);}
          catch(e){confirm.disabled=false;card.appendChild(el('p',null,e.message));}
        };
      }
    } catch(e) { out.textContent='تعذر تحليل التحدي: '+e.message; }
    finally {busy=false;out.scrollIntoView({behavior:'smooth',block:'start'});}
    return false;
  };
  global.FalconSmartRun=global.FalconWebSessionRun;
  var solve=document.getElementById('solve');
  if(solve) solve.addEventListener('click',function(e){
    if(!challengeUrl())return;
    e.preventDefault();e.stopImmediatePropagation();global.FalconWebSessionRun();
  },true);
})(window);
