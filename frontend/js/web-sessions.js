/* ==========================================================================
 * CTF Falcon — Web Sessions panel  (frontend/js/web-sessions.js)  v148
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
  .fws-btn{background:var(--fws-accent);color:#04121f;border:0;border-radius:10px;
    padding:11px 18px;font-weight:700;cursor:pointer;font-size:15px}
  .fws-btn:disabled{opacity:.55;cursor:progress}
  .fws-btn.ghost{background:transparent;color:var(--fws-txt);border:1px solid var(--fws-line)}
  .fws-muted{color:var(--fws-muted);font-size:13px}
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
      box.appendChild(el("div", "fws-muted", "راجِع الخطوات أدناه؛ قد يكون شكل التحدي مختلفًا عن Old Sessions."));
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
    DEFAULT_ENGINE: DEFAULT_ENGINE, SAMPLE: SAMPLE
  };

  var previous = global.FalconRogueTowerRun || global.FalconSmartRun;
  var busy = false;
  function challengeUrl() {
    var input = document.getElementById('text');
    var matches = ((input && input.value) || '').match(/https?:\/\/[^\s<>\]"')]+/gi) || [];
    for (var i=0; i<matches.length; i++) {
      try { var u=new URL(matches[i]); if(u.hostname.endsWith('.cylabacademy.net')||u.hostname.endsWith('.cylabacademy.org')) return u.href; } catch (_) {}
    }
    return null;
  }
  global.FalconWebSessionRun = async function() {
    var url=challengeUrl();
    if(!url) return previous ? previous() : false;
    if(busy) return false;
    busy=true;
    var out=document.getElementById('result');out.classList.remove('hidden');out.classList.add('fws');injectCSS();
    out.textContent='🔎 جارٍ فحص التحدي عبر المحرك المحلي v2.18.0…';
    try {
      var engine=(location.hostname==='127.0.0.1'||location.hostname==='localhost') ? location.origin : DEFAULT_ENGINE;
      var health=await fetch(engine+'/health',{cache:'no-store'}).then(function(r){return r.json();});
      var version=(health.version||'0.0.0').split('.').map(Number);
      if(version[0]<2||(version[0]===2&&version[1]<17))
        throw new Error('استبدل falcon_local.py وweb_session_audit.py بالإصدار 2.18.0 ثم أعد تشغيل المحرك (يجمع أجزاء العلم المعلّمة 1/3 و2/3 و3/3 في Insp3ct0r).');
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
