(function(){
  var prev=window.FalconSmartRun;
  function id(x){return document.getElementById(x);}
  function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
  function copyBtn(cmd,label){
    return '<div style="margin:10px 0"><code style="direction:ltr;display:block;white-space:pre-wrap">'+esc(cmd)+'</code><button type="button" class="falconCopyCmd" data-cmd="'+esc(cmd).replace(/"/g,'&quot;')+'">📋 '+label+'</button></div>';
  }
  function bind(){
    setTimeout(function(){
      document.querySelectorAll('.falconCopyCmd').forEach(function(b){
        b.onclick=function(){
          if(navigator.clipboard) navigator.clipboard.writeText(this.getAttribute('data-cmd'));
          this.textContent='✅ تم النسخ';
        };
      });
    },0);
  }
  function analyze(t){
    if(!t) return false;
    var hashMatch=t.match(/\b[a-fA-F0-9]{64}\b/);
    var shellMatch=t.match(/([a-fA-F0-9]{64})\s+(files\/[A-Za-z0-9._-]+)/i);
    var verify=/sha-?256|sha256sum|checksum|decrypt\.sh/i.test(t) || !!shellMatch;
    var hash=shellMatch ? shellMatch[1] : (hashMatch ? hashMatch[0] : '');
    if(!hash || !verify) return false;
    var out=id('result');
    if(!out) return false;
    var html='<div class="studentSummary"><h2>🔎 مساعد التحقق SHA-256</h2><div class="studentCard"><b>1️⃣ نوع التحدي</b><p>Forensics / SHA-256 File Verification</p></div><div class="studentCard"><b>2️⃣ ماذا اكتشف صقر؟</b><p>اكتشف Checksum من نوع SHA-256. لا حاجة إلى ROT13 أو فك Hex.</p><div class="solvePath">Challenge → SHA-256 → Find Matching File → Verify → Decrypt → Flag</div></div>';
    if(shellMatch){
      var file=shellMatch[2];
      var cmd2='./decrypt.sh '+file;
      html+='<div class="studentCard success"><b>3️⃣ تم العثور على الملف المطابق ✅</b><p><code>'+esc(file)+'</code></p><h3>🖥️ أين أشغّل الأمر؟</h3><p>ارجع إلى نافذة <b>Terminal / SSH</b> التي دخلت منها إلى خادم التحدي. يجب أن ترى سطرًا شبيهًا بـ <code>ctf-player@academy-chall$</code>. لا تضع الأمر داخل صقر.</p><h3>▶️ كيف أشغّله؟</h3><p>1. اضغط زر <b>نسخ أمر فك التشفير</b> أدناه.<br>2. انتقل إلى نافذة Terminal / SSH.<br>3. الصق الأمر بعد علامة <code>$</code>.<br>4. اضغط <b>Enter</b> من لوحة المفاتيح.<br>5. سيظهر ناتج فك التشفير، وغالبًا يحتوي على الـ Flag.<br>6. انسخ الناتج والصقه في صقر للتحقق.</p>'+copyBtn(cmd2,'نسخ أمر فك التشفير')+'<p><b>مثال:</b> <code>ctf-player@academy-chall$ '+esc(cmd2)+'</code></p></div>';
    }else{
      var cmd1='sha256sum files/* | grep '+hash;
      html+='<div class="studentCard next"><b>3️⃣ الخطوة التالية للطالب</b><h3>🖥️ أين أشغّل الأمر؟</h3><p>شغّل الأمر داخل <b>Terminal / SSH</b> الخاص بالتحدي، وليس داخل مربع صقر. بعد الاتصال بالخادم ستظهر لك علامة أو سطر ينتهي عادةً بـ <code>$</code>.</p><h3>▶️ كيف أشغّله؟</h3><p>1. ادخل إلى جلسة SSH المعطاة في التحدي.<br>2. انتظر حتى يظهر سطر الأوامر مثل <code>ctf-player@academy-chall$</code>.<br>3. اضغط <b>نسخ أمر التحقق</b> أدناه.<br>4. الصقه بعد علامة <code>$</code> ثم اضغط <b>Enter</b>.<br>5. سيظهر اسم الملف الذي يطابق SHA-256.<br>6. انسخ سطر النتيجة كاملًا والصقه في صقر.</p>'+copyBtn(cmd1,'نسخ أمر التحقق')+'<p><b>مهم:</b> لا تكتب علامة <code>$</code> بنفسك؛ هي جزء من موجه Terminal فقط.</p></div>';
    }
    out.innerHTML=html+'</div>';
    out.className='result';
    bind();
    out.scrollIntoView({behavior:'smooth',block:'start'});
    return true;
  }
  window.FalconTerminalVerifyRun=function(){
    var ta=id('text');
    var t=ta ? ta.value.trim() : '';
    if(analyze(t)) return false;
    return prev ? prev() : false;
  };
  window.FalconSmartRun=window.FalconTerminalVerifyRun;
})();