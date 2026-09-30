(function(){
  var prev=window.FalconSmartRun, state={};
  function id(x){return document.getElementById(x);}
  function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
  function copyBtn(cmd,label){return '<div style="margin:10px 0"><code style="direction:ltr;display:block;white-space:pre-wrap">'+esc(cmd)+'</code><button type="button" class="falconCopyCmd" data-cmd="'+esc(cmd).replace(/"/g,'&quot;')+'">📋 '+label+'</button></div>';}
  function steps(n){var a=['① الاتصال بالخادم','② التحقق SHA-256','③ الملف الصحيح','④ فك التشفير','⑤ العلم'];return '<div class="solvePath">'+a.map(function(x,i){return (i<n?'✅ ':'')+x;}).join(' → ')+'</div>';}
  function pasteBox(label){return '<div style="margin-top:14px"><b>'+label+'</b><textarea class="falconVerifyPaste" style="width:100%;min-height:90px;margin-top:8px" placeholder="الصق نتيجة Terminal هنا..."></textarea><button type="button" class="falconVerifyContinue">➡️ تحليل النتيجة والمتابعة</button></div>';}
  function bind(){
    setTimeout(function(){
      document.querySelectorAll('.falconCopyCmd').forEach(function(b){b.onclick=function(){var v=this.getAttribute('data-cmd');if(navigator.clipboard)navigator.clipboard.writeText(v);this.textContent='✅ تم النسخ';};});
      document.querySelectorAll('.falconVerifyContinue').forEach(function(b){b.onclick=function(){var box=this.parentNode.querySelector('.falconVerifyPaste');if(box&&box.value.trim()) analyze(box.value.trim(),true);};});
    },0);
  }
  function parse(t){
    var hash=(t.match(/\b[a-fA-F0-9]{64}\b/)||[])[0]||state.hash||'';
    var shell=t.match(/([a-fA-F0-9]{64})\s+(files\/[A-Za-z0-9._-]+)/i);
    var ssh=t.match(/ssh\s+(?:-p\s+(\d+)\s+)?([A-Za-z0-9._-]+)@([A-Za-z0-9.-]+)/i);
    var pass=t.match(/(?:password|كلمة\s*المرور)\s*[:：]?\s*([^\s]+)/i);
    var flag=t.match(/(?:academy|flag|ctf|moe)\{[^}\r\n]+\}/i);
    return {hash:hash,shell:shell,ssh:ssh,pass:pass,flag:flag};
  }
  function analyze(t,continuing){
    if(!t)return false;
    var p=parse(t);
    var verify=/sha-?256|sha256sum|checksum|decrypt\.sh|ssh\s+/i.test(t)||!!p.shell||!!state.hash;
    if(!verify&&!p.flag)return false;
    if(p.hash)state.hash=p.hash;
    if(p.ssh){state.port=p.ssh[1]||'22';state.user=p.ssh[2];state.host=p.ssh[3];}
    if(p.pass)state.password=p.pass[1];
    var out=id('result');if(!out)return false;
    var html='<div class="studentSummary"><h2>🦅 معالج Verify للطالب</h2>';
    if(p.flag){
      html+=steps(5)+'<div class="studentCard success"><h3>🚩 تم العثور على العلم</h3><p><code>'+esc(p.flag[0])+'</code></p><p>اكتمل التحدي بنجاح. انسخ العلم وأرسله في منصة المسابقة.</p></div></div>';
    } else if(p.shell){
      var file=p.shell[2], dec='./decrypt.sh '+file;
      state.file=file;
      html+=steps(3)+'<div class="studentCard success"><h3>③ تم العثور على الملف الصحيح ✅</h3><p><code>'+esc(file)+'</code></p><h3>④ فك التشفير</h3><p>ابقَ في <b>نفس نافذة SSH</b>. انسخ الأمر التالي، الصقه بعد علامة <code>$</code> ثم اضغط <b>Enter</b>.</p>'+copyBtn(dec,'نسخ أمر فك التشفير')+'<p><b>لا تغلق نافذة SSH.</b> بعد ظهور النتيجة انسخها والصقها هنا:</p>'+pasteBox('📥 الصق نتيجة فك التشفير')+'</div></div>';
    } else {
      var connect=(state.user&&state.host)?'ssh -p '+state.port+' '+state.user+'@'+state.host:'';
      var check=state.hash?'sha256sum files/* | grep '+state.hash:'';
      html+=steps(0)+'<div class="studentCard next"><h3>① الاتصال بالخادم</h3>';
      if(connect){
        html+='<p>افتح قائمة Start، واكتب <b>PowerShell</b>، ثم افتح Windows PowerShell. انسخ أمر الاتصال التالي والصقه في النافذة واضغط Enter:</p>'+copyBtn(connect,'نسخ أمر الاتصال SSH');
        if(state.password)html+=copyBtn(state.password,'نسخ كلمة المرور');
        html+='<ol><li>إذا ظهر السؤال <code>Are you sure you want to continue connecting?</code> فاكتب <code>yes</code> واضغط Enter.</li>';
        if(state.password)html+='<li>عند ظهور <code>Password:</code> الصق كلمة المرور أعلاه واضغط Enter. لن تظهر الأحرف أثناء الكتابة؛ هذا طبيعي.</li>';
        else html+='<li>عند ظهور <code>Password:</code> أدخل كلمة المرور المذكورة في وصف التحدي ثم اضغط Enter. لن تظهر الأحرف أثناء الكتابة؛ هذا طبيعي.</li>';
        html+='<li>اكتمل الاتصال عندما يظهر سطر أوامر ينتهي بالرمز <code>$</code>. لا تكتب <code>$</code> بنفسك.</li></ol>';
      }else html+='<p><b>طريقة فتح جلسة SSH خطوة بخطوة:</b></p><ol><li>افتح قائمة Start، واكتب <b>PowerShell</b>، ثم افتح Windows PowerShell.</li><li>ارجع إلى وصف التحدي وابحث عن أمر يبدأ بكلمة <code>ssh</code>، مثل <code>ssh -p رقم_المنفذ ctf-player@اسم_الخادم</code>.</li><li>انسخ الأمر من الوصف والصقه في PowerShell ثم اضغط Enter.</li><li>إذا ظهر السؤال <code>Are you sure you want to continue connecting?</code> فاكتب <code>yes</code> واضغط Enter.</li><li>أدخل كلمة المرور الموجودة في وصف التحدي عند ظهور <code>Password:</code> ثم اضغط Enter. لن تظهر الأحرف أثناء الكتابة؛ هذا طبيعي.</li><li>تم الاتصال عندما يظهر سطر أوامر ينتهي بـ <code>$</code>.</li></ol><p>إذا لم تجد أمر SSH في النص الذي حللته، الصق الأمر هنا ليجهزه لك صقر:</p><textarea class="falconVerifyPaste" style="width:100%;min-height:64px" placeholder="ssh -p 12345 ctf-player@rhea.picoctf.net"></textarea><button type="button" class="falconVerifyContinue">➡️ جهّز أمر الاتصال</button>';
      if(check)html+='<h3>② التحقق من SHA-256</h3><p>بعد نجاح الاتصال وظهور علامة <code>$</code>، انسخ هذا الأمر والصقه في <b>نفس نافذة SSH</b> ثم اضغط Enter:</p>'+copyBtn(check,'نسخ أمر التحقق')+'<p>ستظهر نتيجة فيها اسم ملف مثل <code>files/xxxx</code>. انسخ <b>سطر النتيجة كاملًا</b> والصقه هنا:</p>'+pasteBox('📥 الصق نتيجة SHA-256');
      html+='</div></div>';
    }
    out.innerHTML=html;out.className='result';bind();out.scrollIntoView({behavior:'smooth',block:'start'});return true;
  }
  window.FalconTerminalVerifyRun=function(){var ta=id('text'),t=ta?ta.value.trim():'';if(analyze(t,false))return false;return prev?prev():false;};
  window.FalconSmartRun=window.FalconTerminalVerifyRun;
})();
