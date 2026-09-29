(function(){
'use strict';
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function fmt(n){return (n/1048576).toFixed(1)+' MB';}
async function run(){
 var inp=document.getElementById('file'),f=(inp&&inp.files&&inp.files[0])||window.__falconDroppedFile;if(!f)return false;
 if(!/\\.img\\.gz$/i.test(f.name||''))return false;
 var r=document.getElementById('result');if(!r)return true;r.classList.remove('hidden');
 r.innerHTML='<div class="finding"><h3>🕒 Timeline Analyzer — V116</h3><p>تم التعرف على صورة قرص مضغوطة. جارٍ الاتصال بمحرك صقر المحلي لتنفيذ <code>fls + mactime</code> تلقائيًا…</p><p>📦 <code>'+esc(f.name)+'</code> — '+fmt(f.size)+'</p></div>';
 try{
  var health=await fetch('http://127.0.0.1:8765/health',{cache:'no-store'}).then(function(x){return x.json();});
  if(!health.sleuthkit)throw new Error('SLEUTHKIT');
  var res=await fetch('http://127.0.0.1:8765/timeline/analyze',{method:'POST',headers:{'Content-Type':'application/octet-stream','X-Filename':f.name},body:f});
  var d=await res.json(); if(!d.ok)throw new Error(d.error||'ENGINE');
  var lines=(d.evidence&&d.evidence.length?d.evidence:d.recent)||[];
  r.innerHTML='<div class="finding success"><h3>🕒 MAC Timeline جاهز</h3><p><b>المسار:</b> IMG.GZ → ext filesystem → fls → mactime → macb → Recent Files</p><p>وجد صقر <b>'+d.macb_count+'</b> سجلًا من نوع <code>macb</code>.</p><h4>🔎 أحدث الأدلة</h4><pre dir="ltr" style="white-space:pre-wrap;max-height:360px;overflow:auto">'+esc(lines.slice(-30).join('\\n'))+'</pre><p>انسخ السطر/اسم الملف المشبوه إلى مربع النص ليكمل صقر التحليل، أو افتح التفاصيل لمراجعة آخر الأحداث.</p><details><summary>🔧 آخر سجلات macb</summary><pre dir="ltr" style="white-space:pre-wrap">'+esc((d.recent||[]).slice(-50).join('\\n'))+'</pre></details></div>';
 }catch(e){
  var msg=e.message==='SLEUTHKIT'?'المحرك المحلي يعمل، لكن Sleuth Kit (fls + mactime) غير مثبت.':'تعذر الاتصال بمحرك صقر المحلي V0.5.';
  r.innerHTML='<div class="finding warn"><h3>🕒 Timeline Analyzer — V116</h3><p>'+msg+'</p><p>شغّل <code>local-engine/falcon_local.py</code> وتأكد أن <code>fls</code> و<code>mactime</code> متاحان، ثم أعد التحليل. لم يتم استخدام strings أو تخمين العلم.</p></div>';
 }
 r.scrollIntoView({behavior:'smooth',block:'start'});return true;
};