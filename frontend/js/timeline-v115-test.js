(function(){
'use strict';
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function fmt(n){return (n/1048576).toFixed(1)+' MB';}
async function run(){
 var inp=document.getElementById('file'),f=(inp&&inp.files&&inp.files[0])||window.__falconDroppedFile;if(!f)return false;
 if(!/\.img\.gz$/i.test(f.name||''))return false;
 var r=document.getElementById('result');if(!r)return true;r.classList.remove('hidden');
 r.innerHTML='<div class="finding"><h3>🕒 Timeline Analyzer — V129</h3><p>تم التعرف على صورة قرص مضغوطة. جارٍ الاتصال بمحرك صقر المحلي لتنفيذ <code>fls + Falcon Python Timeline</code> تلقائيًا…</p><p>📦 <code>'+esc(f.name)+'</code> — '+fmt(f.size)+'</p></div>';
 try{
  var health=await fetch((location.hostname==='127.0.0.1'||location.hostname==='localhost'?'':'http://127.0.0.1:8765')+'/health',{cache:'no-store'}).then(function(x){if(!x.ok)throw new Error('HEALTH_'+x.status);return x.json();});
  if(!health.ok||!health.ready)throw new Error('ENGINE_NOT_READY');
  if(!health.sleuthkit)throw new Error('SLEUTHKIT');
  var res=await fetch((location.hostname==='127.0.0.1'||location.hostname==='localhost'?'':'http://127.0.0.1:8765')+'/timeline/analyze',{method:'POST',headers:{'Content-Type':'application/octet-stream','X-Filename':f.name},body:f});
  var d=await res.json(); if(!d.ok)throw new Error(d.error||'ENGINE');
  var anomalies=d.old_anomalies||[], lines=(d.evidence&&d.evidence.length?d.evidence:d.recent)||[], ex=d.extracted||[], flags=[];
  ex.forEach(function(x){(x.flags||[]).concat(x.candidates||[]).forEach(function(f){if(flags.indexOf(f)<0)flags.push(f);});});
  var exhtml=ex.length?'<h4>📂 محتوى الأدلة المستخرج بـ icat</h4>'+ex.map(function(x){var dec=(x.decoded||[]);return '<div class="finding"><b>'+esc(x.path)+'</b> — inode <code>'+esc(x.inode)+'</code><pre dir="ltr" style="white-space:pre-wrap;max-height:260px;overflow:auto">'+esc(x.text||'(فارغ)')+'</pre>'+(dec.length?'<p><b>🔓 Base64:</b> <code>'+esc(dec.join(' | '))+'</code></p>':'')+(x.error?'<small>'+esc(x.error)+'</small>':'')+'</div>';}).join(''):'<p>لم يُستخرج محتوى إضافي. تأكد أن المحرك المحلي هو v1.4 وأن <code>icat.exe</code> يظهر 🟢 عند التشغيل.</p>';
  var flaghtml=flags.length?'<div class="finding success"><h3>🚩 مرشح العلم</h3><code>'+esc(flags[0])+'</code></div>':'';
  r.innerHTML='<div class="finding success"><h3>🕒 MAC Timeline جاهز — V129</h3><p><b>المسار:</b> IMG.GZ → ext filesystem → fls → Falcon Python Timeline → macb → icat → Evidence</p><p>وجد صقر <b>'+d.macb_count+'</b> سجلًا من نوع <code>macb</code>.</p><h4>🔎 أحدث الأدلة</h4><pre dir="ltr" style="white-space:pre-wrap;max-height:360px;overflow:auto">'+esc(lines.slice(-30).join('\\n'))+'</pre>'+(anomalies.length?'<h4>⏳ شذوذ زمني / Timestomping</h4><pre dir="ltr" style="white-space:pre-wrap;max-height:300px;overflow:auto">'+esc(anomalies.slice(0,30).join('\\n'))+'</pre>':'')+flaghtml+exhtml+'<details><summary>🔧 آخر سجلات macb</summary><pre dir="ltr" style="white-space:pre-wrap">'+esc((d.recent||[]).slice(-50).join('\\n'))+'</pre></details></div>';
 }catch(e){
  var msg=e.message==='SLEUTHKIT'?'المحرك المحلي يعمل، لكن Sleuth Kit / fls غير مثبت.':'تعذر الاتصال بمحرك صقر المحلي على 127.0.0.1:8765.';
  r.innerHTML='<div class="finding warn"><h3>🕒 Timeline Analyzer — V129</h3><p>'+msg+'</p><p>شغّل <code>local-engine/falcon_local.py</code> (v1.4 أو أحدث) وتأكد أن <code>fls</code> متاح، ثم أعد التحليل. إذا كان المحرك يعمل بالفعل، حدّث ملف المحرك المحلي إلى آخر نسخة. لم يتم استخدام strings أو تخمين العلم.</p></div>';
 }
 r.scrollIntoView({behavior:'smooth',block:'start'});return true;
};
var prev=window.FalconSmartRun;
window.FalconTimelineRun=async function(){try{if(await run())return false;}catch(e){console.warn('Falcon Timeline',e);}return prev?prev():false;};
window.FalconSmartRun=window.FalconTimelineRun;
})();
