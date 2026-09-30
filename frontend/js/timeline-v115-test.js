(function(){
'use strict';
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function fmt(n){return (n/1048576).toFixed(1)+' MB';}

function renderTimeline(d){
 var anomalies=d.old_anomalies||[],lines=(d.evidence&&d.evidence.length?d.evidence:d.recent)||[],items=[],seen=new Map(),flags=[];
 (d.extracted||[]).forEach(function(x){
  var key=String(x.inode)+'|'+String(x.path),existing=seen.get(key);
  if(!existing){existing=Object.assign({},x);existing.decoded=[];existing.flags=[];existing.candidates=[];seen.set(key,existing);items.push(existing);}
  ['decoded','flags','candidates'].forEach(function(k){(x[k]||[]).forEach(function(v){if(existing[k].indexOf(v)<0)existing[k].push(v);});});
  if(!existing.text&&x.text)existing.text=x.text;
 });
 function hasFlag(x){return x.flags.length||x.candidates.length;}
 function binary(x){var t=String(x.text||'');return /\.(?:gz|xz|zip|png|jpg|jpeg|elf|exe|dll|ko)(?:\s|$)/i.test(x.path||'')||/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(t);}
 items.forEach(function(x){x.flags.concat(x.candidates).forEach(function(f){if(flags.indexOf(f)<0)flags.push(f);});});
 items.sort(function(a,b){return Number(!!hasFlag(b))-Number(!!hasFlag(a));});
 var hidden=0,other=[];
 function card(x){return '<div class="finding"><b>'+esc(x.path)+'</b> — inode <code>'+esc(x.inode)+'</code>'+(binary(x)?'<p>محتوى ثنائي — تم إخفاء النص غير المقروء.</p>':'<pre dir="ltr" style="white-space:pre-wrap;max-height:260px;overflow:auto">'+esc(x.text||'(فارغ)')+'</pre>')+(x.decoded.length?'<p><b>🔓 Base64:</b> <code dir="ltr">'+esc(x.decoded.join(' | '))+'</code></p>':'')+(x.error?'<small>'+esc(x.error)+'</small>':'')+'</div>';}
 var primary='';items.forEach(function(x){if(hasFlag(x))primary+=card(x);else if(binary(x))hidden++;else other.push(card(x));});
 var flaghtml=flags.length?'<div class="finding success"><h3>🚩 مرشح العلم</h3>'+flags.map(function(f){return '<p><code dir="ltr">'+esc(f)+'</code></p>';}).join('')+'</div>':'';
 function pre(rows){return '<pre dir="ltr" style="white-space:pre-wrap;max-height:360px;overflow:auto">'+esc(rows.join('\n'))+'</pre>';}
 return '<div class="finding success"><h3>🕒 MAC Timeline جاهز — V136</h3><p>وجد صقر <b>'+esc(d.macb_count)+'</b> سجلًا من نوع <code>macb</code>.</p>'+flaghtml+(primary?'<h4>📂 دليل العلم المستخرج بـ icat</h4>'+primary:'')+(anomalies.length?'<h4>⏳ شذوذ زمني / Timestomping</h4>'+pre(anomalies.slice(0,30)):'')+'<details><summary>🔎 الأدلة الأخرى ('+other.length+')</summary>'+other.join('')+'</details>'+(hidden?'<p>تم إخفاء محتوى '+hidden+' ملفًا ثنائيًا غير مقروء.</p>':'')+'<details><summary>🔎 سجلات الأدلة</summary>'+pre(lines.slice(-30))+'</details><details><summary>🔧 آخر سجلات macb</summary>'+pre((d.recent||[]).slice(-50))+'</details></div>';
}

async function run(){
 var inp=document.getElementById('file'),f=(inp&&inp.files&&inp.files[0])||window.__falconDroppedFile;if(!f)return false;
 if(!/\.img\.gz$/i.test(f.name||''))return false;
 var r=document.getElementById('result');if(!r)return true;r.classList.remove('hidden');
 r.innerHTML='<div class="finding"><h3>🕒 Timeline Analyzer — V136</h3><p>تم التعرف على صورة قرص مضغوطة. جارٍ الاتصال بمحرك صقر المحلي لتنفيذ <code>fls + Falcon Python Timeline</code> تلقائيًا…</p><p>📦 <code>'+esc(f.name)+'</code> — '+fmt(f.size)+'</p></div>';
 try{
  var health=await fetch((location.hostname==='127.0.0.1'||location.hostname==='localhost'?'':'http://127.0.0.1:8765')+'/health',{cache:'no-store'}).then(function(x){if(!x.ok)throw new Error('HEALTH_'+x.status);return x.json();});
  if(!health.ok||!health.ready)throw new Error('ENGINE_NOT_READY');
  if(!health.sleuthkit)throw new Error('SLEUTHKIT');
  var res=await fetch((location.hostname==='127.0.0.1'||location.hostname==='localhost'?'':'http://127.0.0.1:8765')+'/timeline/analyze',{method:'POST',headers:{'Content-Type':'application/octet-stream','X-Filename':f.name},body:f});
  var raw=await res.text(),d; try{d=JSON.parse(raw);}catch(_){throw new Error('HTTP '+res.status+' — '+raw.slice(0,300));}
  if(!res.ok||!d.ok)throw new Error('HTTP '+res.status+' — '+(d.error||'ENGINE')+(d.message?' — '+d.message:''));
  r.innerHTML=renderTimeline(d);
 }catch(e){
  var msg=e.message==='SLEUTHKIT'?'المحرك المحلي يعمل، لكن Sleuth Kit / fls غير مثبت.':'فشل تحليل Timeline: <code>'+esc(e.message||e)+'</code>';
  r.innerHTML='<div class="finding warn"><h3>🕒 Timeline Analyzer — V136</h3><p>'+msg+'</p><p>شغّل <code>local-engine/falcon_local.py</code> (v1.4 أو أحدث) وتأكد أن <code>fls</code> متاح، ثم أعد التحليل. إذا كان المحرك يعمل بالفعل، حدّث ملف المحرك المحلي إلى آخر نسخة. لم يتم استخدام strings أو تخمين العلم.</p></div>';
 }
 r.scrollIntoView({behavior:'smooth',block:'start'});return true;
};
var prev=window.FalconSmartRun;
window.FalconTimelineRun=async function(){try{if(await run())return false;}catch(e){console.warn('Falcon Timeline',e);}return prev?prev():false;};
window.FalconSmartRun=window.FalconTimelineRun;
})();
