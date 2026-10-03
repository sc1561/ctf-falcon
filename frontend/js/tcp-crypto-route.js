(function(global){
'use strict';
var busy=false;
function routePrompt(text){
 text=String(text||'');
 if(/(?:^|\n)\s*(?:#{1,6}\s*)?(?:Undo|Credential Stuffing|Secret Box)(?=\s|$)/im.test(text))return false;
 var target=text.match(/\bnc\s+([A-Za-z0-9_.-]+)\s+(\d{1,5})\b/)||text.match(/tcp:\/\/([A-Za-z0-9_.-]+):(\d{1,5})\b/);
 if(target)return Number(target[2])>0&&Number(target[2])<65536;
 return /^\s*(?:N|modulus)\s*[:=]\s*(?:0x[0-9a-f]+|\d+)/im.test(text)&&/^\s*(?:ciphertext|cyphertext|c|ct)\s*[:=]\s*(?:0x[0-9a-f]+|\d+)/im.test(text);
}
function esc(value){return String(value==null?'':value).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
async function run(text){
 if(busy)return false;
 busy=true;
 var out=document.getElementById('result'),button=document.getElementById('solve');
 if(!out){busy=false;return false;}
 var previous=button&&button.disabled;
 if(button)button.disabled=true;
 out.classList.remove('hidden');
 out.innerHTML='<h2>🔐 تحليل خدمة TCP أو قيم RSA</h2><p>⏳ جارٍ قراءة القيم واختيار المحلل المناسب…</p>';
 var controller=typeof AbortController==='function'?new AbortController():null;
 var timer=controller?setTimeout(function(){controller.abort();},40000):null;
 try{
  var base=(location.port==='8765'&&(location.hostname==='127.0.0.1'||location.hostname==='localhost'))?location.origin:'http://127.0.0.1:8765';
  var health=await fetch(base+'/health',{cache:'no-store',signal:controller?controller.signal:undefined}).then(function(r){if(!r.ok)throw new Error('HTTP '+r.status);return r.json();});
  if(!health.rsa_tcp_weak_factors||!health.hashcrack_tcp)throw new Error('يلزم تشغيل محرك صقر 2.59.1 أو أحدث.');
  var response=await fetch(base+'/crypto/analyze',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({confirm:true,challenge_text:text}),cache:'no-store',signal:controller?controller.signal:undefined});
  var data=await response.json();
  if(!response.ok)throw new Error(data.error||data.detail||('HTTP '+response.status));
  var solved=data.success===true&&typeof data.flag==='string'&&data.flag.length>0;
  out.innerHTML='<h2>'+(solved?'🚩 استخرج صقر العلم':'🔐 لم يُستخرج علم مؤكد')+'</h2><p>المحرك: '+esc(data.engine_version||health.version)+' · المحلل: '+esc(data.analyzer||'غير محدد')+'</p>'+(solved?'<div class="flag">'+esc(data.flag)+'</div>':'')+(data.explanation_ar||[]).map(function(t){return '<p>'+esc(t)+'</p>';}).join('')+(data.warnings||[]).map(function(t){return '<div class="finding warn">'+esc(t)+'</div>';}).join('')+'<details><summary>🔧 التفاصيل التقنية</summary><pre>'+esc(JSON.stringify(data,null,2))+'</pre></details>';
 }catch(error){out.innerHTML='<h2>⚠️ تعذر إكمال التحليل</h2><p>'+esc(error.message||error)+'</p><p>تأكد من تشغيل المحرك ومن صلاحية عنوان المثيل. لم يُطبّق ROT13 على وصف التحدي.</p>';}
 finally{if(timer)clearTimeout(timer);busy=false;if(button)button.disabled=previous;if(out.scrollIntoView)out.scrollIntoView({block:'start'});}
 return false;
}
global.FalconTcpCrypto={routePrompt:routePrompt,run:run};
})(window);
