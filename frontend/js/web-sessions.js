(function(){
'use strict';
function esc(t){return String(t==null?'':t).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
var prev=window.FalconRogueTowerRun||window.FalconSmartRun;
function challengeUrl(){
 var input=document.getElementById('text'),text=(input&&input.value||'').trim();
 var matches=text.match(/https?:\/\/[^\s<>\]"')]+/gi)||[];
 for(var i=0;i<matches.length;i++){try{var u=new URL(matches[i]);if(u.hostname.endsWith('.cylabacademy.net'))return u.href;}catch(_){}}
 return null;
}
window.FalconWebSessionRun=async function(){
 var text=challengeUrl();if(!text)return prev?prev():false;
 var r=document.getElementById('result');r.classList.remove('hidden');r.innerHTML='<div class="finding"><h3>🍪 فحص الجلسات</h3><p>جارٍ قراءة استجابة الموقع وكوكيز الجلسة عبر المحرك المحلي v2.1.0…</p></div>';
 try{
 var base=location.hostname==='127.0.0.1'||location.hostname==='localhost'?'':'http://127.0.0.1:8765';
 var response=await fetch(base+'/web/session-audit',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:text})}),d=await response.json();
 if(!response.ok||!d.ok)throw new Error(d.error||'تعذر الفحص');
 r.innerHTML='<div class="finding"><h3>🍪 نتائج فحص الجلسات</h3>'+(d.flags||[]).map(function(f){return '<div class="flag">'+esc(f)+'</div>';}).join('')+'<p>تم تنفيذ طلبين للقراءة مع إعادة استخدام الكوكيز المستلمة.</p>'+(d.cookies||[]).map(function(c){return '<div class="finding"><b>'+esc(c.name)+'</b><p>Expires: '+esc(c.expires||'غير محدد')+' · Max-Age: '+esc(c.max_age||'غير محدد')+'</p><ul>'+c.findings.map(function(f){return '<li>'+esc(f)+'</li>';}).join('')+'</ul>'+c.decoded.map(function(z){return '<pre dir="ltr">'+esc(z)+'</pre>';}).join('')+'</div>';}).join('')+(!d.cookies.length?'<p>لم يرسل الموقع كوكيز في الطلبين. قد يلزم فحص كوكيز الصفحة داخل المتصفح أو جلسة مسجلة.</p>':'')+'<p><b>حدود الفحص:</b> بقاء الكوكي لا يثبت بقاء المصادقة. لم يتم اختبار انتهاء جلسة مسجلة أو إبطالها بعد تسجيل الخروج.</p><p>للتحدي Old Sessions: افتح F12 ثم Storage / Cookies وافحص الكوكيز الموجودة. لا يلزم إدخال بيانات حسابك الحقيقي.</p></div>';
 }catch(e){r.innerHTML='<div class="finding warn"><h3>🍪 تعذر فحص الجلسات</h3><p>'+esc(e.message)+'</p><p>شغّل المحرك v2.1.0 وتأكد أن نسخة التحدي لا تزال فعالة.</p></div>';}
 r.scrollIntoView({behavior:'smooth'});return false;
};
window.FalconSmartRun=window.FalconWebSessionRun;
var solve=document.getElementById('solve');
if(solve)solve.addEventListener('click',function(e){
 if(!challengeUrl())return;
 e.preventDefault();e.stopImmediatePropagation();window.FalconWebSessionRun();
},true);
})();
