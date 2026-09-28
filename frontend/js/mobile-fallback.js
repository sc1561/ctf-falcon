(function(){
function byId(id){return document.getElementById(id);}
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function flags(s){var r=/(?:flag|ctf|moe)[_\- ]?\{[^\r\n{}]{1,200}\}/ig,a=[],m;while((m=r.exec(s||''))!==null)a.push(m[0]);return a;}
function b64(s){try{return atob(String(s).replace(/\s/g,''));}catch(e){return '';}}
function hexDecode(s){try{return (s.match(/[0-9a-f]{2}/ig)||[]).map(function(x){return String.fromCharCode(parseInt(x,16));}).join('');}catch(e){return '';}}
function rot13(s){return String(s).replace(/[A-Za-z]/g,function(c){var a=c<='Z'?65:97;return String.fromCharCode((c.charCodeAt(0)-a+13)%26+a);});}
function analyzeText(raw,deep){
 var result=byId('result'),queue=[{v:raw,p:'Original',d:0}],seen={},rows=[],found=flags(raw),limit=deep?4:2,count=0;
 seen[raw]=1;
 while(queue.length&&count<80){
  var x=queue.shift(); if(x.d>=limit)continue;
  var candidates=[];
  var t=String(x.v||'').trim();
  if(/^[A-Za-z0-9+/=\s]+$/.test(t)&&t.replace(/\s/g,'').length>=8){var z=b64(t);if(z)candidates.push(['Base64',z]);}
  if(/^(?:[0-9a-f]{2}\s*){4,}$/i.test(t)){var h=hexDecode(t);if(h)candidates.push(['Hex',h]);}
  if(/[A-Za-z]{4}/.test(t))candidates.push(['ROT13',rot13(t)]);
  for(var i=0;i<candidates.length;i++){var n=candidates[i][1],p=x.p+' → '+candidates[i][0];if(!seen[n]&&n.length<100000){seen[n]=1;rows.push([p,n]);var ff=flags(n);for(var k=0;k<ff.length;k++)found.push(ff[k]);queue.push({v:n,p:p,d:x.d+1});count++;}}
 }
 var unique=[],u={};for(var q=0;q<found.length;q++)if(!u[found[q]]){u[found[q]]=1;unique.push(found[q]);}
 var detected=[];for(var di=0;di<rows.length;di++){var path=rows[di][0];if(path.indexOf('Base64')>=0&&detected.indexOf('Base64')<0)detected.push('Base64');if(path.indexOf('Hex')>=0&&detected.indexOf('Hex')<0)detected.push('Hex');if(path.indexOf('ROT13')>=0&&detected.indexOf('ROT13')<0)detected.push('ROT13');}
 var html='<div class="studentSummary"><h2>'+(unique.length?'🎉 تم العثور على علم محتمل':'🧭 نتيجة التحليل')+'</h2>';
 html+='<div class="studentCard"><b>1️⃣ ما نوع التحدي؟</b><p>'+(detected.length?'يبدو أنه تحدي ترميز/تشفير نصي.':'لم يتضح نوع الترميز تلقائيًا بعد.')+'</p></div>';
 html+='<div class="studentCard"><b>2️⃣ ماذا اكتشف صقر CTF؟</b><p>'+(detected.length?'اكتشف النظام هذه الطرق: <strong>'+esc(detected.join(' ← '))+'</strong>. جرّبها النظام تلقائيًا، لذلك لا تحتاج إلى فك النص يدويًا.':'لم يجد تحويلًا واضحًا في الفحص الحالي.')+'</p></div>';
 if(unique.length){html+='<div class="studentCard success"><b>3️⃣ العلم المرشح 🚩</b><p>وصل النظام إلى نتيجة تشبه صيغة العلم. انسخها ثم تحقق منها في منصة المسابقة.</p>';for(var f=0;f<unique.length;f++)html+='<div class="flag">'+esc(unique[f])+'</div>';html+='</div>';}
 else html+='<div class="studentCard next"><b>3️⃣ ماذا أفعل الآن؟</b><p>'+(deep?'تم تجربة عدة طبقات تلقائيًا ولم يظهر Flag واضح. انتقل إلى «لم أجد العلم» أو جرّب ملف/معلومة أخرى من التحدي.':'اضغط <strong>🧠 تحليل عميق</strong> ليجرب النظام طبقات إضافية تلقائيًا.')+'</p></div>';
 html+='</div><details class="tech"><summary>🔧 عرض التفاصيل التقنية للمتقدمين</summary><div class="techBody"><h3>مسارات التحليل</h3>';
 for(var r=0;r<Math.min(rows.length,deep?30:12);r++)html+='<div class="finding"><b>'+esc(rows[r][0])+'</b>: <code>'+esc(rows[r][1].slice(0,350))+'</code></div>';
 if(!rows.length)html+='<div class="finding warn">لم يتم اكتشاف ترميز مدعوم في النص الحالي.</div>';
 html+='</div></details>';
 result.innerHTML=html;result.className='result';result.scrollIntoView({behavior:'smooth',block:'start'});
}
window.FalconRun=function(deep){
 var result=byId('result'),ta=byId('text'),fi=byId('file');
 result.className='result';result.innerHTML='<div class="finding">⏳ بدأ التحليل...</div>';
 setTimeout(function(){
  try{
   if(fi&&fi.files&&fi.files.length){result.innerHTML='<div class="finding">📂 تم استلام الملف. تحليل الملفات المتقدم يعمل عبر المحرك الرئيسي. جرّب النص الآن للتأكد من استجابة الأزرار.</div>';return;}
   var raw=ta?ta.value:'';
   if(!raw.trim()){result.innerHTML='<div class="finding warn">الصق نص التحدي أولاً.</div>';return;}
   analyzeText(raw,!!deep);
  }catch(e){result.innerHTML='<div class="finding warn">⚠️ '+esc(e.message||e)+'</div>';}
 },20);
 return false;
};
})();