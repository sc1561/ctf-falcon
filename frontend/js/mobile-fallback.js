(function(){
function byId(id){return document.getElementById(id);}
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function flags(s){var r=/(?:flag|ctf|moe)[_\- ]?\{[^\r\n{}]{1,200}\}/ig,a=[],m;while((m=r.exec(s||''))!==null)a.push(m[0]);return a;}
function b64(s){try{return atob(String(s).replace(/\s/g,''));}catch(e){return '';}}
function hexDecode(s){try{return (s.match(/[0-9a-f]{2}/ig)||[]).map(function(x){return String.fromCharCode(parseInt(x,16));}).join('');}catch(e){return '';}}
function rotN(s,n){return String(s).replace(/[A-Za-z]/g,function(c){var a=c<='Z'?65:97;return String.fromCharCode((c.charCodeAt(0)-a+n)%26+a);});}
function rot13(s){return rotN(s,13);}
function binaryDecode(s){try{var b=String(s).replace(/\s/g,'');if(!/^[01]+$/.test(b)||b.length%8)return '';return (b.match(/.{8}/g)||[]).map(function(x){return String.fromCharCode(parseInt(x,2));}).join('');}catch(e){return '';}}
function urlDecode(s){try{var x=decodeURIComponent(String(s).replace(/\+/g,' '));return x!==s?x:'';}catch(e){return '';}}
var MORSE={'.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E','..-.':'F','--.':'G','....':'H','..':'I','.---':'J','-.-':'K','.-..':'L','--':'M','-.':'N','---':'O','.--.':'P','--.-':'Q','.-.':'R','...':'S','-':'T','..-':'U','...-':'V','.--':'W','-..-':'X','-.--':'Y','--..':'Z','-----':'0','.----':'1','..---':'2','...--':'3','....-':'4','.....':'5','-....':'6','--...':'7','---..':'8','----.':'9'};
function morseDecode(s){var t=String(s).trim();if(!/^[.\-\/\s]+$/.test(t))return '';var bad=false,v=t.split(/\s*\/\s*/).map(function(w){return w.split(/\s+/).map(function(x){if(!MORSE[x]){bad=true;return '?';}return MORSE[x];}).join('');}).join(' ');return bad?'':v;}
function quality(s){s=String(s||'');if(!s)return 0;var printable=(s.match(/[\x20-\x7e\r\n\t]/g)||[]).length/Math.max(1,s.length),score=Math.round(printable*40);if(flags(s).length)score+=200;if(/flag|ctf|moe|secret|password|key|token/i.test(s))score+=60;if(/[{}]/.test(s))score+=10;return score;}
function candidates(t){var a=[],z;t=String(t||'').trim();if(/^[A-Za-z0-9+/=\s]+$/.test(t)&&t.replace(/\s/g,'').length>=8&&(t.replace(/\s/g,'').length%4===0)){z=b64(t);if(z)a.push(['Base64',z]);}if(/^(?:[0-9a-f]{2}\s*){4,}$/i.test(t)){z=hexDecode(t);if(z)a.push(['Hex',z]);}if(/^[01\s]{8,}$/.test(t)){z=binaryDecode(t);if(z)a.push(['Binary',z]);}z=urlDecode(t);if(z)a.push(['URL Decode',z]);if(/^[.\-\/\s]+$/.test(t)&&t.length>5){z=morseDecode(t);if(z)a.push(['Morse',z]);}if(/[A-Za-z]{4}/.test(t))a.push(['ROT13',rot13(t)]);if(/^[A-Za-z ]{6,}$/.test(t)){for(var n=1;n<26;n++){z=rotN(t,n);if(/flag|ctf|moe|secret|key/i.test(z))a.push(['Caesar +'+n,z]);}}return a;}
function analyzeText(raw,deep){
 var result=byId('result'),queue=[{v:raw,p:'Original',d:0}],seen={},rows=[],found=[],limit=deep?6:3,count=0,best={score:quality(raw),path:'Original',value:raw};
 seen[raw]=1;var direct=flags(raw);for(var df=0;df<direct.length;df++)found.push({flag:direct[df],path:'Original'});
 while(queue.length&&count<(deep?240:90)){
  var x=queue.shift();if(x.d>=limit)continue;var cs=candidates(x.v);
  cs.sort(function(a,b){return quality(b[1])-quality(a[1]);});
  for(var i=0;i<cs.length;i++){var n=cs[i][1],p=x.p+' → '+cs[i][0];if(!seen[n]&&n.length<100000){seen[n]=1;var sc=quality(n);rows.push({path:p,value:n,score:sc,depth:x.d+1});if(sc>best.score)best={score:sc,path:p,value:n};var ff=flags(n);for(var k=0;k<ff.length;k++)found.push({flag:ff[k],path:p});queue.push({v:n,p:p,d:x.d+1});count++;}}
 }
 rows.sort(function(a,b){return b.score-a.score||a.depth-b.depth;});
 var unique=[],u={},flagPaths={};for(var q=0;q<found.length;q++)if(!u[found[q].flag]){u[found[q].flag]=1;unique.push(found[q].flag);flagPaths[found[q].flag]=found[q].path;}
 var detected=[];var names=['Base64','Hex','Binary','URL Decode','ROT13','Morse','Caesar'];for(var ni=0;ni<names.length;ni++){for(var di=0;di<rows.length;di++)if(rows[di].path.indexOf(names[ni])>=0){detected.push(names[ni]);break;}}
 var html='<div class="studentSummary"><h2>'+(unique.length?'🎉 تم العثور على علم محتمل':'🧭 نتيجة التحليل')+'</h2>';
 html+='<div class="studentCard"><b>1️⃣ ما نوع التحدي؟</b><p>'+(detected.length?'يبدو أنه تحدي ترميز/تشفير نصي متعدد المراحل.':'لم يتضح نوع الترميز تلقائيًا بعد.')+'</p></div>';
 html+='<div class="studentCard"><b>2️⃣ ماذا اكتشف صقر CTF؟</b><p>'+(detected.length?'جرّب النظام تلقائيًا: <strong>'+esc(detected.join('، '))+'</strong>، وتتبع حتى '+limit+' طبقات دون الحاجة لفك النص يدويًا.':'لم يجد تحويلًا واضحًا في الفحص الحالي.')+'</p></div>';
 if(unique.length){html+='<div class="studentCard success"><b>3️⃣ العلم المرشح 🚩</b><p>نجح النظام في الوصول إلى صيغة علم. مسار الحل:</p>';for(var f=0;f<unique.length;f++)html+='<div class="solvePath">'+esc(flagPaths[unique[f]])+'</div><div class="flag">'+esc(unique[f])+'</div>';html+='</div>';}
 else{html+='<div class="studentCard next"><b>3️⃣ أين وصلنا؟</b><p>أفضل مسار حتى الآن: <strong>'+esc(best.path)+'</strong>.</p><p>لم تظهر صيغة Flag واضحة بعد. '+(deep?'هذا يعني غالبًا أن التحدي يحتاج نوع تحليل آخر أو معلومة/ملفًا إضافيًا، وليس مجرد زيادة طبقات عشوائية.':'اضغط <strong>🧠 تحليل عميق</strong> ليكمل النظام المسارات الواعدة فقط.')+'</p></div>';}
 html+='</div><details class="tech"><summary>🔧 عرض التفاصيل التقنية للمتقدمين</summary><div class="techBody"><h3>أفضل مسارات التحليل</h3>';
 for(var r=0;r<Math.min(rows.length,deep?35:15);r++)html+='<div class="finding"><b>'+esc(rows[r].path)+'</b> <span class="score">درجة '+rows[r].score+'</span>: <code>'+esc(rows[r].value.slice(0,350))+'</code></div>';
 if(!rows.length)html+='<div class="finding warn">لم يتم اكتشاف ترميز مدعوم في النص الحالي.</div>';html+='</div></details>';
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