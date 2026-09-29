(function(){
'use strict';
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function fmt(n){return (n/1048576).toFixed(1)+' MB';}
async function run(){
 var inp=document.getElementById('file'),f=(inp&&inp.files&&inp.files[0])||window.__falconDroppedFile;if(!f)return false;
 if(!/\.img\.gz$/i.test(f.name||''))return false;
 var r=document.getElementById('result');if(!r)return true;r.classList.remove('hidden');
 r.innerHTML='<div class="finding"><h3>🕒 Timeline / Filesystem Analyzer — V115</h3><p>اكتشف صقر صورة قرص مضغوطة مخصصة لتحليل الخط الزمني.</p><p><b>المسار المقترح:</b> IMG.GZ → ext filesystem → Sleuth Kit bodyfile → MAC Timeline → <code>macb</code> → أحدث الملفات</p><p>📦 الملف: <code>'+esc(f.name)+'</code> — '+fmt(f.size)+'</p><div class="finding warn"><b>⚠️ يحتاج محرك Timeline المحلي</b><p>إنشاء MAC timeline الكامل من صورة قرص كبيرة يحتاج أدوات Sleuth Kit مثل <code>fls</code> و<code>mactime</code>. المتصفح لن يخمّن العلم عبر strings بدل التحليل الجنائي المطلوب.</p></div><h4>🔧 أوامر التحليل</h4><pre dir="ltr">gunzip -k '+esc(f.name)+'\nfls -r -m / '+esc((f.name||'disk.img.gz').replace(/\.gz$/i,''))+' > bodyfile.txt\nmactime -b bodyfile.txt > timeline.csv\ngrep "macb" timeline.csv | tail -n 50</pre><p>بعد تشغيلها، الصق آخر الأسطر في مربع النص الرئيسي واضغط <b>حلّل التحدي</b> ليكمل صقر فرز الأحداث والبحث عن الدليل.</p><details><summary>🧠 لماذا macb؟</summary><p><code>m a c b</code> تشير إلى وجود أزمنة Modified / Accessed / Changed / Birth للملف في سجل Sleuth Kit، وهي النقطة التي يطلبها تلميح التحدي للتركيز على الملفات الجديدة قرب النشاط المضاد للتحليل الجنائي.</p></details></div>';
 r.scrollIntoView({behavior:'smooth',block:'start'});return true;
}
var prev=window.FalconSmartRun;
window.FalconTimelineRun=async function(){try{if(await run())return false;}catch(e){console.warn('Falcon Timeline',e);}return prev?prev():false;};
window.FalconSmartRun=window.FalconTimelineRun;
})();