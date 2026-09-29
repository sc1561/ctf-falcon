(function(){
 var prev=window.FalconSmartRun;
 function el(x){return document.getElementById(x);}
 function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
 function ascii(u,a,b){var s='';for(var i=a;i<Math.min(b,u.length);i++)s+=String.fromCharCode(u[i]);return s;}
 function find(u,s,start){var b=new TextEncoder().encode(s);outer:for(var i=start||0;i<=u.length-b.length;i++){for(var j=0;j<b.length;j++)if(u[i+j]!==b[j])continue outer;return i;}return -1;}
 function flag(s){var m=String(s||'').match(/(?:academy|flag|ctf|moe)\{[^}\r\n]+\}/i);return m&&m[0];}
 async function run(){
  var file=el('file')&&el('file').files&&el('file').files[0]; if(!file&&window.__falconDroppedFile)file=window.__falconDroppedFile;
  if(!file)return prev?prev():false;
  var u=new Uint8Array(await file.arrayBuffer()), png=u.length>8&&u[0]===137&&u[1]===80&&u[2]===78&&u[3]===71, pdf=find(u,'%PDF-',0);
  if(!png||pdf<0)return prev?prev():false;
  var out=el('result'); out.className='result';
  var chunks=[], re=/(?:academy|flag|ctf|moe)\{[^}\r\n]*|[A-Za-z0-9_@&!$#-]{5,}\}/ig, all=ascii(u,0,u.length),m;
  while((m=re.exec(all)))chunks.push(m[0]);
  var direct=flag(all);
  var pngPart=null,pdfPart=null,joined=null;
  var pm=all.slice(0,pdf).match(/(?:academy|flag|ctf|moe)\{[^\r\n\x00]*/i); if(pm)pngPart=pm[0].replace(/[^\x20-\x7e]+$/,'');
  var tail=all.slice(pdf); var tm=tail.match(/[A-Za-z0-9_@&!$#-]{4,}\}/); if(tm)pdfPart=tm[0];
  if(pngPart&&pdfPart)joined=pngPart+pdfPart;
  if(joined&&!flag(joined))joined=null;
  out.innerHTML='<div class="studentSummary"><h2>🧬 Polyglot Analyzer</h2><div class="solvePath">Magic Bytes → PNG + Embedded PDF → استخراج الجزأين → دمج Flag</div><div class="studentCard success"><h3>✅ تم اكتشاف ملف Polyglot</h3><p>التوقيع الأول: <code>PNG</code></p><p>PDF مضمّن عند البايت: <code>'+pdf+'</code></p>'+(direct?'<h3>🚩 تم العثور على العلم</h3><code>'+esc(direct)+'</code>':joined?'<p>🖼️ جزء PNG: <code>'+esc(pngPart)+'</code></p><p>📄 جزء PDF: <code>'+esc(pdfPart)+'</code></p><h3>🚩 تم دمج العلم</h3><code>'+esc(joined)+'</code>':'<p>تم اكتشاف البنية المزدوجة، لكن تعذر دمج جزأي العلم تلقائيًا.</p>')+'</div></div>';
  return false;
 }
 window.FalconPolyglotRun=run; window.FalconSmartRun=run;
})();