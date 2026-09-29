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
  // V101: real extraction: OCR the PNG view and inflate PDF text streams.
  var ocrText='';
  try{if(window.Tesseract){var pngBlob=new Blob([u.slice(0,pdf)],{type:'image/png'});var bmp=await createImageBitmap(pngBlob),cv=document.createElement('canvas'),scale=6;cv.width=bmp.width*scale;cv.height=bmp.height*scale;var cx=cv.getContext('2d');cx.imageSmoothingEnabled=false;cx.drawImage(bmp,0,0,cv.width,cv.height);if(bmp.close)bmp.close();var rr=await Tesseract.recognize(cv,'eng');ocrText=(rr&&rr.data&&rr.data.text)||'';}}catch(e){}
  var pdfText='';
  try{if(window.pako){var tailBytes=u.slice(pdf), marker=new TextEncoder().encode('stream'), endm=new TextEncoder().encode('endstream');function fb(h,n,s){outer:for(var ii=s||0;ii<=h.length-n.length;ii++){for(var jj=0;jj<n.length;jj++)if(h[ii+jj]!==n[jj])continue outer;return ii;}return -1;}var pos=0;while((pos=fb(tailBytes,marker,pos))>=0){var st=pos+marker.length;while(st<tailBytes.length&&(tailBytes[st]===13||tailBytes[st]===10))st++;var en=fb(tailBytes,endm,st);if(en<0)break;try{pdfText+=new TextDecoder('latin1').decode(pako.inflate(tailBytes.slice(st,en)))+'\n';}catch(e){}pos=en+endm.length;}}}catch(e){}
  var pngPart=null,pdfPart=null,joined=null;
  var pm=ocrText.match(/(?:academy|flag|ctf|moe)\s*\{[^\r\n]*/i); if(pm)pngPart=pm[0].replace(/\s+/g,'').replace(/[^\x20-\x7e]+$/,'');
  var tail=all.slice(pdf); var tm=pdfText.match(/\(([^()]{4,}\})\)\s*Tj/i); if(tm)pdfPart=tm[1]; else {tm=tail.match(/[A-Za-z0-9_@&!$#-]{4,}\}/);if(tm)pdfPart=tm[0];}
  if(pngPart&&pdfPart)joined=pngPart+pdfPart;
  if(joined&&!flag(joined))joined=null;
  out.innerHTML='<div class="studentSummary"><h2>🧬 Polyglot Analyzer</h2><div class="solvePath">Magic Bytes → PNG + Embedded PDF → استخراج الجزأين → دمج Flag</div><div class="studentCard success"><h3>✅ تم اكتشاف ملف Polyglot</h3><p>التوقيع الأول: <code>PNG</code></p><p>PDF مضمّن عند البايت: <code>'+pdf+'</code></p>'+(direct?'<h3>🚩 تم العثور على العلم</h3><code>'+esc(direct)+'</code>':joined?'<p>🖼️ جزء PNG: <code>'+esc(pngPart)+'</code></p><p>📄 جزء PDF: <code>'+esc(pdfPart)+'</code></p><h3>🚩 تم دمج العلم</h3><code>'+esc(joined)+'</code>':'<p>تم اكتشاف البنية المزدوجة، لكن تعذر دمج جزأي العلم تلقائيًا.</p>')+'</div></div>';
  return false;
 }
 window.FalconPolyglotRun=run; window.FalconSmartRun=run;
})();