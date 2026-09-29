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
  try{if(window.Tesseract){var pngBlob=new Blob([u.slice(0,pdf)],{type:'image/png'});var bmp=await createImageBitmap(pngBlob),best='',votes=[]; for(var sc=3;sc<=14;sc++){var cv=document.createElement('canvas');cv.width=bmp.width*sc;cv.height=bmp.height*sc;var cx=cv.getContext('2d');cx.imageSmoothingEnabled=false;cx.drawImage(bmp,0,0,cv.width,cv.height);for(var mode=0;mode<2;mode++){if(mode){var im=cx.getImageData(0,0,cv.width,cv.height),d=im.data;for(var z=0;z<d.length;z+=4){var g=(d[z]+d[z+1]+d[z+2])/3,v=g<160?0:255;d[z]=d[z+1]=d[z+2]=v;}cx.putImageData(im,0,0);}var rr=await Tesseract.recognize(cv,'eng',{},{tessedit_char_whitelist:'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_{}@&!$#-'});var tx=((rr&&rr.data&&rr.data.text)||'').replace(/\s+/g,'');if(tx){votes.push(tx);if(tx.length>best.length)best=tx;} if(rr&&rr.data&&rr.data.symbols){var sy=rr.data.symbols.map(function(s){return {t:s.text,c:s.confidence};}); window.__falconPolySymbols=(window.__falconPolySymbols||[]).concat(sy);}}}if(bmp.close)bmp.close();ocrText=best; var bodies=votes.map(function(v){var mm=v.match(/[A-Za-z]{5,12}\{([^}]*)/);return mm&&mm[1];}).filter(Boolean);if(bodies.length){var L=Math.max.apply(null,bodies.map(function(x){return x.length;})),cons='';for(var q=0;q<L;q++){var cnt={};bodies.forEach(function(x){if(x[q])cnt[x[q]]=(cnt[x[q]]||0)+1;});var ks=Object.keys(cnt).sort(function(a,b){return cnt[b]-cnt[a];});if(ks.length)cons+=ks[0];}ocrText='academy{'+cons;} var ambiguous=/[lIiyt]/.test(ocrText);}}catch(e){}
  var pdfText='';
  try{if(window.pako){var tailBytes=u.slice(pdf), marker=new TextEncoder().encode('stream'), endm=new TextEncoder().encode('endstream');function fb(h,n,s){outer:for(var ii=s||0;ii<=h.length-n.length;ii++){for(var jj=0;jj<n.length;jj++)if(h[ii+jj]!==n[jj])continue outer;return ii;}return -1;}var pos=0;while((pos=fb(tailBytes,marker,pos))>=0){var st=pos+marker.length;while(st<tailBytes.length&&(tailBytes[st]===13||tailBytes[st]===10))st++;var en=fb(tailBytes,endm,st);if(en<0)break;try{pdfText+=new TextDecoder('latin1').decode(pako.inflate(tailBytes.slice(st,en)))+'\n';}catch(e){}pos=en+endm.length;}}}catch(e){}
  var pngPart=null,pdfPart=null,joined=null;
  var cleanOcr=(ocrText||'').replace(/\s+/g,'').replace(/[^A-Za-z0-9_{}@&!$#-]/g,''); var pm=cleanOcr.match(/([A-Za-z]{6,12})\{([^}]{3,})/i); if(pm){var word=pm[1].toLowerCase(),body=pm[2]; function dist(a,b){var d=Array(b.length+1).fill(0).map(function(_,i){return i});for(var i=1;i<=a.length;i++){var p=d.slice();d[0]=i;for(var j=1;j<=b.length;j++)d[j]=Math.min(d[j-1]+1,p[j]+1,p[j-1]+(a[i-1]===b[j-1]?0:1));}return d[b.length];} var known=['academy','flag','ctf','moe'],best=known[0],bd=99;known.forEach(function(k){var z=dist(word,k);if(z<bd){bd=z;best=k;}}); if(bd<=2)pngPart=best+'{'+body;}
  var tail=all.slice(pdf); var tm=pdfText.match(/\(([^()]{4,}\})\)\s*Tj/i); if(tm)pdfPart=tm[1]; else {tm=tail.match(/[A-Za-z0-9_@&!$#-]{4,}\}/);if(tm)pdfPart=tm[0];}
  if(pngPart&&pdfPart)joined=pngPart+pdfPart;
  if(joined&&!flag(joined))joined=null;
  if(joined&&ambiguous)joined=null;
  var sym=(window.__falconPolySymbols||[]).slice(-120).map(function(s){return s.t+':'+Math.round(s.c);}).join(' | '); var diag='<details open><summary>🔬 تشخيص الاستخراج</summary><p>PNG OCR: <code>'+esc(ocrText||'—')+'</code></p><p>PDF text: <code>'+esc(pdfText||'—')+'</code></p><p>PNG candidate: <code>'+esc(pngPart||'—')+'</code></p><p>PDF candidate: <code>'+esc(pdfPart||'—')+'</code></p><p>OCR symbols/confidence: <code>'+esc(sym||'—')+'</code></p></details>';
  out.innerHTML='<div class="studentSummary"><h2>🧬 Polyglot Analyzer</h2><div class="solvePath">Magic Bytes → PNG + Embedded PDF → استخراج الجزأين → دمج Flag</div><div class="studentCard success"><h3>✅ تم اكتشاف ملف Polyglot</h3><p>التوقيع الأول: <code>PNG</code></p><p>PDF مضمّن عند البايت: <code>'+pdf+'</code></p>'+(direct?'<h3>🚩 تم العثور على العلم</h3><code>'+esc(direct)+'</code>':joined?'<p>🖼️ جزء PNG: <code>'+esc(pngPart)+'</code></p><p>📄 جزء PDF: <code>'+esc(pdfPart)+'</code></p><h3>🚩 تم دمج العلم</h3><code>'+esc(joined)+'</code>':'<p>⚠️ تم استخراج الجزأين، لكن OCR يحتوي أحرفًا متشابهة بصريًا (مثل 1/l أو 7/y). لذلك لن يعرض صقر علمًا نهائيًا غير موثوق.</p><p>🖼️ قراءة PNG الحالية: <code>'+esc(pngPart||'—')+'</code></p><p>📄 جزء PDF المؤكد: <code>'+esc(pdfPart||'—')+'</code></p>')+diag+'</div></div>';
  return false;
 }
 window.FalconPolyglotRun=run; window.FalconSmartRun=run;
})();