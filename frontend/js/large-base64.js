(function(){
var originalRun=window.FalconSmartRun;
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function genericFlags(s){return String(s||'').match(/[A-Za-z][A-Za-z0-9_.:-]{1,30}\{[^{}\r\n]{2,200}\}/g)||[];}
function hexText(s){try{return (String(s).match(/[0-9a-f]{2}/ig)||[]).map(function(x){return String.fromCharCode(parseInt(x,16));}).join('');}catch(e){return '';}}
function decodedType(u8){
 if(u8.length>=8&&u8[0]===137&&u8[1]===80&&u8[2]===78&&u8[3]===71)return ['PNG','image/png','png'];
 if(u8.length>=3&&u8[0]===255&&u8[1]===216&&u8[2]===255)return ['JPEG','image/jpeg','jpg'];
 if(u8.length>=4&&u8[0]===80&&u8[1]===75&&u8[2]===3&&u8[3]===4)return ['ZIP','application/zip','zip'];
 if(u8.length>=4&&u8[0]===37&&u8[1]===80&&u8[2]===68&&u8[3]===70)return ['PDF','application/pdf','pdf'];
 return null;
}
async function largeBase64(file){
 if(!file||file.size<128)return false;
 var raw=await file.text(),clean=raw.replace(/\s+/g,'');
 /* V62: do not require the whole TXT to be pure Base64. CTF files can contain
    labels, quotes or log-like prefixes. Prefer a known file-signature prefix,
    then fall back to the largest Base64-looking block. */
 if(clean.length<128||!/^[A-Za-z0-9+/]+={0,2}$/.test(clean)){
  var compact=raw.replace(/[\r\n\t ]+/g,''),starts=['iVBORw0KGgo','/9j/','JVBERi0','UEsDB'],pos=-1;
  for(var si=0;si<starts.length;si++){var sp=compact.indexOf(starts[si]);if(sp>=0&&(pos<0||sp<pos))pos=sp;}
  if(pos>=0){
   var tail=compact.slice(pos),mm=tail.match(/^[A-Za-z0-9+/]+={0,2}/);clean=mm?mm[0]:'';
  }else{
   var blocks=raw.match(/[A-Za-z0-9+/=\r\n\t ]{128,}/g)||[];
   blocks=blocks.map(function(v){return v.replace(/\s+/g,'');}).filter(function(v){return /^[A-Za-z0-9+/]+={0,2}$/.test(v);}).sort(function(x,y){return y.length-x.length;});
   clean=blocks[0]||'';
  }
 }
 while(clean.length%4)clean=clean.slice(0,-1);
 if(clean.length<128)return false;
 var bin;try{bin=atob(clean);}catch(e){return false;}
 var u8=new Uint8Array(bin.length);for(var i=0;i<bin.length;i++)u8[i]=bin.charCodeAt(i)&255;
 var t=decodedType(u8);if(!t)return false;
 var result=document.getElementById('result'),blob=new Blob([u8],{type:t[1]}),url=URL.createObjectURL(blob);
 result.className='result';
 var h='<div class="studentSummary"><h2>🔥 Large Base64 Reconstruction</h2><div class="studentCard"><b>1️⃣ ماذا اكتشف صقر؟</b><p>الملف النصي يحتوي على كتلة Base64 كبيرة. تم فك <strong>'+clean.length+'</strong> حرفًا إلى <strong>'+u8.length+'</strong> بايت.</p><div class="solvePath">TXT → Large Base64 → Bytes → '+t[0]+' Signature</div></div>';
 if(t[0]==='PNG'||t[0]==='JPEG'){
  h+='<div class="studentCard success"><b>2️⃣ الملف المستعاد</b><p>تم التعرف على صورة <strong>'+t[0]+'</strong> وإعادة بنائها تلقائيًا.</p><img id="falconB64Image" src="'+url+'" style="max-width:100%;height:auto;border-radius:12px;margin-top:10px"><p><a href="'+url+'" download="falcon_base64_recovered.'+t[2]+'">💾 حفظ الصورة المستعادة</a></p></div><div class="studentCard"><b>3️⃣ Visual Evidence Hunter</b><div id="falconB64Ocr" class="finding">⏳ جارٍ قراءة النص الظاهر داخل الصورة ثم اختبار Hex/Flag...</div><div class="solvePath">Base64 → '+t[0]+' → OCR → Hex → Flag</div></div>';
 }else h+='<div class="studentCard success"><b>2️⃣ الملف المستعاد</b><p>تم التعرف على <strong>'+t[0]+'</strong>.</p><a href="'+url+'" download="falcon_base64_recovered.'+t[2]+'">💾 حفظ الملف المستعاد</a></div>';
 result.innerHTML=h+'</div>';
 if(t[0]!=='PNG'&&t[0]!=='JPEG')return true;
 setTimeout(async function(){
  var st=document.getElementById('falconB64Ocr');if(!st)return;
  try{
   for(var w=0;w<20&&typeof Tesseract==='undefined';w++)await new Promise(function(r){setTimeout(r,250);});
   if(typeof Tesseract==='undefined'){st.className='finding warn';st.innerHTML='⚠️ تم استعادة الصورة بنجاح، لكن OCR غير متاح. افحص النص الظاهر داخل الصورة.';return;}
   var rec=await Tesseract.recognize(url,'eng'),txt=(rec&&rec.data&&rec.data.text)||'',found=genericFlags(txt),hexes=txt.replace(/\s+/g,' ').match(/(?:[0-9a-fA-F]{2}[\s:]*){12,}/g)||[],decoded=[];
   for(var x=0;x<hexes.length;x++){var hx=hexes[x].replace(/[^0-9a-f]/gi,'');if(hx.length%2)continue;var d=hexText(hx),ff=genericFlags(d);for(var f=0;f<ff.length;f++)decoded.push(ff[f]);}
   var all=found.concat(decoded).filter(function(v,i,a){return a.indexOf(v)===i;});
   if(all.length){st.className='finding success';st.innerHTML='<b>🚩 تم الوصول إلى العلم تلقائيًا</b><div class="solvePath">TXT → Large Base64 → '+t[0]+' → OCR → Hex → Flag</div>'+all.map(function(v){return '<div class="flag">'+esc(v)+'</div>';}).join('');}
   else{st.className='finding warn';st.innerHTML='تمت إعادة بناء الصورة وقراءة النص، لكن لم يظهر Flag موثوق تلقائيًا. افحص النص الظاهر في الصورة أو احفظها للتحليل اليدوي.';}
  }catch(e){st.className='finding warn';st.innerHTML='تمت إعادة بناء الصورة، لكن تعذر OCR: '+esc(e.message||e);}
 },100);
 return true;
}
window.FalconSmartRun=function(){
 var fi=document.getElementById('file'),ta=document.getElementById('text'),chosen=(fi&&fi.files&&fi.files.length)?fi.files[0]:window.__falconDroppedFile;
 if(chosen&&(!ta||!ta.value.trim())){largeBase64(chosen).then(function(hit){if(!hit)originalRun();});return false;}
 return originalRun();
};
})();