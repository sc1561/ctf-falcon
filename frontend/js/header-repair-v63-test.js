(function(){
var originalRun=window.FalconSmartRun;
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function genericFlags(s){return String(s||'').match(/[A-Za-z][A-Za-z0-9_.:-]{1,30}\{[^{}\r\n]{2,200}\}/g)||[];}
function hex2(u8,n){var a=[];for(var i=0;i<Math.min(n||16,u8.length);i++)a.push(u8[i].toString(16).padStart(2,'0').toUpperCase());return a.join(' ');}
function looksCorruptJpeg(u8){
 if(!u8||u8.length<12)return false;
 if(u8[0]===0xFF&&u8[1]===0xD8&&u8[2]===0xFF)return false;
 /* Conservative V63 rule: bytes 2..11 already look like a normal JPEG APP0/APP1 header.
    Only repair the two-byte SOI; never rewrite arbitrary data. */
 if(u8[2]!==0xFF)return false;
 var marker=u8[3];
 if(marker!==0xE0&&marker!==0xE1&&marker!==0xDB&&marker!==0xEE)return false;
 if(marker===0xE0&&u8.length>=11){
  var id=String.fromCharCode.apply(null,u8.slice(6,11));
  if(id!=='JFIF\x00'&&id!=='JFXX\x00')return false;
 }
 if(marker===0xE1&&u8.length>=10){
  var ex=String.fromCharCode.apply(null,u8.slice(6,10));
  if(ex!=='Exif')return false;
 }
 return true;
}
async function repairHeader(file){
 if(!file||file.size<12)return false;
 var ab=await file.arrayBuffer(),u8=new Uint8Array(ab);
 if(!looksCorruptJpeg(u8))return false;
 var before=hex2(u8,12),fixed=new Uint8Array(u8);fixed[0]=0xFF;fixed[1]=0xD8;
 var after=hex2(fixed,12),blob=new Blob([fixed],{type:'image/jpeg'}),url=URL.createObjectURL(blob),result=document.getElementById('result');
 result.className='result';
 result.innerHTML='<div class="studentSummary"><h2>🩺 File Header Repair — V63 TEST</h2><div class="studentCard"><b>1️⃣ ماذا اكتشف صقر؟</b><p>الملف لا يبدأ بتوقيع JPEG الصحيح، لكن البنية التالية للهيدر تطابق JPEG بدرجة عالية.</p><p><strong>قبل:</strong> <code>'+esc(before)+'</code></p><p><strong>بعد الإصلاح الآمن:</strong> <code>'+esc(after)+'</code></p><div class="solvePath">Broken File → Header Inspection → JPEG Signature Mismatch → Repair FF D8</div></div><div class="studentCard success"><b>2️⃣ الملف المستعاد</b><p>تم تعديل أول بايتين فقط داخل نسخة مؤقتة في الذاكرة. الملف الأصلي لم يتغير.</p><img id="falconV63Image" src="'+url+'" style="max-width:100%;height:auto;border-radius:12px;margin-top:10px"><p><a href="'+url+'" download="falcon_header_repaired.jpg">💾 حفظ JPEG المستعاد</a></p></div><div class="studentCard"><b>3️⃣ Visual Evidence Hunter</b><div id="falconV63Ocr" class="finding">⏳ جارٍ قراءة النص الظاهر داخل الصورة...</div><div class="solvePath">JPEG Repair → Reconstruct → OCR → Flag</div></div></div>';
 setTimeout(async function(){
  var st=document.getElementById('falconV63Ocr');if(!st)return;
  try{
   for(var w=0;w<20&&typeof Tesseract==='undefined';w++)await new Promise(function(r){setTimeout(r,250);});
   if(typeof Tesseract==='undefined'){st.className='finding warn';st.innerHTML='⚠️ تم إصلاح JPEG، لكن OCR غير متاح.';return;}
   var img=document.getElementById('falconV63Image'),targets=[url];
   if(img&&img.naturalWidth){
    var c=document.createElement('canvas'),cx=c.getContext('2d');c.width=img.naturalWidth*2;c.height=img.naturalHeight*2;cx.drawImage(img,0,0,c.width,c.height);targets.push(c.toDataURL('image/png'));
   }
   var found=[];
   for(var i=0;i<targets.length&&!found.length;i++){var rec=await Tesseract.recognize(targets[i],'eng'),txt=(rec&&rec.data&&rec.data.text)||'';found=genericFlags(txt);}
   if(found.length){st.className='finding success';st.innerHTML='<b>🚩 تم الوصول إلى العلم تلقائيًا</b><div class="solvePath">Broken File → JPEG Header Repair → Image → OCR → Flag</div>'+found.map(function(v){return '<div class="flag">'+esc(v)+'</div>';}).join('');}
   else{st.className='finding warn';st.innerHTML='تم إصلاح الصورة بنجاح، لكن OCR لم يستخرج Flag موثوقًا تلقائيًا. افحص الصورة المستعادة.';}
  }catch(e){st.className='finding warn';st.innerHTML='تم إصلاح JPEG، لكن تعذر OCR: '+esc(e.message||e);}
 },100);
 return true;
}
window.FalconSmartRun=function(){
 var fi=document.getElementById('file'),ta=document.getElementById('text'),chosen=(fi&&fi.files&&fi.files.length)?fi.files[0]:window.__falconDroppedFile;
 if(chosen&&(!ta||!ta.value.trim())){repairHeader(chosen).then(function(hit){if(!hit)originalRun();});return false;}
 return originalRun();
};
})();