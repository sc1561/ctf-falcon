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
 result.innerHTML='<div class="studentSummary"><h2>🩺 File Header Repair — V72 TEST</h2><div class="studentCard"><b>1️⃣ ماذا اكتشف صقر؟</b><p>الملف لا يبدأ بتوقيع JPEG الصحيح، لكن البنية التالية للهيدر تطابق JPEG بدرجة عالية.</p><p><strong>قبل:</strong> <code>'+esc(before)+'</code></p><p><strong>بعد الإصلاح الآمن:</strong> <code>'+esc(after)+'</code></p><div class="solvePath">Broken File → Header Inspection → JPEG Signature Mismatch → Repair FF D8</div></div><div class="studentCard success"><b>2️⃣ الملف المستعاد</b><p>تم تعديل أول بايتين فقط داخل نسخة مؤقتة في الذاكرة. الملف الأصلي لم يتغير.</p><img id="falconV63Image" src="'+url+'" style="max-width:100%;height:auto;border-radius:12px;margin-top:10px"><p><a href="'+url+'" download="falcon_header_repaired.jpg">💾 حفظ JPEG المستعاد</a></p></div><div class="studentCard"><b>3️⃣ Visual Evidence Hunter</b><div id="falconV63Ocr" class="finding">⏳ جارٍ قراءة النص الظاهر داخل الصورة...</div><div class="solvePath">JPEG Repair → Reconstruct → OCR → Flag</div></div></div>';
 setTimeout(async function(){
  var st=document.getElementById('falconV63Ocr');if(!st)return;
  try{
   for(var w=0;w<20&&typeof Tesseract==='undefined';w++)await new Promise(function(r){setTimeout(r,250);});
   if(typeof Tesseract==='undefined'){st.className='finding warn';st.innerHTML='⚠️ تم إصلاح JPEG، لكن OCR غير متاح.';return;}
   var img=document.getElementById('falconV63Image');
   if(img&&!img.complete)await new Promise(function(r){img.addEventListener('load',r,{once:true});});
   var targets=[url];
   if(img&&img.naturalWidth){
    /* V64 visual pass: preserve the successful header repair and only improve OCR.
       Try full image + scaled/gray/threshold variants + top/bottom crops. */
    var scales=[2,3,4],modes=['normal','gray','threshold'];
    for(var si=0;si<scales.length;si++)for(var mi=0;mi<modes.length;mi++){
     var sc=scales[si],cv=document.createElement('canvas'),cx=cv.getContext('2d');
     cv.width=img.naturalWidth*sc;cv.height=img.naturalHeight*sc;cx.drawImage(img,0,0,cv.width,cv.height);
     if(modes[mi]!=='normal'){
      var id=cx.getImageData(0,0,cv.width,cv.height),d=id.data;
      for(var pi=0;pi<d.length;pi+=4){var g=Math.round(.299*d[pi]+.587*d[pi+1]+.114*d[pi+2]);if(modes[mi]==='threshold')g=g>145?255:0;d[pi]=d[pi+1]=d[pi+2]=g;}cx.putImageData(id,0,0);
     }
     targets.push(cv.toDataURL('image/png'));
    }
    var crops=[[0,.55,1,.45],[0,0,1,.45]];
    for(var ci=0;ci<crops.length;ci++){
     var cr=crops[ci],cc=document.createElement('canvas'),ccx=cc.getContext('2d'),cw=img.naturalWidth,ch=Math.floor(img.naturalHeight*cr[3]),sy=Math.floor(img.naturalHeight*cr[1]);
     cc.width=cw*4;cc.height=ch*4;ccx.drawImage(img,0,sy,cw,ch,0,0,cc.width,cc.height);targets.push(cc.toDataURL('image/png'));
    }
   }
   var found=[],allText='',flagish=[],votes={},normalizedCandidates=[];
   for(var i=0;i<targets.length&&!found.length;i++){
    st.innerHTML='⏳ Visual Evidence Hunter: محاولة '+(i+1)+' من '+targets.length+'...';
    var rec=await Tesseract.recognize(targets[i],'eng'),txt=(rec&&rec.data&&rec.data.text)||'';allText+='\\n'+txt;found=genericFlags(txt);
    if(!found.length){var compact=txt.replace(/\\s+/g,'');found=genericFlags(compact);}
    if(!found.length){var lines=txt.split(/\r?\n/);for(var q=0;q<lines.length;q++){var cand=lines[q].replace(/\s+/g,''),low=cand.toLowerCase(),prefix='';if(low.indexOf('academy')===0)prefix=cand.slice(0,7);else if(low.indexOf('ctf')===0)prefix=cand.slice(0,3);else if(low.indexOf('flag')===0)prefix=cand.slice(0,4);else if(low.indexOf('moe')===0)prefix=cand.slice(0,3);if(prefix){var body=cand.slice(prefix.length);if(body.length>=10&&'({['.indexOf(body.charAt(0))>=0&&'})]'.indexOf(body.charAt(body.length-1))>=0){flagish.push(cand);var norm=prefix+'{'+body.slice(1,-1)+'}';normalizedCandidates.push(norm);votes[norm]=(votes[norm]||0)+1;}}}}
   }
   if(!found.length){var ranked=Object.keys(votes).sort(function(a,b){return votes[b]-votes[a];});if(ranked.length){var top=ranked[0],same=normalizedCandidates.filter(function(v){return v.length===top.length&&v.slice(0,top.indexOf('{')+1).toLowerCase()===top.slice(0,top.indexOf('{')+1).toLowerCase();});if(same.length>=2){var chars=top.split('');for(var pos=0;pos<chars.length;pos++){var count={};for(var vi=0;vi<same.length;vi++){var ch=same[vi].charAt(pos);count[ch]=(count[ch]||0)+1;}var keys=Object.keys(count).sort(function(x,y){return count[y]-count[x];});if(keys.length&&count[keys[0]]>=2)chars[pos]=keys[0];}found=[chars.join('')];}}}
   if(found.length){st.className='finding success';st.innerHTML='<b>🚩 تم الوصول إلى العلم تلقائيًا</b><div class="solvePath">Broken File → JPEG Header Repair → Image → OCR → Flag</div>'+found.map(function(v){return '<div class="flag">'+esc(v)+'</div>';}).join('');}
   else{st.className='finding warn';st.innerHTML='تم إصلاح الصورة بنجاح، لكن OCR لم يستخرج Flag موثوقًا تلقائيًا.'+(flagish.length?'<p>🔎 نصوص شبيهة بالعلم التقطها OCR:</p>'+flagish.slice(0,5).map(function(v){return '<code>'+esc(v)+'</code><br>';}).join(''):'')+'<details><summary>🔬 عرض نص OCR الخام للتشخيص</summary><pre style="white-space:pre-wrap;direction:ltr;text-align:left">'+esc(allText.slice(0,12000))+'</pre></details>';}
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