(function(){
 var originalRun=window.FalconSmartRun;
 function byId(id){return document.getElementById(id);}
 function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
 function genericFlags(s){var r=/[A-Za-z][A-Za-z0-9_.:-]{1,30}\{[^{}\r\n]{2,200}\}/g,a=[],m;while((m=r.exec(s||''))!==null)if(a.indexOf(m[0])<0)a.push(m[0]);return a;}
 function bytesFromBits(bits){var out=[];for(var i=0;i+7<bits.length;i+=8){var v=0;for(var k=0;k<8;k++)v=(v<<1)|bits[i+k];out.push(v);}return new Uint8Array(out);}
 function ascii(u8){var s='',n=8192;for(var i=0;i<u8.length;i+=n)s+=String.fromCharCode.apply(null,u8.subarray(i,Math.min(i+n,u8.length)));return s;}
 function decodeB64Candidates(s){
  var hits=[],seen={},m,re=/[A-Za-z0-9+\/]{12,}={1,2}/g;
  while((m=re.exec(s))!==null){var token=m[0];try{var d=atob(token),ff=genericFlags(d);for(var j=0;j<ff.length;j++)if(!seen[ff[j]]){seen[ff[j]]=1;hits.push({flag:ff[j],encoded:token});}}catch(e){}}
  return hits;
 }
 async function analyze(file){
  if(!file||!/\.png$/i.test(file.name||''))return false;
  var result=byId('result');if(!result)return false;
  try{
   var u8=new Uint8Array(await file.arrayBuffer());
   if(u8.length<8||u8[0]!==137||u8[1]!==80||u8[2]!==78||u8[3]!==71)return false;
   var url=URL.createObjectURL(new Blob([u8],{type:'image/png'})),img=new Image();
   return await new Promise(function(resolve){
    img.onerror=function(){URL.revokeObjectURL(url);resolve(false);};
    img.onload=function(){
     try{
      var cv=document.createElement('canvas');cv.width=img.naturalWidth;cv.height=img.naturalHeight;
      var cx=cv.getContext('2d',{willReadFrequently:true});cx.drawImage(img,0,0);
      var px=cx.getImageData(0,0,cv.width,cv.height).data,bits=[];
      for(var p=0;p<px.length;p+=4)bits.push(px[p]&1,px[p+1]&1,px[p+2]&1,px[p+3]&1);
      var text=ascii(bytesFromBits(bits)),direct=genericFlags(text),decoded=decodeB64Candidates(text),hits=[],seen={};
      direct.forEach(function(f){if(!seen[f]){seen[f]=1;hits.push({flag:f,path:'PNG → RGBA LSB → Flag'});}});
      decoded.forEach(function(h){if(!seen[h.flag]){seen[h.flag]=1;hits.push({flag:h.flag,path:'PNG → RGBA LSB → Base64 → Flag'});}});
      URL.revokeObjectURL(url);
      if(!hits.length){resolve(false);return;}
      var html='<div class="studentSummary"><h2>🎉 تم حل تحدي PNG Steganography</h2><div class="studentCard"><b>1️⃣ ما نوع التحدي؟</b><p>PNG / Pixel Steganography — فحص LSB عبر قنوات <strong>RGBA</strong>.</p></div><div class="studentCard"><b>2️⃣ ماذا اكتشف صقر؟</b><p>جمع أقل بت من R ثم G ثم B ثم Alpha لكل بكسل، وحوّل البتات إلى Bytes ثم فحص Base64 تلقائيًا.</p></div><div class="studentCard success"><b>3️⃣ العلم المرشح 🚩</b>';
      hits.forEach(function(h){html+='<div class="solvePath">'+esc(h.path)+'</div><div class="flag">'+esc(h.flag)+'</div>';});
      result.innerHTML=html+'</div></div>';result.className='result';result.scrollIntoView({behavior:'smooth',block:'start'});resolve(true);
     }catch(e){URL.revokeObjectURL(url);resolve(false);}
    };img.src=url;
   });
  }catch(e){return false;}
 }
 var analyzeBtn=byId('solve');
 if(analyzeBtn)analyzeBtn.addEventListener('click',async function(e){
   var inp=byId('fileInput'),ta=byId('text'),file=(inp&&inp.files&&inp.files[0])||window.__falconDroppedFile,pasted=ta?ta.value.trim():'';
   if(file&&!pasted&&/\.png$/i.test(file.name||'')){
     e.preventDefault();e.stopImmediatePropagation();
     var hit=await analyze(file);
     if(!hit&&originalRun)originalRun();
   }
 },true);
 window.FalconSmartRun=async function(){
  var inp=byId('fileInput'),ta=byId('text'),file=(inp&&inp.files&&inp.files[0])||window.__falconDroppedFile,pasted=ta?ta.value.trim():'';
  if(file&&!pasted){var hit=await analyze(file);if(hit)return false;}
  return originalRun?originalRun():false;
 };
})();