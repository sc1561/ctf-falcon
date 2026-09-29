(function(){
 var prev=window.FalconSmartRun;
 function id(x){return document.getElementById(x);}
 function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
 function flag(s){var m=String(s||'').match(/(?:academy|flag|ctf|moe)\{[^}\r\n]+\}/i);return m&&m[0];}
 async function decodeImage(blob){
   if(!('BarcodeDetector' in window)) throw new Error('QR_API');
   var det=new BarcodeDetector({formats:['qr_code']});
   var bmp=await createImageBitmap(blob);
   var codes=await det.detect(bmp);
   if(bmp.close)bmp.close();
   return codes&&codes.length?(codes[0].rawValue||''):'';
 }
 async function scanZip(file,out){
   if(!window.JSZip)return false;
   var zip=await JSZip.loadAsync(file), names=Object.keys(zip.files);
   var imgs=names.filter(function(n){return !zip.files[n].dir&&/\.(png|jpe?g|webp)$/i.test(n);});
   if(!imgs.length)return false;
   out.className='result';out.innerHTML='<div class="studentSummary"><h2>📷 QR Analyzer</h2><p>📦 تم فتح ZIP — جارٍ فحص '+imgs.length+' صورة بحثًا عن QR...</p></div>';
   for(var i=0;i<imgs.length;i++){
     var b=await zip.files[imgs[i]].async('blob');
     try{
       var txt=await decodeImage(b);
       if(txt){
         var fl=flag(txt);
         out.innerHTML='<div class="studentSummary"><h2>📷 Scan Surprise — QR Analyzer</h2><div class="solvePath">ZIP → '+esc(imgs[i])+' → QR Code → Data → Flag</div><div class="studentCard success"><h3>✅ تم اكتشاف QR Code</h3><p>الصورة: <code>'+esc(imgs[i])+'</code></p><p>محتوى QR:</p><code>'+esc(txt)+'</code>'+(fl?'<h3>🚩 تم العثور على العلم</h3><p><code>'+esc(fl)+'</code></p>':'<p>تمت قراءة QR، لكن لم تظهر صيغة Flag معروفة.</p>')+'</div></div>';
         return true;
       }
     }catch(e){
       if(e&&e.message==='QR_API'){
         out.innerHTML='<div class="studentSummary"><h2>📷 QR Analyzer</h2><div class="studentCard warn"><b>⚠️ المتصفح لا يدعم قارئ QR المحلي المطلوب في هذا الاختبار.</b><p>تم العثور على صورة داخل ZIP: <code>'+esc(imgs[i])+'</code></p><p>جرّب Chrome/Edge حديثًا، أو سنضيف قارئ QR مستقلًا في المرحلة التالية.</p></div></div>';
         return true;
       }
     }
   }
   return false;
 }
 window.FalconQrZipRun=async function(){
   var file=id('file')&&id('file').files&&id('file').files[0];
   if(!file&&window.__falconDroppedFile)file=window.__falconDroppedFile;
   if(!file)return prev?prev():false;
   var out=id('result');
   var sig=new Uint8Array(await file.slice(0,4).arrayBuffer());
   var isZip=sig[0]===0x50&&sig[1]===0x4b;
   if(!isZip)return prev?prev():false;
   try{if(await scanZip(file,out))return false;}catch(e){}
   return prev?prev():false;
 };
 window.FalconSmartRun=window.FalconQrZipRun;
})();