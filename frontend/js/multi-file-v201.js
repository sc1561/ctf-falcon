/* Falcon V200 multi-file bridge: file-first analysis for paired CTF artifacts. */
(function(){
'use strict';
var previous=window.FalconWebSessionRun||window.FalconRogueTowerRun||window.FalconTimelineRun||window.FalconJpegHexRun||window.FalconMetadataRun||window.FalconPolyglotRun||window.FalconQrZipRun||window.FalconTerminalVerifyRun||window.FalconPcapRawTimeRun||window.FalconRawPngRun||window.FalconSmartRun;
function el(id){return document.getElementById(id)}
function esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
function b64(file){
 return file.arrayBuffer().then(function(buf){
  var u=new Uint8Array(buf),parts=[],step=0x8000;
  for(var i=0;i<u.length;i+=step)parts.push(String.fromCharCode.apply(null,u.subarray(i,Math.min(i+step,u.length))));
  return btoa(parts.join(''));
 });
}
function selected(){
 var f=el('file');
 if(f&&f.files&&f.files.length)return Array.prototype.slice.call(f.files);
 if(window.__falconDroppedFiles&&window.__falconDroppedFiles.length)return Array.prototype.slice.call(window.__falconDroppedFiles);
 if(window.__falconDroppedFile)return [window.__falconDroppedFile];
 return [];
}
function isStegoRsa(files){
 var n=files.map(function(f){return (f.name||'').toLowerCase()});
 return n.indexOf('image.jpg')>=0&&n.indexOf('flag.enc')>=0;
}
async function runPair(files){
 var out=el('result'); if(!out)return false;
 out.classList.remove('hidden');
 out.innerHTML='<div class="finding"><h3>🧠 تحليل ذكي متعدد الملفات</h3><p>اكتشف صقر أن <code>image.jpg</code> و <code>flag.enc</code> مترابطان.</p><div class="solvePath">Files → Stego/Metadata → RSA → Flag Hunter</div><p>⏳ جارٍ التحليل محليًا على جهازك…</p></div>';
 try{
  var payload=[];
  for(var i=0;i<files.length;i++)payload.push({name:files[i].name,data_b64:await b64(files[i])});
  var base=(location.hostname==='127.0.0.1'||location.hostname==='localhost')?'':'http://127.0.0.1:8765';
  var res=await fetch(base+'/crypto/analyze-files',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({challenge_text:(el('text')&&el('text').value)||'',files:payload})});
  var raw=await res.text(),d; try{d=JSON.parse(raw)}catch(_){throw new Error('HTTP '+res.status)}
  if(!res.ok||!d.ok)throw new Error(d.error||d.detail||('HTTP '+res.status));
  if(d.success&&d.flag){
   out.innerHTML='<div class="finding success"><h3>🚩 نجح صقر في استخراج العلم</h3><p><b>التعرف:</b> من الملفين مباشرة — لم يحتج إلى وصف التحدي.</p><div class="solvePath">image.jpg + flag.enc → Metadata → RSA → Flag Hunter</div><div class="flag">'+esc(d.flag)+'</div>'+(d.explanation_ar&&d.explanation_ar.length?'<details><summary>📚 كيف وصل صقر للحل؟</summary><ol>'+d.explanation_ar.map(function(x){return '<li>'+esc(x)+'</li>'}).join('')+'</ol></details>':'')+'</div>';
  }else{
   out.innerHTML='<div class="finding warn"><h3>🧠 اكتشف صقر الملفين المترابطين</h3><p>تم تشغيل مسار StegoRSA تلقائيًا، لكن لم يظهر علم مؤكد.</p>'+(d.explanation_ar||[]).map(function(x){return '<p>'+esc(x)+'</p>'}).join('')+(d.warnings||[]).map(function(x){return '<p>⚠️ '+esc(x)+'</p>'}).join('')+'</div>';
  }
 }catch(e){
  out.innerHTML='<div class="finding warn"><h3>🧠 تحليل متعدد الملفات</h3><p>تعذر الوصول إلى محرك صقر المحلي أو أنه إصدار قديم.</p><p><code>'+esc(e.message||e)+'</code></p><p>حدّث وشغّل <code>local-engine/falcon_local.py</code> ثم أعد التحليل.</p></div>';
 }
 out.scrollIntoView({behavior:'smooth',block:'start'}); return true;
}
window.FalconMultiFileRun=async function(){
 var files=selected();
 if(files.length>=2&&isStegoRsa(files)){await runPair(files);return false}
 return previous?previous():false;
};
})();
