(function(){
var originalRun=window.FalconSmartRun;
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function flags(s){return String(s||'').match(/[A-Za-z][A-Za-z0-9_.:-]{1,30}\{[^{}\r\n]{2,200}\}/g)||[];}
function asciiStrings(u8,min){
 min=min||4;var out=[],buf=[];
 function flush(){if(buf.length>=min)out.push(String.fromCharCode.apply(null,buf));buf=[];}
 for(var i=0;i<u8.length;i++){var b=u8[i];if(b>=32&&b<=126)buf.push(b);else flush();}
 flush();return out;
}
async function diskStrings(file){
 if(!file)return false;
 var n=(file.name||'').toLowerCase();
 if(!(/\.dd\.gz$|\.img\.gz$|\.raw\.gz$|\.gz$/.test(n)))return false;
 if(typeof pako==='undefined')return false;
 var result=document.getElementById('result');result.className='result';
 result.innerHTML='<div class="studentSummary"><h2>💽 Disk Image Strings — V75 TEST</h2><div class="studentCard"><b>1️⃣ نوع التحدي</b><p>Compressed Disk Image / Forensics</p><div class="solvePath">GZIP → Disk Image → Strings → Flag Hunter</div></div><div class="studentCard"><b>2️⃣ التحليل</b><div id="falconDiskStatus" class="finding">⏳ جارٍ فك GZIP محليًا ثم استخراج ASCII strings...</div></div></div>';
 try{
  var u8=new Uint8Array(await file.arrayBuffer());
  if(!(u8[0]===0x1f&&u8[1]===0x8b))return false;
  var raw=pako.ungzip(u8),ss=asciiStrings(raw,4),found=[],hits=[];
  for(var i=0;i<ss.length;i++){var f=flags(ss[i]);for(var j=0;j<f.length;j++){var v=f[j];if(found.indexOf(v)<0){found.push(v);hits.push({flag:v,stringIndex:i,context:ss[i].slice(0,500)});}}}
  function score(h){
   var v=h.flag,s=0,prefix=(v.split('{')[0]||'').toLowerCase(),body=(v.match(/\{([^{}]+)\}/)||[])[1]||'';
   if(prefix==='academy')s+=80;else if(prefix==='ctf'||prefix==='flag'||prefix==='moe')s+=45;
   if(body.length>=12&&body.length<=80)s+=20;
   if(/[_0-9]/.test(body))s+=8;
   if(/^[A-Za-z0-9_!@#$%^&*()+.\-]+$/.test(body))s+=6;
   if(/decoy|fake|dummy|example|test/i.test(v))s-=70;
   return s;
  }
  hits.forEach(function(h){h.score=score(h);});hits.sort(function(x,y){return y.score-x.score||x.stringIndex-y.stringIndex;});
  var st=document.getElementById('falconDiskStatus');if(!st)return true;
  if(hits.length){var top=hits[0],alts=hits.slice(1,6);st.className='finding success';st.innerHTML='<b>🎯 العلم الأعلى ثقة</b><p>تم فك <strong>'+u8.length+'</strong> بايت GZIP إلى <strong>'+raw.length+'</strong> بايت، ثم فحص <strong>'+ss.length+'</strong> سلسلة ASCII والعثور على <strong>'+hits.length+'</strong> مرشحًا.</p><div class="solvePath">GZIP → Disk Image (.dd) → Strings → Candidate Ranking → Best Flag</div><div class="flag">'+esc(top.flag)+'</div><p><strong>درجة الثقة:</strong> '+top.score+'</p>'+(alts.length?'<details><summary>عرض المرشحين الآخرين ('+alts.length+')</summary>'+alts.map(function(h){return '<div class="finding"><code>'+esc(h.flag)+'</code> — '+h.score+'</div>';}).join('')+'</details>':'');}
  else{st.className='finding warn';st.innerHTML='تم فك صورة القرص واستخراج <strong>'+ss.length+'</strong> سلسلة، لكن لم يظهر Flag مباشر.';}
  return true;
 }catch(e){
  var st=document.getElementById('falconDiskStatus');if(st){st.className='finding warn';st.innerHTML='⚠️ تعذر تحليل صورة القرص: '+esc(e.message||e);}
  return true;
 }
}
window.FalconSmartRun=function(){
 var fi=document.getElementById('file'),ta=document.getElementById('text'),chosen=(fi&&fi.files&&fi.files.length)?fi.files[0]:window.__falconDroppedFile;
 if(chosen&&(!ta||!ta.value.trim())){diskStrings(chosen).then(function(hit){if(!hit)originalRun();});return false;}
 return originalRun();
};
})();