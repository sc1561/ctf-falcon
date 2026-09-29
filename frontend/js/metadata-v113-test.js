(function(){
'use strict';
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function flags(s){return String(s||'').match(/(?:academy|flag|ctf|moe)\{[^}\r\n]{1,200}\}/ig)||[];}
function b64(s){try{var x=String(s||'').replace(/\s+/g,'');if(x.length<12||x.length%4!==0||!/^[A-Za-z0-9+/]+={0,2}$/.test(x))return '';return atob(x);}catch(e){return '';}}
function bytesText(u){var out='',step=0x8000;for(var i=0;i<u.length;i+=step)out+=String.fromCharCode.apply(null,u.subarray(i,Math.min(i+step,u.length)));return out;}
async function analyzeJpeg(u,name){
 if(u.length<4||u[0]!==0xff||u[1]!==0xd8)return null;
 var raw=bytesText(u), hits=[], seen={};
 function add(label,val){val=String(val||'').trim();if(!val||seen[val])return;seen[val]=1;var dec=b64(val), fs=flags(dec);if(fs.length)hits.push({label:label,value:val,decoded:dec,flag:fs[0]});}
 var re=/(?:cc:(?:attributionURL|license)|attributionURL|license|dc:[A-Za-z]+|photoshop:[A-Za-z]+|xmp:[A-Za-z]+)\\s*=\\s*[\"']([^\"']{12,500})[\"']/ig,m;
 while((m=re.exec(raw)))add(m[0].split('=')[0].trim(),m[1]);
 var generic=raw.match(/[A-Za-z0-9+/]{24,}={0,2}/g)||[];generic.slice(0,200).forEach(function(x){add('Metadata/Base64',x);});
 if(!hits.length)return null;
 return {name:name,hit:hits[0],all:hits};
}
async function run(){
 var input=document.getElementById('file'), file=(input&&input.files&&input.files[0])||window.__falconDroppedFile;
 if(!file)return false;
 var u=new Uint8Array(await file.arrayBuffer()), zip=null, source=file.name||'file';
 if(typeof JSZip!=='undefined'){try{zip=await JSZip.loadAsync(u);}catch(e){}}
 var candidates=[];
 if(zip){var names=Object.keys(zip.files).filter(function(n){return !zip.files[n].dir&&/\.(jpe?g)$/i.test(n);});for(var i=0;i<names.length;i++){try{var bu=await zip.files[names[i]].async('uint8array');var a=await analyzeJpeg(bu,names[i]);if(a)candidates.push(a);}catch(e){}}}
 else {var a=await analyzeJpeg(u,source);if(a)candidates.push(a);}
 if(!candidates.length)return false;
 var x=candidates[0], r=document.getElementById('result'); if(!r)return true;
 r.classList.remove('hidden');
 r.innerHTML='<div class="finding success"><h3>🖼️ Metadata / XMP Analyzer</h3><p>وجد صقر بيانات مخفية داخل معلومات الصورة.</p><p><b>المسار:</b> '+(zip?'ZIP → ':'')+'JPEG → Metadata/XMP → '+esc(x.hit.label)+' → Base64 → Flag</p><p>📁 الصورة: <code>'+esc(x.name)+'</code></p><p>🔎 القيمة الملفتة: <code>'+esc(x.hit.value)+'</code></p><h3>🚩 العلم المكتشف</h3><code>'+esc(x.hit.flag)+'</code><details><summary>🔧 التفاصيل التقنية</summary><p>Base64 decoded: <code>'+esc(x.hit.decoded)+'</code></p></details></div>';
 r.scrollIntoView({behavior:'smooth',block:'start'}); return true;
}
var prev=window.FalconSmartRun;
window.FalconMetadataV113Run=async function(){try{if(await run())return false;}catch(e){console.warn('Falcon metadata',e);}return prev?prev():false;};
window.FalconSmartRun=window.FalconMetadataV113Run;
})();