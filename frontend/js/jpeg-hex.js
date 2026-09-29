(function(){
'use strict';
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function text(u){var o='',step=32768;for(var i=0;i<u.length;i+=step)o+=String.fromCharCode.apply(null,u.subarray(i,Math.min(i+step,u.length)));return o;}
function flags(s){return String(s||'').match(/(?:academy|picoCTF|flag|ctf|moe)\{[^}\r\n]{1,200}\}/ig)||[];}
function printableRuns(u){var a=[],start=-1;for(var i=0;i<=u.length;i++){var ok=i<u.length&&u[i]>=32&&u[i]<=126;if(ok&&start<0)start=i;if((!ok||i===u.length)&&start>=0){if(i-start>=6)a.push({off:start,s:text(u.subarray(start,i))});start=-1;}}return a;}
async function analyze(u,name){
 if(u.length<4||u[0]!==255||u[1]!==216)return null;
 var raw=text(u), direct=flags(raw); if(direct.length)return {flag:direct[0],off:raw.indexOf(direct[0]),kind:'Printable ASCII inside JPEG'};
 var runs=printableRuns(u), hits=[];
 for(var i=0;i<runs.length;i++){var f=flags(runs[i].s);if(f.length)hits.push({flag:f[0],off:runs[i].off+runs[i].s.indexOf(f[0]),kind:'Printable bytes'});}
 if(hits.length)return hits[0];
 var eoi=-1;for(var j=u.length-2;j>=0;j--){if(u[j]===255&&u[j+1]===217){eoi=j+2;break;}}
 if(eoi>0&&eoi<u.length){var tail=text(u.subarray(eoi)), tf=flags(tail);if(tf.length)return {flag:tf[0],off:eoi+tail.indexOf(tf[0]),kind:'Data after JPEG EOI'};}
 return null;
}
async function run(){
 var inp=document.getElementById('file'),f=(inp&&inp.files&&inp.files[0])||window.__falconDroppedFile;if(!f)return false;
 var u=new Uint8Array(await f.arrayBuffer()),a=await analyze(u,f.name||'JPEG');if(!a)return false;
 var r=document.getElementById('result');if(!r)return true;r.classList.remove('hidden');
 var hex='0x'+a.off.toString(16).toUpperCase();
 r.innerHTML='<div class="finding success"><h3>🔎 JPEG Hex / Binary Analyzer</h3><p>وجد صقر نصًا مهمًا داخل بايتات ملف JPEG.</p><p><b>المسار:</b> JPEG → Binary/Hex Inspection → Printable Data → Flag</p><p>📍 موضع الاكتشاف: <code>'+hex+'</code> ('+a.off+' bytes)</p><p>🧩 النوع: <code>'+esc(a.kind)+'</code></p><h3>🚩 العلم المكتشف</h3><code>'+esc(a.flag)+'</code><details><summary>🔧 التفاصيل التقنية</summary><p>يمكن الوصول لنفس الموضع باستخدام Hex Editor أو أداة strings.</p></details></div>';
 r.scrollIntoView({behavior:'smooth',block:'start'});return true;
}
var prev=window.FalconSmartRun;
window.FalconJpegHexRun=async function(){try{if(await run())return false;}catch(e){console.warn('Falcon JPEG Hex',e);}return prev?prev():false;};
window.FalconSmartRun=window.FalconJpegHexRun;
})();