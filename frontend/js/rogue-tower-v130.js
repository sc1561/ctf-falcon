(function(){
'use strict';
var previous=window.FalconSmartRun;
function el(x){return document.getElementById(x)}
function clean(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
function flag(s){return String(s).match(/[A-Za-z][A-Za-z0-9_.:-]{1,30}\{[^{}\r\n]{2,200}\}/g)||[]}
function unpack64(s){try{var q=atob(s),a=[];for(var i=0;i<q.length;i++)a.push(q.charCodeAt(i));return a}catch(e){return []}}
function transform(a,k){var t='';for(var i=0;i<a.length;i++)t+=String.fromCharCode(a[i]^k.charCodeAt(i%k.length));return t}
async function analyze(file){
 var out=el('result'); if(!out)return false;
 var bytes=new Uint8Array(await file.arrayBuffer());
 if(bytes.length<24)return false;
 var view=new DataView(bytes.buffer), little=bytes[0]===0xd4||bytes[0]===0x4d;
 var magic=view.getUint32(0,little);
 if(magic!==0xa1b2c3d4&&magic!==0xa1b23c4d)return false;
 var link=view.getUint32(20,little); if(link!==228)return false;
 var text=new TextDecoder('latin1').decode(bytes);
 if(text.indexOf('55000')<0 && !/CELLID=/i.test(text))return false;
 var cells=[...text.matchAll(/(?:UNAUTHORIZED[^\r\n]*?)?PLMN=([0-9]+)[^\r\n]*?CELLID=([0-9]+)/gi)];
 var agents=[...text.matchAll(/IMSI[:= ]+(\d+)[^\r\n]*?CELL[:= ]+(\d+)/gi)];
 var rogue=cells.find(x=>/UNAUTHORIZED|TEST/i.test(x[0]))||cells[0];
 var victim=rogue&&agents.find(x=>x[2]===rogue[2]);
 if(!rogue||!victim)return false;
 var bodies=[...text.matchAll(/POST [^\r\n]*[\s\S]*?\r\n\r\n([A-Za-z0-9+\/=]{4,})/g)].map(x=>x[1]);
 var joined=bodies.join(''), data=unpack64(joined), imsi=victim[1], keys=[imsi.slice(-8),imsi.slice(-6),imsi.slice(-4),imsi], hits=[],used='';
 for(var z=0;z<keys.length&&!hits.length;z++){var plain=transform(data,keys[z]);hits=flag(plain);if(hits.length)used=keys[z]}
 out.innerHTML='<div class="studentSummary"><h2>📡 Rogue Tower Analyzer — V130</h2><div class="studentCard"><b>البرج المشبوه</b><p>PLMN <code>'+clean(rogue[1])+'</code> — CELLID <code>'+clean(rogue[2])+'</code></p></div><div class="studentCard"><b>الجهاز المتأثر</b><p>IMSI <code>'+clean(victim[1])+'</code></p></div><p>أجزاء HTTP POST المكتشفة: <strong>'+bodies.length+'</strong></p>'+(hits.length?'<div class="studentCard success"><b>🚩 العلم المرشح</b><div class="flag">'+clean(hits[0])+'</div><small>IMSI-derived key: '+clean(used)+'</small></div>':'<p>تم تحديد البرج والجهاز، لكن لم يظهر علم صالح بعد.</p>')+'</div>';
 out.className='result'; return true;
}
window.FalconRogueTowerRun=async function(){var f=(el('file')&&el('file').files&&el('file').files[0])||window.__falconDroppedFile;if(f){try{if(await analyze(f))return false}catch(e){console.warn(e)}}return previous?previous():false};
window.FalconSmartRun=window.FalconRogueTowerRun;
})();