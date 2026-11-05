/* Falcon V206: focused Base64 -> ROT13 chain repair, no changes to other routes. */
(function(){'use strict';
const pattern=/(?:academy|flag|ctf|moe)\{[A-Za-z0-9_\-]{1,160}\}/ig;
const tokenPattern=/\b[A-Za-z0-9+/]{24,}={0,2}\b/g;
function escapeHTML(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function rot13(s){return s.replace(/[A-Za-z]/g,c=>String.fromCharCode((c.charCodeAt(0)-(c<='Z'?65:97)+13)%26+(c<='Z'?65:97)));}
function decodeText(s){const hits=[];for(const token of (s.match(tokenPattern)||[]).slice(0,100)){
 try {const first=atob(token);if(!/^[\x20-\x7e\r\n\t]+$/.test(first))continue;
 const second=rot13(first);const match=second.match(pattern);
 if(match)for(const flag of match)hits.push({flag,chain:'Base64 → ROT13',intermediate:first});
 const plain=first.match(pattern);if(plain)for(const flag of plain)hits.push({flag,chain:'Base64',intermediate:first});
 }catch(_){}}
 return hits;
}
function show(hits,source){const result=document.getElementById('result');if(!result)return;
 const unique=[...new Map(hits.map(x=>[x.flag,x])).values()];
 result.className='result';result.innerHTML='<div class="studentSummary"><h2>🚩 تم العثور على العلم المرشح</h2><div class="studentCard"><b>المصدر</b><p>'+escapeHTML(source)+'</p></div><div class="studentCard success"><b>نتيجة فك الترميز المتسلسل</b>'+unique.map(x=>'<div class="solvePath">'+escapeHTML(x.chain)+'</div><div class="flag">'+escapeHTML(x.flag)+'</div>').join('')+'</div><div class="studentCard"><b>ملاحظة</b><p>هذا علم مرشح مستخرج من المحتوى، ويجب التحقق منه وفق قواعد المسابقة.</p></div></div>';
 result.scrollIntoView({behavior:'smooth',block:'start'});
}
async function inspectZip(file){if(typeof JSZip==='undefined')return [];
 const zip=await JSZip.loadAsync(file),hits=[];let count=0;
 for(const [name,entry] of Object.entries(zip.files)){
  if(entry.dir||++count>80)continue;
  if(!/\.(?:txt|md|json|csv|log|xml|html|js|ini|cfg)$/i.test(name))continue;
  if(entry._data&&entry._data.uncompressedSize>1024*1024)continue;
  const text=await entry.async('string');hits.push(...decodeText(text).map(x=>({...x,source:name})));
 }return hits;
}
document.addEventListener('click',async function(ev){const btn=ev.target.closest&&ev.target.closest('#solve');if(!btn)return;
 const text=document.getElementById('text')?.value||'';
 const input=document.getElementById('file');const files=input?.files?.length?[...input.files]:(window.__falconDroppedFiles||[]);
 const file=files.length===1?files[0]:null;
 if(!file){const hits=decodeText(text);if(!hits.length)return;ev.preventDefault();ev.stopImmediatePropagation();show(hits,'النص الملصق');return;}
 if(!/\.zip$/i.test(file.name)||file.size>20*1024*1024)return;
 ev.preventDefault();ev.stopImmediatePropagation();
 try{const hits=await inspectZip(file);if(hits.length)show(hits,'ZIP → '+[...new Set(hits.map(x=>x.source))].join('، '));
 else if(window.FalconSmartRun)window.FalconSmartRun();}
 catch(e){if(window.FalconSmartRun)window.FalconSmartRun();}
},true);
})();