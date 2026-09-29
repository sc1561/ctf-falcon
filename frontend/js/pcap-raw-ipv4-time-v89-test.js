(function(){
 var prev=window.FalconSmartRun;
 function id(x){return document.getElementById(x)}
 function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
 function u32(d,o,l){return d.getUint32(o,l)}
 function flag(s){var m=String(s).match(/[A-Za-z][A-Za-z0-9_.:-]{1,30}\{[^{}\r\n]{2,200}\}/g);return m||[]}
 function b64(s){try{return atob(s)}catch(e){return ''}}
 async function run(file){
  var out=id('result');if(!out)return false;
  var u=new Uint8Array(await file.arrayBuffer());if(u.length<24)return false;
  var d=new DataView(u.buffer,u.byteOffset,u.byteLength),sig=[u[0],u[1],u[2],u[3]].map(function(x){return x.toString(16).padStart(2,'0')}).join(''),le;
  if(sig==='d4c3b2a1'||sig==='4d3cb2a1')le=true;else if(sig==='a1b2c3d4'||sig==='a1b23c4d')le=false;else return false;
  var link=d.getUint32(20,le);if(link!==228)return false;
  var p=24,parts=[],packets=0;
  while(p+16<=u.length){var sec=u32(d,p,le),sub=u32(d,p+4,le),n=u32(d,p+8,le),s=p+16,e=s+n;if(e>u.length)break;packets++;
   if(n>=40&&(u[s]>>4)===4){var ihl=(u[s]&15)*4;if(u[s+9]===6&&s+ihl+20<=e){var t=s+ihl,doff=(u[t+12]>>4)*4,ps=t+doff;if(ps<e){var raw='';for(var j=ps;j<e;j++)raw+=String.fromCharCode(u[j]);raw=raw.trim();if(/^[A-Za-z0-9+\/]+={0,2}$/.test(raw)){var dec=b64(raw);if(dec)parts.push({sec:sec,sub:sub,raw:raw,dec:dec});}}}}
   p=e;
  }
  parts.sort(function(a,b){return a.sec-b.sec||a.sub-b.sub});
  var printable=parts.filter(function(x){return /^[\x20-\x7e]+$/.test(x.dec)}),joined='';
  for(var k=0;k<printable.length;k++)joined+=printable[k].dec;
  var hits=flag(joined);if(!hits.length)return false;
  var html='<div class="studentSummary"><h2>🎉 تم حل تحدي PCAP الزمني</h2><div class="studentCard"><b>1️⃣ نوع التحدي</b><p>PCAP / Raw IPv4 (DLT 228) / Timed Payload Forensics</p></div><div class="studentCard"><b>2️⃣ ماذا اكتشف صقر؟</b><p>قرأ <strong>'+packets+'</strong> حزمة، ورتب الحمولات حسب Timestamp، ثم فك Base64 وجمع الأجزاء النصية.</p><div class="solvePath">PCAP → DLT_RAW IPv4 → Timestamp Sort → TCP Payload → Base64 → Join Fragments → Flag</div></div><div class="studentCard success"><b>3️⃣ العلم المرشح 🚩</b>';
  for(k=0;k<hits.length;k++)html+='<div class="flag">'+esc(hits[k])+'</div>';out.innerHTML=html+'</div></div>';out.className='result';out.scrollIntoView({behavior:'smooth',block:'start'});return true;
 }
 window.FalconPcapRawTimeRun=async function(){var fi=id('file'),ta=id('text'),file=(fi&&fi.files&&fi.files[0])||window.__falconDroppedFile;if(file&&!(ta&&ta.value.trim())){try{if(await run(file))return false}catch(e){}}return prev?prev():false};
window.FalconSmartRun=window.FalconPcapRawTimeRun;
})();