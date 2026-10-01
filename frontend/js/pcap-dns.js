/* Dependency-free classic PCAP/PCAPNG DNS evidence analyzer. */
(function(){
 'use strict';
 var previous=window.FalconSmartRun,previousWebSession=window.FalconWebSessionRun;
 function el(id){return document.getElementById(id)}
 function esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
 function u16(v,o,le){return v.getUint16(o,le)} function u32(v,o,le){return v.getUint32(o,le)}
 function readFrames(bytes){
  var v=new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength),frames=[],ifaces=[],off=0;
  function block(len,link,ts){if(len<12||off+len>bytes.length)return false;frames.push({link:link,ts:ts,data:bytes.subarray(off+28,off+len-4)});return true}
  if(bytes.length<24)return null;
  if(bytes[0]===10&&bytes[1]===13&&bytes[2]===13&&bytes[3]===10){
   while(off+12<=bytes.length){
    var type=u32(v,off,true),le=true;
    if(type===0x0a0d0d0a){var bom=off+8;if(bom+4>bytes.length)return null;var bm=[bytes[bom],bytes[bom+1],bytes[bom+2],bytes[bom+3]].join(',');le=bm==='77,60,43,26';if(bm==='26,43,60,77')le=false;else if(!le)return null;var sl=u32(v,off+4,le);if(sl<28||off+sl>bytes.length)return null;frames._le=le;off+=sl;continue;}
    var bl=u32(v,off+4,true); /* byte order is set from the section header */
    if(frames._le===false)bl=u32(v,off+4,false);le=frames._le!==false;
    if(bl<12||off+bl>bytes.length)return null;
    var bt=u32(v,off,le);
    if(bt===1&&bl>=20){var link=u16(v,off+8,le),res=1e6;for(var q=off+16;q+4<=off+bl-4;){var c=u16(v,q,le),n=u16(v,q+2,le);q+=4;if(!c)break;if(c===9&&n){var r=bytes[q];res=(r&128)?Math.pow(2,r&127):Math.pow(10,r);}q+=(n+3)&~3;}ifaces.push({link:link,res:res});}
    else if(bt===6&&bl>=32){var ix=u32(v,off+8,le),hi=u32(v,off+12,le),lo=u32(v,off+16,le),cap=u32(v,off+20,le);if(ix<ifaces.length&&28+cap<=bl-4){var ticks=hi*4294967296+lo,resolution=ifaces[ix].res,tsns=null;if(Number.isInteger(resolution)&&resolution>0&&1e9%resolution===0)tsns=(BigInt(hi)<<32n|BigInt(lo))*BigInt(1e9/resolution);else if(Number.isFinite(resolution)&&resolution>0)tsns=BigInt(Math.round(ticks*1e9/resolution));frames.push({link:ifaces[ix].link,ts:tsns,data:bytes.subarray(off+28,off+28+cap)});}}
    else if(bt===3&&ifaces.length&&bl>=16){var orig=u32(v,off+8,le);frames.push({link:ifaces[0].link,ts:null,data:bytes.subarray(off+12,Math.min(off+12+orig,off+bl-4))});}
    frames._le=le;off+=bl;
   }
   return frames;
  }
  var magic=[bytes[0],bytes[1],bytes[2],bytes[3]].join(','),le,nano=false;
  if(magic==='212,195,178,161'||magic==='77,60,178,161'){le=true;nano=bytes[0]===77;}
  else if(magic==='161,178,195,212'||magic==='161,178,60,77'){le=false;nano=bytes[2]===60;}
  else return null;
  var link=u32(v,20,le);off=24;
  while(off+16<=bytes.length){var sec=u32(v,off,le),frac=u32(v,off+4,le),cap=u32(v,off+8,le);if(cap>bytes.length-off-16)break;frames.push({link:link,ts:BigInt(sec)*1000000000n+BigInt(frac)*(nano?1n:1000n),data:bytes.subarray(off+16,off+16+cap)});off+=16+cap;}
  return frames;
 }
 function dnsName(p,start){var labels=[],cur=start,resume=-1,seen={};for(var i=0;i<128&&cur<p.length;i++){if(seen[cur])break;seen[cur]=1;var n=p[cur];if(n===0){cur++;break;}if((n&192)===192){if(cur+1>=p.length)break;if(resume<0)resume=cur+2;cur=((n&63)<<8)|p[cur+1];continue;}if(n&192||cur+1+n>p.length)break;labels.push(String.fromCharCode.apply(null,p.subarray(cur+1,cur+1+n)));cur+=1+n;}return {name:labels.join('.'),end:resume>=0?resume:cur};}
 function packet(f){var p=f.data,o=0,et,src,dst,proto;
  if(f.link===1){if(p.length<14)return null;et=p[12]*256+p[13];o=14;while(et===0x8100||et===0x88a8||et===0x9100){if(o+4>p.length)return null;et=p[o+2]*256+p[o+3];o+=4;}
   if(et===0x0800){if(o+20>p.length)return null;var ih=(p[o]&15)*4;if((p[o]>>4)!==4||o+ih>p.length)return null;proto=p[o+9];src=Array.from(p.subarray(o+12,o+16)).join('.');dst=Array.from(p.subarray(o+16,o+20)).join('.');o+=ih;}
   else if(et===0x86dd){if(o+40>p.length)return null;proto=p[o+6];src=hex(p.subarray(o+8,o+24));dst=hex(p.subarray(o+24,o+40));o+=40;}else return null;
  }else if(f.link===101){if(!p.length)return null;if((p[0]>>4)===4){o=(p[0]&15)*4;proto=p[9];src=Array.from(p.subarray(12,16)).join('.');dst=Array.from(p.subarray(16,20)).join('.');}else if((p[0]>>4)===6){o=40;proto=p[6];src=hex(p.subarray(8,24));dst=hex(p.subarray(24,40));}else return null;}else return null;
  var sp,dp,payload,transport;if(proto===17){if(o+8>p.length)return null;sp=p[o]*256+p[o+1];dp=p[o+2]*256+p[o+3];var len=p[o+4]*256+p[o+5];payload=p.subarray(o+8,o+Math.max(8,len));transport='UDP';}else if(proto===6){if(o+20>p.length)return null;sp=p[o]*256+p[o+1];dp=p[o+2]*256+p[o+3];var h=(p[o+12]>>4)*4;payload=p.subarray(o+h);if(payload.length>=2){var size=payload[0]*256+payload[1];payload=payload.subarray(2,2+size);}transport='TCP';}else return null;
  if(sp!==53&&dp!==53||payload.length<12)return null;var id=payload[0]*256+payload[1],fl=payload[2]*256+payload[3],qd=payload[4]*256+payload[5],an=payload[6]*256+payload[7],name='',qt=null;
  if(qd){var d=dnsName(payload,12);name=d.name;if(d.end+4<=payload.length)qt=payload[d.end]*256+payload[d.end+1];}
  return {id:id,qr:fl>>15,rcode:fl&15,name:name,qtype:qt,answers:an,src:src,dst:dst,sport:sp,dport:dp,transport:transport,ts:f.ts};
 }
 function hex(a){return Array.from(a).map(function(x){return x.toString(16).padStart(2,'0')}).join(':')}
 function runAnalysis(bytes,name,result){var fs=readFrames(bytes);if(!fs)return false;var msgs=[];for(var i=0;i<fs.length;i++){var m=packet(fs[i]);if(m)msgs.push(m);}var qs=msgs.filter(function(x){return !x.qr&&x.name}),rs=msgs.filter(function(x){return x.qr;});if(!qs.length)return false;
  var cnt={};qs.forEach(function(q){var k=q.name.toLowerCase();cnt[k]=(cnt[k]||0)+1;});var domain=Object.keys(cnt).sort(function(a,b){return cnt[b]-cnt[a]})[0],qset=qs.filter(function(x){return x.name.toLowerCase()===domain;}),matched=[];
  qset.forEach(function(q){var r=rs.find(function(x){return x.id===q.id&&x.name.toLowerCase()===q.name.toLowerCase()&&x.src===q.dst&&x.dst===q.src&&x.sport===q.dport&&x.dport===q.sport;});if(r&&q.ts!=null&&r.ts!=null&&r.ts>=q.ts)matched.push({q:q,r:r,dt:r.ts-q.ts});});
  function mode(arr){var c={};arr.forEach(function(x){c[x]=(c[x]||0)+1;});return Object.keys(c).sort(function(a,b){return c[b]-c[a]})[0]||null;}
  var qt=mode(qset.map(function(x){return ({1:'A',2:'NS',5:'CNAME',6:'SOA',12:'PTR',15:'MX',16:'TXT',28:'AAAA',33:'SRV',255:'ANY'})[x.qtype]||String(x.qtype)})),rcCode=mode(matched.map(function(x){return String(x.r.rcode)})),rcNames={0:'NOERROR',1:'FORMERR',2:'SERVFAIL',3:'NXDOMAIN',4:'NOTIMP',5:'REFUSED'},rc=rcCode==null?null:(rcNames[rcCode]||rcCode),status=rcCode==null?'غير محسوم':Number(rcCode)===0?'Success':Number(rcCode)===5?'Refused':'Failure',transport=mode(qset.map(function(x){return x.transport})),sport=mode(qset.map(function(x){return String(x.sport)})),dport=mode(qset.map(function(x){return String(x.dport)})),avg=matched.length?Number(matched.reduce(function(a,x){return a+x.dt},0n))/matched.length/1e9:null;
  var rows=[['اسم النطاق',domain],['نوع استعلام DNS',qt],['إجابة المرحلة المختصرة',status],['رمز الاستجابة الفعلي',rc==null?null:rc+' ('+rcCode+')'],['بروتوكول النقل',transport],['منفذ الوجهة على خادم DNS — إجابة سؤال المنفذ',dport],['منفذ المصدر على جهاز العميل',sport],['زمن الاستجابة — قرّب إلى 6 منازل للإدخال',avg==null?'غير متاح':avg.toFixed(6)]];
  var html='<div class="studentSummary"><h2>🌐 تحليل حزم الشبكة PCAP</h2><div class="studentCard"><b>1️⃣ ماذا فحص صقر؟</b><p>قرأ '+fs.length+' إطارًا، واستخرج '+msgs.length+' رسالة DNS، منها '+qs.length+' استعلامًا و'+rs.length+' استجابة.</p><div class="solvePath">PCAP/PCAPNG → Frames → Ethernet/IP → UDP/TCP → DNS → مطابقة الاستعلام والاستجابة</div></div><div class="studentCard"><b>2️⃣ إجابات المرحلة وأدلتها</b><table><tbody>';
  rows.forEach(function(r){html+='<tr><th>'+esc(r[0])+'</th><td><code>'+esc(r[1]||'لم يُستخرج')+'</code></td></tr>';});html+='</tbody></table></div><div class="studentCard"><b>3️⃣ تفسير مهم</b><p>رمز <code>'+esc(rc||'غير متاح')+'</code> يعني '+(Number(rcCode)===3?'أن اسم النطاق غير موجود (إجابة سلبية). هذا الرمز ليس REFUSED؛ ووفق السؤال الثنائي فالتصنيف هو Failure.':'حالة DNS المبينة أعلاه.')+' منفذ الوجهة 53 هو منفذ خادم DNS، بينما '+esc(sport||'—')+' هو منفذ العميل المؤقت. الزمن الدقيق '+(avg==null?'غير متاح':avg.toFixed(9))+' ثانية، ويُقرب إلى 6 منازل عند الإدخال.</p><details><summary>تفاصيل إضافية</summary><p>الملف: <code>'+esc(name)+'</code> · أزواج DNS المطابقة: '+matched.length+'</p></details></div></div>';
  result.className='result';result.innerHTML=html;result.scrollIntoView({behavior:'smooth',block:'start'});return true;
 }
 window.FalconPcapDnsRun=async function(){var input=el('file'),ta=el('text'),f=(input&&input.files&&input.files[0])||window.__falconDroppedFile;if(f&&!(ta&&ta.value.trim())&&/\.(pcap|pcapng|cap)$/i.test(f.name||'')){try{var r=el('result');r.className='result';r.innerHTML='<div class="finding">⏳ يجري تحليل إطارات PCAP وطلبات DNS…</div>';if(runAnalysis(new Uint8Array(await f.arrayBuffer()),f.name,r))return false;}catch(e){var r2=el('result');if(r2)r2.innerHTML='<div class="finding warn">تعذر تحليل PCAP: '+esc(e.message||e)+'</div>';return false;}}return previous?previous():false;};
 /* web-sessions installs a capture-phase handler and routes unmatched prompts through its
    captured earlier FalconSmartRun. Override that entry point too, or PCAPNG falls through. */
 window.FalconWebSessionRun=async function(){var input=el('file'),ta=el('text'),f=(input&&input.files&&input.files[0])||window.__falconDroppedFile;if(f&&!(ta&&ta.value.trim())&&/\.(pcap|pcapng|cap)$/i.test(f.name||''))return window.FalconPcapDnsRun();return previousWebSession?previousWebSession():(previous?previous():false);};
 window.FalconPcapRawTimeRun=window.FalconPcapDnsRun;window.FalconSmartRun=window.FalconPcapDnsRun;
 window.FalconPcapDnsTest={readFrames:readFrames,analyze:function(bytes,name){return runAnalysis(bytes,name,el('result'));}};
})();
