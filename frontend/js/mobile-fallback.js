(function(){
function byId(id){return document.getElementById(id);}
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function flags(s){var r=/(?:flag|ctf|moe)[_\- ]?\{[^\r\n{}]{1,200}\}/ig,a=[],m;while((m=r.exec(s||''))!==null)a.push(m[0]);return a;}
function b64(s){try{return atob(String(s).replace(/\s/g,''));}catch(e){return '';}}
function hexDecode(s){try{return (s.match(/[0-9a-f]{2}/ig)||[]).map(function(x){return String.fromCharCode(parseInt(x,16));}).join('');}catch(e){return '';}}
function rotN(s,n){return String(s).replace(/[A-Za-z]/g,function(c){var a=c<='Z'?65:97;return String.fromCharCode((c.charCodeAt(0)-a+n)%26+a);});}
function rot13(s){return rotN(s,13);}
function binaryDecode(s){try{var b=String(s).replace(/\s/g,'');if(!/^[01]+$/.test(b)||b.length%8)return '';return (b.match(/.{8}/g)||[]).map(function(x){return String.fromCharCode(parseInt(x,2));}).join('');}catch(e){return '';}}
function urlDecode(s){try{var x=decodeURIComponent(String(s).replace(/\+/g,' '));return x!==s?x:'';}catch(e){return '';}}
var MORSE={'.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E','..-.':'F','--.':'G','....':'H','..':'I','.---':'J','-.-':'K','.-..':'L','--':'M','-.':'N','---':'O','.--.':'P','--.-':'Q','.-.':'R','...':'S','-':'T','..-':'U','...-':'V','.--':'W','-..-':'X','-.--':'Y','--..':'Z','-----':'0','.----':'1','..---':'2','...--':'3','....-':'4','.....':'5','-....':'6','--...':'7','---..':'8','----.':'9'};
function morseDecode(s){var t=String(s).trim();if(!/^[.\-\/\s]+$/.test(t))return '';var bad=false,v=t.split(/\s*\/\s*/).map(function(w){return w.split(/\s+/).map(function(x){if(!MORSE[x]){bad=true;return '?';}return MORSE[x];}).join('');}).join(' ');return bad?'':v;}
function quality(s){s=String(s||'');if(!s)return 0;var printable=(s.match(/[\x20-\x7e\r\n\t]/g)||[]).length/Math.max(1,s.length),score=Math.round(printable*40);if(flags(s).length)score+=200;if(/flag|ctf|moe|secret|password|key|token/i.test(s))score+=60;if(/[{}]/.test(s))score+=10;return score;}
function candidates(t){var a=[],z;t=String(t||'').trim();if(/^[A-Za-z0-9+/=\s]+$/.test(t)&&t.replace(/\s/g,'').length>=8&&(t.replace(/\s/g,'').length%4===0)){z=b64(t);if(z)a.push(['Base64',z]);}if(/^(?:[0-9a-f]{2}\s*){4,}$/i.test(t)){z=hexDecode(t);if(z)a.push(['Hex',z]);}if(/^[01\s]{8,}$/.test(t)){z=binaryDecode(t);if(z)a.push(['Binary',z]);}z=urlDecode(t);if(z)a.push(['URL Decode',z]);if(/^[.\-\/\s]+$/.test(t)&&t.length>5){z=morseDecode(t);if(z)a.push(['Morse',z]);}if(/[A-Za-z]{4}/.test(t))a.push(['ROT13',rot13(t)]);if((t.match(/[A-Za-z]/g)||[]).length>=6){for(var n=1;n<26;n++){z=rotN(t,n);if(/flag|ctf|moe|secret|key/i.test(z))a.push(['Caesar '+n,z]);}}return a;}
function analyzeText(raw,deep,source){
 var result=byId('result'),root=source||'Original',queue=[{v:raw,p:root,d:0}],seen={},rows=[],found=[],limit=deep?6:3,count=0,best={score:quality(raw),path:root,value:raw};
 seen[raw]=1;var direct=flags(raw);for(var df=0;df<direct.length;df++)found.push({flag:direct[df],path:root});
 while(queue.length&&count<(deep?240:90)){
  var x=queue.shift();if(x.d>=limit)continue;var cs=candidates(x.v);
  cs.sort(function(a,b){return quality(b[1])-quality(a[1]);});
  for(var i=0;i<cs.length;i++){var n=cs[i][1],p=x.p+' → '+cs[i][0];if(!seen[n]&&n.length<100000){seen[n]=1;var sc=quality(n);rows.push({path:p,value:n,score:sc,depth:x.d+1});if(sc>best.score)best={score:sc,path:p,value:n};var ff=flags(n);for(var k=0;k<ff.length;k++)found.push({flag:ff[k],path:p});queue.push({v:n,p:p,d:x.d+1});count++;}}
 }
 rows.sort(function(a,b){return b.score-a.score||a.depth-b.depth;});
 var unique=[],u={},flagPaths={};for(var q=0;q<found.length;q++)if(!u[found[q].flag]){u[found[q].flag]=1;unique.push(found[q].flag);flagPaths[found[q].flag]=found[q].path;}
 var detected=[];var names=['Base64','Hex','Binary','URL Decode','ROT13','Morse','Caesar'];for(var ni=0;ni<names.length;ni++){for(var di=0;di<rows.length;di++)if(rows[di].path.indexOf(names[ni])>=0){detected.push(names[ni]);break;}}
 var html='<div class="studentSummary"><h2>'+(unique.length?'🎉 تم العثور على علم محتمل':'🧭 نتيجة التحليل')+'</h2>';
 html+='<div class="studentCard"><b>1️⃣ ما نوع التحدي؟</b><p>'+(detected.length?'يبدو أنه تحدي ترميز/تشفير نصي متعدد المراحل.':'لم يتضح نوع الترميز تلقائيًا بعد.')+'</p></div>';
 html+='<div class="studentCard"><b>2️⃣ ماذا اكتشف صقر CTF؟</b><p>'+(detected.length?'جرّب النظام تلقائيًا: <strong>'+esc(detected.join('، '))+'</strong>، وتتبع حتى '+limit+' طبقات دون الحاجة لفك النص يدويًا.':'لم يجد تحويلًا واضحًا في الفحص الحالي.')+'</p></div>';
 if(unique.length){html+='<div class="studentCard success"><b>3️⃣ العلم المرشح 🚩</b><p>نجح النظام في الوصول إلى صيغة علم. مسار الحل:</p>';for(var f=0;f<unique.length;f++)html+='<div class="solvePath">'+esc(flagPaths[unique[f]])+'</div><div class="flag">'+esc(unique[f])+'</div>';html+='</div>';}
 else{html+='<div class="studentCard next"><b>3️⃣ أين وصلنا؟</b><p>أفضل مسار حتى الآن: <strong>'+esc(best.path)+'</strong>.</p><p>لم تظهر صيغة Flag واضحة بعد. '+(deep?'هذا يعني غالبًا أن التحدي يحتاج نوع تحليل آخر أو معلومة/ملفًا إضافيًا، وليس مجرد زيادة طبقات عشوائية.':'اضغط <strong>🧠 تحليل عميق</strong> ليكمل النظام المسارات الواعدة فقط.')+'</p></div>';}
 html+='</div><details class="tech"><summary>🔧 عرض التفاصيل التقنية للمتقدمين</summary><div class="techBody"><h3>أفضل مسارات التحليل</h3>';
 for(var r=0;r<Math.min(rows.length,deep?35:15);r++)html+='<div class="finding"><b>'+esc(rows[r].path)+'</b> <span class="score">درجة '+rows[r].score+'</span>: <code>'+esc(rows[r].value.slice(0,350))+'</code></div>';
 if(!rows.length)html+='<div class="finding warn">لم يتم اكتشاف ترميز مدعوم في النص الحالي.</div>';html+='</div></details>';
 result.innerHTML=html;result.className='result';result.scrollIntoView({behavior:'smooth',block:'start'});
}
function runText(raw,deep,source){
 var result=byId('result');
 raw=String(raw||'').trim();
 result.className='result';
 if(!raw){result.innerHTML='<div class="finding warn">⚠️ لم يصل أي نص إلى محرك التحليل.</div>';return false;}
 result.innerHTML='<div class="finding">⏳ بدأ التحليل — تم استلام <b>'+raw.length+'</b> حرفًا من '+esc(source||'الإدخال')+'.</div>';
 setTimeout(function(){try{analyzeText(raw,!!deep);}catch(e){result.innerHTML='<div class="finding warn">⚠️ خطأ في محرك التحليل: '+esc(e.message||e)+'</div>';}},20);
 return false;
}
window.FalconSelfTest=function(){
 var plain='CTF{FALCON_ENGINE_OK}',rot=rot13(plain),encoded=btoa(rot),ta=byId('text');
 if(ta)ta.value=encoded;
 return runText(encoded,true,'اختبار المحرك');
};
function bytesText(u8){var s='',chunk=8192;for(var i=0;i<u8.length;i+=chunk)s+=String.fromCharCode.apply(null,u8.subarray(i,Math.min(i+chunk,u8.length)));return s;}
function pngEnd(u8){if(u8.length<12||u8[0]!==137||u8[1]!==80||u8[2]!==78||u8[3]!==71)return -1;var p=8;while(p+12<=u8.length){var len=((u8[p]<<24)>>>0)+(u8[p+1]<<16)+(u8[p+2]<<8)+u8[p+3],type=String.fromCharCode(u8[p+4],u8[p+5],u8[p+6],u8[p+7]),end=p+12+len;if(end>u8.length)return -1;if(type==='IEND')return end;p=end;}return -1;}
function parsePngChunks(u8){
 var out={chunks:[],texts:[]};if(u8.length<8||u8[0]!==137||u8[1]!==80||u8[2]!==78||u8[3]!==71)return out;
 var p=8,guard=0;
 while(p+12<=u8.length&&guard++<10000){
  var len=((u8[p]<<24)>>>0)+(u8[p+1]<<16)+(u8[p+2]<<8)+u8[p+3],type=String.fromCharCode(u8[p+4],u8[p+5],u8[p+6],u8[p+7]),ds=p+8,de=ds+len,end=de+4;
  if(end>u8.length)break;out.chunks.push({type:type,len:len});
  if(type==='tEXt'){
   var data=bytesText(u8.slice(ds,de)),z=data.indexOf('\x00'),key=z>=0?data.slice(0,z):'',val=z>=0?data.slice(z+1):data;
   if(val)out.texts.push({type:type,key:key,value:val});
  }else if(type==='iTXt'){
   var idata=bytesText(u8.slice(ds,de)),iz=idata.indexOf('\x00');
   if(iz>=0){var rest=idata.slice(iz+1),parts=rest.split('\x00');var val=parts.length?parts[parts.length-1]:'';if(val)out.texts.push({type:type,key:idata.slice(0,iz),value:val});}
  }else if(type==='zTXt'){
   var zdata=bytesText(u8.slice(ds,de)),zz=zdata.indexOf('\x00');
   out.texts.push({type:type,key:zz>=0?zdata.slice(0,zz):'',value:'',compressed:true});
  }
  p=end;if(type==='IEND')break;
 }
 return out;
}

async function analyzeEmbeddedZip(extra,result){
 if(!(extra.length>=4&&extra[0]===0x50&&extra[1]===0x4b&&(extra[2]===0x03||extra[2]===0x05||extra[2]===0x07)))return false;
 if(typeof JSZip==='undefined'){result.innerHTML='<div class="finding warn">⚠️ تم اكتشاف ZIP مضمّن، لكن مكتبة فك ZIP لم تُحمّل. أعد تحميل الصفحة.</div>';return true;}
 var zip=await JSZip.loadAsync(extra),names=Object.keys(zip.files),texts=[],found=[];
 for(var i=0;i<names.length;i++){var zf=zip.files[names[i]];if(zf.dir)continue;if(/\.(txt|log|csv|json|xml|md|ini|cfg)$/i.test(zf.name)||names.length<=5){var t=await zf.async('string');texts.push({name:zf.name,text:t});var ff=flags(t);for(var k=0;k<ff.length;k++)found.push(ff[k]);}}
 var html='<div class="studentSummary"><h2>🧠 Challenge Brain</h2><div class="studentCard"><b>1️⃣ المسار المكتشف</b><p>PNG → بيانات بعد IEND → <strong>ZIP مضمّن</strong></p></div><div class="studentCard"><b>2️⃣ الملفات المستخرجة</b><p>'+esc(names.join('، '))+'</p></div>';
 if(found.length){html+='<div class="studentCard success"><b>3️⃣ العلم المرشح 🚩</b>';for(var j=0;j<found.length;j++)html+='<div class="flag">'+esc(found[j])+'</div>';result.innerHTML=html+'</div></div>';return true;}
 var combined='';for(var x=0;x<texts.length;x++)combined+='\n'+texts[x].text;
 var dataMatch=combined.match(/(?:DATA\s*=\s*)?([A-Za-z0-9+/=]{12,})/g),candidate='';
 if(dataMatch){for(var d=0;d<dataMatch.length;d++){var v=dataMatch[d].replace(/^DATA\s*=\s*/,'');if(v.length>candidate.length)candidate=v;}}
 html+='<div class="studentCard next"><b>3️⃣ متابعة التحليل</b><p>لم يوجد Flag مباشر داخل ZIP. سيُرسل المحتوى النصي والترميز المكتشف تلقائيًا إلى Smart Decoder.</p></div></div>';
 result.innerHTML=html;
 if(candidate){setTimeout(function(){analyzeText(candidate,true);},80);}else if(combined.trim()){setTimeout(function(){analyzeText(combined,true);},80);}
 return true;
}
function ipstr(u,o){return u[o]+'.'+u[o+1]+'.'+u[o+2]+'.'+u[o+3];}
function analyzePcap(u8,name,result){
 try{
  if(u8.length<24)return false;
  var dv=new DataView(u8.buffer,u8.byteOffset,u8.byteLength),magic=dv.getUint32(0,true),le=true;
  if(magic===0xd4c3b2a1)le=false; else if(magic!==0xa1b2c3d4)return false;
  var link=dv.getUint32(20,le);if(link!==1){result.innerHTML='<div class="finding warn">⚠️ PCAP معروف، لكن نوع Link-Layer الحالي غير مدعوم بعد.</div>';return true;}
  var p=24,packets=0,hosts={},streams={},dnsQueries=[];
  while(p+16<=u8.length){
   var incl=dv.getUint32(p+8,le),s=p+16,e=s+incl;if(e>u8.length)break;packets++;
   if(incl>=54&&u8[s+12]===0x08&&u8[s+13]===0x00){
    var ip=s+14,ihl=(u8[ip]&15)*4,proto=u8[ip+9],src=ipstr(u8,ip+12),dst=ipstr(u8,ip+16);hosts[src]=1;hosts[dst]=1;
    if(proto===17&&ip+ihl+8<=e){
     var udp=ip+ihl,usport=(u8[udp]<<8)|u8[udp+1],udport=(u8[udp+2]<<8)|u8[udp+3],ds=udp+8;
     if((usport===53||udport===53)&&ds+12<e){
      var qd=(u8[ds+4]<<8)|u8[ds+5],pos=ds+12;
      if(qd>0){var labels=[],guard=0;while(pos<e&&guard++<128){var ln=u8[pos++];if(ln===0)break;if((ln&192)===192){pos++;break;}if(ln>63||pos+ln>e)break;var lab='';for(var li=0;li<ln;li++)lab+=String.fromCharCode(u8[pos++]);labels.push(lab);}if(labels.length)dnsQueries.push(labels.join('.'));}
     }
    }
    if(proto===6&&ip+ihl+20<=e){
     var tcp=ip+ihl,sport=(u8[tcp]<<8)|u8[tcp+1],dport=(u8[tcp+2]<<8)|u8[tcp+3],seq=dv.getUint32(tcp+4,false),doff=(u8[tcp+12]>>4)*4,ps=tcp+doff;
     if(ps<e){
      var key=src+':'+sport+'>'+dst+':'+dport;
      if(!streams[key])streams[key]=[];
      streams[key].push({seq:seq,data:u8.slice(ps,e)});
     }
    }
   } p=e;
  }
  var dnsParts=[];
  for(var dq=0;dq<dnsQueries.length;dq++){
   var dm=dnsQueries[dq].match(/^(\d{2})-([A-Za-z0-9_-]+)\./);
   if(dm)dnsParts.push({n:parseInt(dm[1],10),v:dm[2],q:dnsQueries[dq]});
  }
  dnsParts.sort(function(a,b){return a.n-b.n;});
  if(dnsParts.length){
   var joined='';for(var dp=0;dp<dnsParts.length;dp++)joined+=dnsParts[dp].v;
   var dnsHtml='<div class="studentSummary"><h2>🌐 تحليل DNS</h2><div class="studentCard"><b>1️⃣ نوع التحدي</b><p>PCAP / DNS Analysis</p></div><div class="studentCard"><b>2️⃣ ماذا اكتشف صقر CTF؟</b><p>قرأ <strong>'+packets+'</strong> حزمة، واستخرج <strong>'+dnsQueries.length+'</strong> DNS Query، واكتشف <strong>'+dnsParts.length+'</strong> أجزاء بيانات غير طبيعية ومرتبة.</p><div class="solvePath">PCAP → UDP/53 → DNS Queries → Chunk Detection → Reassembly</div></div><div class="studentCard next"><b>3️⃣ Challenge Brain</b><p>تم تجميع أجزاء DNS وسيتم إرسال الناتج تلقائيًا إلى Smart Decoder.</p><div class="solvePath">DNS Chunks → Reassembled Data → Smart Decoder</div></div></div>';
   result.innerHTML=dnsHtml;
   setTimeout(function(){analyzeText(joined,true);},120);return true;
  }
  var rebuilt=[],streamCount=0;
  Object.keys(streams).forEach(function(key){
   var segs=streams[key];segs.sort(function(a,b){return a.seq-b.seq;});
   var bytes=[],next=null;
   for(var i=0;i<segs.length;i++){
    var seg=segs[i],data=seg.data,startAt=0;
    if(next!==null&&seg.seq<next)startAt=Math.min(data.length,next-seg.seq);
    for(var j=startAt;j<data.length;j++)bytes.push(data[j]);
    var endSeq=seg.seq+data.length;if(next===null||endSeq>next)next=endSeq;
   }
   if(bytes.length){streamCount++;rebuilt.push({key:key,text:bytesText(new Uint8Array(bytes))});}
  });
  var http=[];
  for(var r=0;r<rebuilt.length;r++)if(/HTTP\/|GET |POST |Host:|Content-Type:|X-[A-Za-z0-9-]+:/i.test(rebuilt[r].text))http.push(rebuilt[r].text);
  var combined=http.join('\n'),direct=flags(combined),vals=[],m;
  var headerRe=/^[A-Za-z0-9-]+:\s*([A-Za-z0-9+\/]{12,}={0,2})\s*$/gm;
  while((m=headerRe.exec(combined))!==null)vals.push(m[1]);
  var genericRe=/(?:^|[=:\s])([A-Za-z0-9+\/]{20,}={0,2})(?=\r?$|[\s&])/gm;
  while((m=genericRe.exec(combined))!==null)vals.push(m[1]);
  vals=vals.filter(function(v,i,a){return a.indexOf(v)===i;});
  var html='<div class="studentSummary"><h2>🌐 تحليل الشبكة</h2><div class="studentCard"><b>1️⃣ نوع التحدي</b><p>PCAP / Network Analysis</p></div><div class="studentCard"><b>2️⃣ ماذا اكتشف صقر CTF؟</b><p>قرأ <strong>'+packets+'</strong> حزم، وأعاد بناء <strong>'+streamCount+'</strong> TCP Stream، ووجد <strong>'+http.length+'</strong> تدفق HTTP.</p><div class="solvePath">PCAP → TCP Segments → Stream Reassembly → HTTP</div></div>';
  if(direct.length){html+='<div class="studentCard success"><b>3️⃣ العلم المرشح 🚩</b>';for(var q=0;q<direct.length;q++)html+='<div class="flag">'+esc(direct[q])+'</div>';result.innerHTML=html+'</div></div>';return true;}
  if(vals.length){
   html+='<div class="studentCard next"><b>3️⃣ Challenge Brain</b><p>بعد إعادة تجميع TCP وجد النظام بيانات مرمّزة داخل HTTP، وسيحللها تلقائيًا.</p><div class="solvePath">TCP Stream → HTTP → Encoded Data → Smart Decoder</div></div></div>';result.innerHTML=html;
   vals.sort(function(a,b){return b.length-a.length;});setTimeout(function(){analyzeText(vals[0],true);},120);return true;
  }
  html+='<div class="studentCard next"><b>3️⃣ النتيجة</b><p>تمت إعادة تجميع TCP، لكن لم يظهر ترميز واضح. الخطوة التالية ستكون تحليل DNS أو بروتوكولات أخرى.</p></div></div>';result.innerHTML=html;return true;
 }catch(e){result.innerHTML='<div class="finding warn">⚠️ خطأ في PCAP Analyzer: '+esc(e.message||e)+'</div>';return true;}
}
function analyzePngLSB(file,u8,result){
 return new Promise(function(resolve){
  try{
   var blob=new Blob([u8],{type:'image/png'}),url=URL.createObjectURL(blob),img=new Image();
   img.onerror=function(){URL.revokeObjectURL(url);resolve(false);};
   img.onload=function(){
    try{
     var cv=document.createElement('canvas');cv.width=img.naturalWidth;cv.height=img.naturalHeight;
     var cx=cv.getContext('2d',{willReadFrequently:true});cx.drawImage(img,0,0);
     var px=cx.getImageData(0,0,cv.width,cv.height).data,streams=[];
     function addStream(label,mode){
      var bits=[],bytes=[];
      if(mode==='rgb'){for(var p=0;p<px.length;p+=4)bits.push(px[p]&1,px[p+1]&1,px[p+2]&1);}
      else{for(var i=mode;i<px.length;i+=4)bits.push(px[i]&1);}
      for(var b=0;b+7<bits.length;b+=8){var v=0;for(var k=0;k<8;k++)v=(v<<1)|bits[b+k];bytes.push(v);}
      streams.push({label:label,text:bytesText(new Uint8Array(bytes))});
     }
     addStream('R channel LSB',0);addStream('G channel LSB',1);addStream('B channel LSB',2);addStream('RGB interleaved LSB','rgb');
     var direct=[];
     for(var si=0;si<streams.length;si++){var ff=flags(streams[si].text);for(var q=0;q<ff.length;q++)direct.push({flag:ff[q],path:streams[si].label});}
     if(direct.length){
      var seen={},html='<div class="studentSummary"><h2>🕵️ تحليل LSB Steganography</h2><div class="studentCard"><b>1️⃣ نوع التحدي</b><p>PNG / Pixel Steganography</p></div><div class="studentCard"><b>2️⃣ ماذا اكتشف صقر CTF؟</b><p>فحص النظام قنوات R وG وB وكذلك RGB المتداخل.</p><div class="solvePath">PNG → Pixels → LSB Bits → Bytes → Flag Hunter</div></div><div class="studentCard success"><b>3️⃣ العلم المرشح 🚩</b>';
      for(var di=0;di<direct.length;di++)if(!seen[direct[di].flag]){seen[direct[di].flag]=1;html+='<div class="flag">'+esc(direct[di].flag)+'</div><p>المسار: <strong>'+esc(direct[di].path)+'</strong></p>';}
      result.innerHTML=html+'</div></div>';URL.revokeObjectURL(url);resolve(true);return;
     }
     /* No direct flag: send plausible LSB byte streams into the same chained decoder. */
     var best=null;
     for(var s=0;s<streams.length;s++){
      var t=streams[s].text.split('\x00')[0].trim();
      if(t.length<8)continue;
      var sc=quality(t);
      if(/^[A-Za-z0-9+\/=\s]+$/.test(t)&&t.replace(/\s/g,'').length%4===0)sc+=120;
      if(/^(?:[0-9a-f]{2}\s*){4,}$/i.test(t))sc+=100;
      if(!best||sc>best.score)best={label:streams[s].label,text:t,score:sc};
     }
     if(best){
      result.innerHTML='<div class="studentSummary"><h2>🧠 Challenge Brain</h2><div class="studentCard"><b>1️⃣ تم فك LSB</b><p>لم يظهر Flag مباشر، لكن تم استخراج بيانات قابلة للتحليل من <strong>'+esc(best.label)+'</strong>.</p></div><div class="studentCard next"><b>2️⃣ متابعة تلقائية</b><p>سيتم إرسال ناتج LSB إلى Smart Decoder بدل التوقف هنا.</p><div class="solvePath">PNG → LSB → Bytes → Encoded Data → Smart Decoder</div></div></div>';
      URL.revokeObjectURL(url);
      setTimeout(function(){analyzeText(best.text,true,'PNG → LSB → '+best.label);},120);
      resolve(true);return;
     }
     URL.revokeObjectURL(url);resolve(false);
    }catch(e){URL.revokeObjectURL(url);resolve(false);}
   };img.src=url;
  }catch(e){resolve(false);}
 });
}
function analyzeFile(file){
 var result=byId('result');result.className='result';result.innerHTML='<div class="finding">⏳ جارٍ قراءة الملف وتحليله داخل جهازك...</div>';
 var reader=new FileReader();
 reader.onerror=function(){result.innerHTML='<div class="finding warn">⚠️ تعذر قراءة الملف.</div>';};
 reader.onload=async function(){try{
  var u8=new Uint8Array(reader.result),name=file.name||'file',lower=name.toLowerCase(),raw=bytesText(u8),allFlags=flags(raw),html='';if(lower.endsWith('.pcap')||lower.endsWith('.cap')){if(analyzePcap(u8,name,result))return;}
  if(lower.endsWith('.png')||(u8[0]===137&&u8[1]===80&&u8[2]===78&&u8[3]===71)){
   var end=pngEnd(u8),extra=end>=0&&end<u8.length?u8.slice(end):new Uint8Array(0),extraText=bytesText(extra),ef=flags(extraText),png=parsePngChunks(u8);
   html='<div class="studentSummary"><h2>🖼️ تحليل الصورة</h2><div class="studentCard"><b>1️⃣ نوع الملف</b><p>PNG — تم تحليل بنية الصورة وقراءة <strong>'+png.chunks.length+'</strong> PNG Chunks حتى IEND.</p></div>';
   if(!extra.length&&!png.texts.length){
    html+='<div class="studentCard"><b>2️⃣ مرحلة Steganography</b><p>لا توجد بيانات بعد IEND ولا metadata نصية. سيبدأ صقر الآن فحص <strong>LSB داخل البكسلات تلقائيًا</strong>…</p><div class="solvePath">PNG → Pixels → RGB → LSB</div></div></div>';
    result.innerHTML=html;
    var lsbHit=await analyzePngLSB(file,u8,result);
    if(lsbHit)return;
    result.innerHTML='<div class="studentSummary"><h2>🖼️ تحليل الصورة</h2><div class="studentCard"><b>1️⃣ نوع الملف</b><p>PNG / Steganography</p></div><div class="studentCard next"><b>2️⃣ نتيجة LSB</b><p>تم فحص LSB في قنوات R وG وB وكذلك RGB المتداخل، ولم تظهر صيغة Flag واضحة.</p></div></div>';
    return;
   }
   if(!extra.length&&png.texts.length){
    var metaVals=[],directMeta=[];
    for(var mt=0;mt<png.texts.length;mt++){var pv=png.texts[mt];if(pv.value){metaVals.push(pv.value);var mf=flags(pv.value);for(var mi=0;mi<mf.length;mi++)directMeta.push(mf[mi]);}}
    html+='<div class="studentCard"><b>2️⃣ ماذا اكتشف صقر CTF؟</b><p>وجد <strong>'+png.texts.length+'</strong> حقل metadata نصيًا داخل PNG: <strong>'+esc(png.texts.map(function(x){return x.type+(x.key?' ('+x.key+')':'');}).join('، '))+'</strong>.</p><div class="solvePath">PNG → Chunks → Metadata</div></div>';
    if(directMeta.length){html+='<div class="studentCard success"><b>3️⃣ العلم المرشح 🚩</b>';for(var mdi=0;mdi<directMeta.length;mdi++)html+='<div class="flag">'+esc(directMeta[mdi])+'</div>';result.innerHTML=html+'</div></div>';return;}
    html+='<div class="studentCard next"><b>3️⃣ Challenge Brain</b><p>الـmetadata لا يحتوي Flag مباشرًا، لذلك سيُرسل المحتوى تلقائيًا إلى Smart Decoder.</p><div class="solvePath">PNG → Metadata → Encoded Data → Smart Decoder</div></div></div>';result.innerHTML=html;
    var bestMeta=metaVals.sort(function(a,b){return b.length-a.length;})[0]||'';if(bestMeta){setTimeout(function(){analyzeText(bestMeta,true);},120);}return;
   }
   if(extra.length){html+='<div class="studentCard"><b>2️⃣ ماذا اكتشف صقر CTF؟</b><p>وجد <strong>'+extra.length+' بايت</strong> من البيانات بعد النهاية الطبيعية للصورة. هذا مؤشر مهم في تحديات Forensics/Steganography.</p></div>';if(await analyzeEmbeddedZip(extra,result))return;
    if(ef.length){html+='<div class="studentCard success"><b>3️⃣ العلم المرشح 🚩</b><p>تم العثور على العلم داخل البيانات الملحقة بالصورة.</p>';for(var i=0;i<ef.length;i++)html+='<div class="flag">'+esc(ef[i])+'</div>';html+='</div>';}
    else{html+='<div class="studentCard next"><b>3️⃣ الخطوة التالية</b><p>تم استخراج البيانات الملحقة وسيجرب عليها محرك فك الترميز تلقائيًا.</p></div></div>';result.innerHTML=html;analyzeText(extraText,true);return;}
   }else html+='<div class="studentCard next"><b>2️⃣ النتيجة</b><p>لم توجد بيانات بعد IEND. سيحتاج الاختبار التالي إلى فحص metadata/chunks أو LSB.</p></div>';
   html+='</div>';result.innerHTML=html;return;
  }
  html='<div class="studentSummary"><h2>📂 تحليل الملف</h2><div class="studentCard"><b>نوع الملف</b><p>'+esc(name)+'</p></div>';
  if(allFlags.length){html+='<div class="studentCard success"><b>🚩 علم محتمل</b>';for(var j=0;j<allFlags.length;j++)html+='<div class="flag">'+esc(allFlags[j])+'</div>';html+='</div>';}else html+='<div class="studentCard next"><b>النتيجة</b><p>لم يظهر Flag نصي مباشر. ستضاف محللات متخصصة لهذا النوع ضمن اختباراتنا التالية.</p></div>';
  result.innerHTML=html+'</div>';
 }catch(e){result.innerHTML='<div class="finding warn">⚠️ خطأ في تحليل الملف: '+esc(e.message||e)+'</div>';}};reader.readAsArrayBuffer(file);return false;
}
window.FalconSmartRun=function(){
 var ta=byId('text'),fi=byId('file'),result=byId('result'),raw=ta?ta.value:'';
 if(fi&&fi.files&&fi.files.length&&!raw.trim()){return analyzeFile(fi.files[0]);}
 if(!raw.trim()){result.className='result';result.innerHTML='<div class="finding warn">⚠️ الصق نص التحدي أو ارفع ملفًا أولًا.</div>';return false;}
 return runText(raw,true,'المحلل الذكي');
};
window.FalconRun=function(deep){
 var ta=byId('text'),fi=byId('file'),result=byId('result');
 if(fi&&fi.files&&fi.files.length){
  result.className='result';
  result.innerHTML='<div class="finding">📂 تم استلام الملف <b>'+esc(fi.files[0].name)+'</b>. تحليل الملفات سيستخدم محرك الملفات في المرحلة التالية. لا يتم تجاهل النص إن كان موجودًا.</div>';
  if(!ta||!ta.value.trim())return false;
 }
 return runText(ta?ta.value:'',!!deep,deep?'التحليل العميق':'التحليل السريع');
};
})();