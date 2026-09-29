(function(){
 var originalRun=window.FalconSmartRun;
 function byId(id){return document.getElementById(id);}
 function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
 function u32(a,i){return ((a[i]<<24)>>>0)+(a[i+1]<<16)+(a[i+2]<<8)+a[i+3];}
 function paeth(a,b,c){var p=a+b-c,pa=Math.abs(p-a),pb=Math.abs(p-b),pc=Math.abs(p-c);return pa<=pb&&pa<=pc?a:pb<=pc?b:c;}
 function rawRGBA(a){
  var p=8,w=0,h=0,bd=-1,ct=-1,id=[];
  while(p+12<=a.length){var n=u32(a,p),t=String.fromCharCode(a[p+4],a[p+5],a[p+6],a[p+7]),d=p+8;if(d+n+4>a.length)throw Error('PNG chunk truncated');
   if(t==='IHDR'){w=u32(a,d);h=u32(a,d+4);bd=a[d+8];ct=a[d+9];}
   if(t==='IDAT')id.push(a.slice(d,d+n));p=d+n+4;if(t==='IEND')break;
  }
  if(!w||!h||bd!==8||ct!==6)return null;
  if(typeof pako==='undefined')throw Error('pako not loaded');
  var total=0,i;for(i=0;i<id.length;i++)total+=id[i].length;var z=new Uint8Array(total),o=0;for(i=0;i<id.length;i++){z.set(id[i],o);o+=id[i].length;}
  var inf=pako.inflate(z),stride=w*4,need=h*(stride+1);if(inf.length<need)throw Error('PNG data incomplete');
  var out=new Uint8Array(stride*h),ip=0;
  for(var y=0;y<h;y++){var f=inf[ip++];for(var x=0;x<stride;x++){var v=inf[ip++],left=x>=4?out[y*stride+x-4]:0,up=y?out[(y-1)*stride+x]:0,ul=y&&x>=4?out[(y-1)*stride+x-4]:0;
    if(f===1)v=(v+left)&255;else if(f===2)v=(v+up)&255;else if(f===3)v=(v+Math.floor((left+up)/2))&255;else if(f===4)v=(v+paeth(left,up,ul))&255;else if(f!==0)throw Error('Unsupported PNG filter '+f);
    out[y*stride+x]=v;
  }}
  return {w:w,h:h,p:out};
 }
 function textFromBytes(a){var s='',n=8192;for(var i=0;i<a.length;i+=n)s+=String.fromCharCode.apply(null,a.subarray(i,Math.min(i+n,a.length)));return s;}
 function flagMatches(s){var r=/[A-Za-z][A-Za-z0-9_.:-]{1,30}\{[^{}\r\n]{2,200}\}/g,a=[],m;while((m=r.exec(s||''))!==null)if(a.indexOf(m[0])<0)a.push(m[0]);return a;}
 function extract(r){
  var bytes=[],v=0,n=0,p=r.p;
  for(var i=0;i<p.length;i+=4)for(var c=0;c<4;c++){v=(v<<1)|(p[i+c]&1);if(++n===8){bytes.push(v);v=0;n=0;}}
  var s=textFromBytes(new Uint8Array(bytes)),hits=flagMatches(s),tokens=s.match(/[A-Za-z0-9+\/]{12,}={0,2}/g)||[];
  for(var j=0;j<tokens.length;j++){try{var d=atob(tokens[j]),ff=flagMatches(d);for(var k=0;k<ff.length;k++)if(hits.indexOf(ff[k])<0)hits.push(ff[k]);}catch(e){}}
  return hits;
 }
 async function analyze(file){
  if(!file)return false;var result=byId('result');if(!result)return false;
  try{var a=new Uint8Array(await file.arrayBuffer());if(a.length<8||a[0]!==137||a[1]!==80||a[2]!==78||a[3]!==71)return false;var r=rawRGBA(a);if(!r)return false,hits=extract(r);if(!hits.length)return false;
   var html='<div class="studentSummary"><h2>🎉 تم حل تحدي PNG Steganography</h2><div class="studentCard"><b>1️⃣ نوع التحدي</b><p>PNG / Raw RGBA LSB Steganography</p></div><div class="studentCard"><b>2️⃣ ماذا اكتشف صقر؟</b><p>قرأ بيانات PNG الخام مباشرة دون Canvas، وفك IDAT ومرشحات PNG ثم استخرج LSB من RGBA.</p><div class="solvePath">PNG → IDAT → Deflate → PNG Filters → Raw RGBA → LSB → Base64 → Flag</div></div><div class="studentCard success"><b>3️⃣ العلم المرشح 🚩</b>';
   for(var i=0;i<hits.length;i++)html+='<div class="flag">'+esc(hits[i])+'</div>';result.innerHTML=html+'</div></div>';result.className='result';result.scrollIntoView({behavior:'smooth',block:'start'});return true;
  }catch(e){result.innerHTML='<div class="studentSummary"><h2>🧪 Raw PNG V87 Diagnostic</h2><div class="studentCard"><b>سبب فشل المحرك الجديد:</b><pre style="white-space:pre-wrap;direction:ltr;text-align:left">'+esc(e&&e.message?e.message:e)+'</pre></div></div>';result.className='result';return 'error';}
 }
 window.FalconRawPngRun=async function(){
 var inp=byId('file')||byId('fileInput'),ta=byId('text'),file=(inp&&inp.files&&inp.files[0])||window.__falconDroppedFile,pasted=ta?ta.value.trim():'';
 if(file&&!pasted){var a=new Uint8Array(await file.slice(0,8).arrayBuffer());var isPng=a.length>=8&&a[0]===137&&a[1]===80&&a[2]===78&&a[3]===71&&a[4]===13&&a[5]===10&&a[6]===26&&a[7]===10;if(isPng){var hit=await analyze(file);if(hit)return false;}}
 return originalRun?originalRun():false;
};
window.FalconSmartRun=window.FalconRawPngRun;

try{var badge=document.createElement('div');badge.id='rawPngEngineBadge';badge.textContent='🟢 Raw PNG Engine V87 Loaded';badge.style.cssText='position:fixed;bottom:12px;left:12px;z-index:99999;background:#073b2a;color:#bfffdc;border:1px solid #19c37d;padding:8px 12px;border-radius:10px;font:700 13px system-ui;box-shadow:0 4px 18px #0008';document.body.appendChild(badge);}catch(e){}
})();