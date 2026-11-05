/* Falcon V208: narrowly scoped PNG pixel-LSB check. Other analyzers remain untouched. */
(function(){'use strict';
var FLAG=/(?:academy|flag|ctf|moe)\{[A-Za-z0-9_\-]{1,160}\}/ig;
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function files(){var input=document.getElementById('file');return input&&input.files&&input.files.length?Array.from(input.files):Array.from(window.__falconDroppedFiles||[]);}
function png(b){return b.length>8&&b[0]===137&&b[1]===80&&b[2]===78&&b[3]===71&&b[4]===13&&b[5]===10&&b[6]===26&&b[7]===10;}
async function pixels(bytes){
 var blob=new Blob([bytes],{type:'image/png'}),url=URL.createObjectURL(blob),img;
 try{img=new Image();img.src=url;await img.decode();if(img.width*img.height>8000000) return null;
 var canvas=document.createElement('canvas');canvas.width=img.width;canvas.height=img.height;
 var ctx=canvas.getContext('2d',{willReadFrequently:true});if(!ctx)return null;
 ctx.drawImage(img,0,0);return ctx.getImageData(0,0,img.width,img.height).data;
 }finally{URL.revokeObjectURL(url);}
}
function scan(data){
 var limit=Math.min(data.length/4,2000000),hits=[];
 var routes=[[0],[1],[2],[3],[0,1,2],[2,1,0]];
 for(var r=0;r<routes.length;r++)for(var plane=0;plane<2;plane++){
  var channels=routes[r],max=Math.min(limit*channels.length,262144),bits=new Uint8Array(max),k=0;
  for(var i=0;k<max&&i<limit;i++)for(var c=0;c<channels.length&&k<max;c++)bits[k++]=(data[i*4+channels[c]]>>plane)&1;
  for(var offset=0;offset<8;offset++)for(var reverse=0;reverse<2;reverse++){
   var n=Math.min(32768,Math.floor((k-offset)/8)),chars=[];
   for(var j=0;j<n;j++){var val=0;for(var b=0;b<8;b++)val|=bits[offset+j*8+b]<<(reverse?b:7-b);chars.push(String.fromCharCode(val));}
   var matches=chars.join('').match(FLAG)||[];
   for(var h=0;h<matches.length;h++)hits.push({flag:matches[h],route:channels.map(x=>'RGBA'[x]).join('')+' / bit '+plane+' / '+(reverse?'LSB-first':'MSB-first')+' / offset '+offset});
  }
 }
 return [...new Map(hits.map(x=>[x.flag,x])).values()];
}
async function inspect(file){
 var bytes=new Uint8Array(await file.arrayBuffer());if(!png(bytes))return [];
 var data=await pixels(bytes);return data?scan(data):[];
}
function render(hits,source){var el=document.getElementById('result');if(!el)return;
 el.className='result';el.innerHTML='<div class="studentSummary"><h2>🚩 نجح صقر في تحليل Steganography</h2><div class="studentCard"><b>مصدر الدليل</b><p>'+esc(source)+'</p><div class="solvePath">ZIP → PNG → Pixels → LSB → Flag Hunter</div></div>'+hits.map(x=>'<div class="studentCard success"><b>العلم المستخرج</b><div class="flag">'+esc(x.flag)+'</div><p>طريقة الاستخراج: '+esc(x.route)+'</p></div>').join('')+'</div>';
 el.scrollIntoView({behavior:'smooth',block:'start'});
}
async function run(){
 var chosen=files();if(chosen.length!==1)return false;var file=chosen[0],name=file.name||'',targets=[];
 if(/\.png$/i.test(name))targets=[{file:file,path:name}];
 else if(/\.zip$/i.test(name)&&typeof JSZip!=='undefined'&&file.size<=30000000){
  var zip=await JSZip.loadAsync(file),entries=Object.values(zip.files).filter(x=>!x.dir&&/\.png$/i.test(x.name)&&(!x._data||x._data.uncompressedSize<=16000000)).slice(0,16);
  for(var e of entries){targets.push({file:new File([await e.async('uint8array')],e.name,{type:'image/png'}),path:name+' → '+e.name});}
 }else return false;
 for(var t of targets){var hits=await inspect(t.file);if(hits.length){render(hits,t.path);return true;}}
 return false;
}
document.addEventListener('click',function(ev){if(!ev.target.closest||!ev.target.closest('#solve'))return;
 var fs=files();if(fs.length!==1||!/\.(?:png|zip)$/i.test(fs[0].name||''))return;
 ev.preventDefault();ev.stopImmediatePropagation();
 var out=document.getElementById('result');if(out){out.className='result';out.innerHTML='<div class="finding">⏳ فحص بيانات الصورة المخفية LSB محليًا…</div>';}
 run().then(function(found){if(!found&&typeof window.FalconMultiFileRun==='function')window.FalconMultiFileRun();}).catch(function(){if(typeof window.FalconMultiFileRun==='function')window.FalconMultiFileRun();});
},true);
})();