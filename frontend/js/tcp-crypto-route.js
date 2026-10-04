(function(global){
'use strict';
var busy=false;
function routePrompt(text){
 text=String(text||'');
 if(/(?:^|\n)\s*(?:#{1,6}\s*)?(?:Undo|Credential Stuffing|Secret Box)(?=\s|$)/im.test(text))return false;
 var target=text.match(/\bnc\s+([A-Za-z0-9_.-]+)\s+(\d{1,5})\b/)||text.match(/tcp:\/\/([A-Za-z0-9_.-]+):(\d{1,5})\b/);
 if(target)return Number(target[2])>0&&Number(target[2])<65536;
 return /^\s*(?:N|modulus)\s*[:=]\s*(?:0x[0-9a-f]+|\d+)/im.test(text)&&/^\s*(?:ciphertext|cyphertext|c|ct)\s*[:=]\s*(?:0x[0-9a-f]+|\d+)/im.test(text);
}
function esc(value){return String(value==null?'':value).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function solutionSteps(data){
 var steps=Array.isArray(data.steps)?data.steps:[],items=[];
 function add(title,body){items.push('<li style="margin:14px 0"><strong>'+esc(title)+'</strong><p>'+body+'</p></li>');}
 function code(value){return '<code style="overflow-wrap:anywhere;direction:ltr;unicode-bidi:isolate">'+esc(value)+'</code>';}
 if(data.analyzer==='rsa-tcp'){
  var evidence=steps.filter(function(s){return s.phase==='rsa-decrypt';});
  if(data.samples>0)add('قراءة بيانات RSA','قرأ صقر '+esc(data.samples)+' عينة تحتوي على N (حاصل ضرب العاملين)، وe (الأس العام)، والنص المشفّر. هذه القيم وحدها لا تضمن إمكان فك RSA.');
  evidence.forEach(function(s){
   add('اكتشاف الضعف في العينة '+esc(s.sample),s.method==='shared-factor-gcd'?'قارن صقر قيم N بين العينات. أعطى القاسم المشترك الأكبر gcd عاملًا أكبر من 1 وأصغر من N، فظهر عامل مشترك يمكن استخدامه.':s.method==='small-factor'?(String(s.p)==='2'?'وجد صقر أن N يقبل القسمة على 2، أي إنه زوجي. لذلك p = 2 وq = N ÷ 2؛ استخدام هذا العامل الصغير أضعف المفتاح.':'وجد صقر عاملًا صغيرًا يقسم N دون باقٍ، ثم حسب العامل الآخر بالقسمة.'): 'سجّل المحلل عاملين؛ طريقة استعادتهما: '+code(s.method||'غير موضحة'));
   add('استعادة العاملين والتحقق من بنيتهما','N = '+code(s.n)+'<br>p = '+code(s.p)+'<br>q = '+code(s.q)+'<br>العاملان يحققان N = p × q. '+(s.prime_check==='probable-prime'?'اجتازا اختبار أولية احتماليًا، وهو اختبار قوي لكنه ليس برهان أولية قطعيًا.':''));
   add('حساب المفتاح الخاص',String(s.p)===String(s.q)?'لأن العاملين متساويان، استخدم صقر φ(N) = p × (p − 1)، ثم حسب d بوصفه معكوس e = '+code(s.e)+' بترديد φ(N).':'حسب صقر φ(N) = (p − 1) × (q − 1)، ثم حسب d بوصفه معكوس e = '+code(s.e)+' بترديد φ(N)، بحيث e × d ≡ 1 (mod φ(N)).');
   add('فك الرسالة','حسب صقر m = c^d mod N، حيث c هو النص المشفّر. ثم حوّل العدد m إلى بايتات وقرأ الرسالة النصية.'+(typeof s.plaintext==='string'?'<br>الناتج: '+code(s.plaintext):''));
   add('التحقق بإعادة التشفير',s.reencryption_verified===true?'أعاد صقر الحساب c′ = m^e mod N. تطابقت النتيجة مع c الأصلي، فثبت أن الرسالة المفكوكة تطابق النص المشفّر.':'لم يؤكد المحلل تطابق إعادة التشفير؛ لا يُعتمد هذا المرشح بوصفه حلًا متحققًا.');
  });
  if(!evidence.length)add('موضع التوقف','لا توجد خطوة فك RSA ناجحة مسجلة في هذه النتيجة. '+esc((data.warnings||[]).join(' '))+' لا يعرض صقر عوامل أو مفتاحًا خاصًا لم يستعدهما.');
 }else if(data.analyzer==='hashcrack-tcp'){
  steps.filter(function(s){return s.phase==='hash-recovery';}).forEach(function(s,i){
   add('قراءة التجزئة — المحاولة '+(i+1),'التجزئة: '+code(s.hash)+'<br>طولها '+esc(String(s.hash||'').length)+' خانة سداسية. الخوارزميات المرشحة: '+code((s.candidate_algorithms||[]).join(', '))+'. الطول يرشّح الخوارزمية ولا يثبتها.');
   add('مطابقة الكلمات محليًا',s.matched?'جرّب صقر كلمات من قائمته والكلمات المحلية المتاحة، وحسب تجزئة كل كلمة. وجد مطابقة باستخدام '+code(s.algorithm)+' بعد '+esc(s.attempts)+' محاولة.'+(s.plaintext!==undefined?'<br>الكلمة المستعادة: '+code(s.plaintext):''):'لم يجد صقر مطابقة ضمن حدود البحث. استعادة كلمة مرور ضعيفة تعتمد على وجود الكلمة في القائمة، وليست عكسًا رياضيًا للتجزئة.');
   if(s.sent===true)add('إرسال الإجابة ومتابعة الخدمة','أرسل صقر الكلمة المطابقة إلى الخدمة وانتظر الرد. الإرسال وحده لا يثبت قبول الإجابة؛ ظهور العلم في رد الخدمة هو دليل نجاح الجلسة.');
  });
  if(!steps.length)add('موضع التوقف','لم تُسجَّل محاولة استعادة تجزئة. '+esc((data.warnings||[]).join(' ')));
 }else if(data.analyzer==='numbers-ocr'){
  steps.filter(function(s){return s.phase==='image-ocr';}).forEach(function(s){
   add('قراءة الأرقام من الصورة','عزل صقر الرموز الداكنة عن الخلفية، وقارن أشكالها بقوالب أرقام وأقواس محلية. القارئ مخصص للأرقام المنفصلة الواضحة، وليس OCR عامًا لكل الصور.<br>القراءة: '+code(s.output));
  });
  steps.filter(function(s){return s.phase==='a1z26';}).forEach(function(s){
   add('تحويل الأعداد إلى حروف — A1Z26','كل عدد من 1 إلى 26 يحدد موضع الحرف: 1=A، 2=B، …، 26=Z. أبقى صقر الأقواس واستخدم الحروف الكبيرة.<br>'+code((s.mapping||[]).map(function(m){return m.number+'='+m.letter;}).join(' · ')));
   if(s.output)add('تجميع الحروف','قرأ الحروف بترتيب الأسطر من اليسار إلى اليمين: '+code(s.output));
  });
  if(!steps.length)add('موضع التوقف',esc((data.warnings||[]).join(' '))+' لم يستبدل صقر الرموز غير الواضحة بتخمين.');
 }else if(data.challenge==='Timestamped Secrets'||steps.some(function(s){return s.phase==='timestamp-input';})){
  steps.filter(function(s){return s.phase==='timestamp-input';}).forEach(function(s){
   add('الخطوة 1 — قراءة الرسالة','استخرج صقر وقت Unix التقريبي: '+code((s.centers||[]).join(', '))+'، وحوّل النص المشفر من Hex إلى '+esc(s.bytes)+' بايت.<br>النص المشفر: '+code(s.ciphertext_hex));
   add('الخطوة 2 — تحديد ضعف المفتاح','المفتاح مشتق من وقت قابل للتوقع. يجرب صقر الوقت المذكور أولًا، ثم الأوقات قبله وبعده ضمن ±'+esc(s.window_seconds)+' ثانية.');
  });
  steps.filter(function(s){return s.phase==='timestamp-decrypt';}).forEach(function(s){
   add('الخطوة 3 — اشتقاق المفتاح الناجح','حوّل الوقت إلى نص UTF-8، وحسب SHA-256 ثم أخذ أول 16 بايت: '+code(s.kdf)+'<br>الوقت الناجح: '+code(s.timestamp)+'؛ الفرق عن الوقت التقريبي: '+code(s.offset_seconds)+' ثانية؛ المحاولات: '+code(s.attempts)+'<br>المفتاح بصيغة Hex: '+code(s.key_hex));
   add('الخطوة 4 — فك AES والتحقق','فك صقر '+code(s.mode)+' بالمفتاح المستعاد، ثم تحقق من بايتات حشو PKCS#7 قبل إزالتها، ومن وجود صيغة علم معروفة.<br>الناتج: '+code(s.plaintext));
  });
  if(!steps.some(function(s){return s.phase==='timestamp-decrypt';}))add('موضع التوقف','لم يسجل المحلل فك تشفير ناجحًا. '+esc((data.explanation_ar||[]).join(' ')));
 }else if(steps.some(function(s){return s.phase==='text-decode';})){
  steps.filter(function(s){return s.phase==='text-decode';}).forEach(function(s,i){
   var why=s.operation==='Base64'||s.operation==='Base64url'?'فك صقر ترميز Base64 لاستعادة الطبقة التالية.':s.operation==='Python bytes literal'?'قرأ صقر القيمة داخل غلاف البايتات b&#39;…&#39; كبيانات، دون تشغيل كود.':/^Caesar shift /.test(s.operation)?'أعاد صقر كل حرف '+esc(s.operation.split(' ').pop())+' مواضع إلى الخلف، وأبقى الأرقام والرموز.':'طبّق صقر التحويل المسجل: '+code(s.operation);
   add('الخطوة '+(i+1)+' — '+s.operation,why+'<br>قبل: '+code(s.input)+'<br>بعد: '+code(s.output)+(s.truncated?'<br>عُرض جزء من النص الطويل فقط.':''));
  });
 }else return '';
 add('هل اكتمل الحل؟',data.success===true&&data.flag?'وجد صقر العلم في الناتج: '+code(data.flag)+'. قبول منصة التحدي للعلم يؤكد اكتمال الحل.':'لم يظهر علم مؤكد في هذه النتيجة؛ لا تعني استعادة كلمة أو فك رسالة عادية اكتمال التحدي.');
 return '<details open class="tech" style="margin-top:16px"><summary style="cursor:pointer;font-weight:bold;padding:12px">📚 كيف حلّ صقر التحدي؟</summary><div class="techBody"><p>الشرح التالي مبني على الأدلة المسجلة في هذه المحاولة.</p><ol>'+items.join('')+'</ol></div></details>';
}

async function run(text,files){
 if(busy)return false;
 busy=true;
 var out=document.getElementById('result'),button=document.getElementById('solve');
 if(!out){busy=false;return false;}
 var previous=button&&button.disabled;
 if(button)button.disabled=true;
 out.classList.remove('hidden');
 out.innerHTML='<h2>🔐 تحليل التشفير بالمحرك المحلي</h2><p>⏳ جارٍ قراءة القيم واختيار المحلل المناسب…</p>';
 var controller=typeof AbortController==='function'?new AbortController():null;
 var timer=controller?setTimeout(function(){controller.abort();},40000):null;
 try{
  var base=(location.port==='8765'&&(location.hostname==='127.0.0.1'||location.hostname==='localhost'))?location.origin:'http://127.0.0.1:8765';
  var health=await fetch(base+'/health',{cache:'no-store',signal:controller?controller.signal:undefined}).then(function(r){if(!r.ok)throw new Error('HTTP '+r.status);return r.json();});
  if(!health.rsa_tcp_weak_factors||!health.hashcrack_tcp)throw new Error('يلزم تشغيل محرك صقر 2.59.1 أو أحدث.');
  var payload={confirm:true,challenge_text:text},endpoint='/crypto/analyze';
  if(files&&files.length){
   if(!health.numeral_image_ocr)throw new Error('يلزم محرك 2.61.0 مع Pillow لقراءة أرقام الصورة.');
   payload.files=[];endpoint='/crypto/analyze-files';
   for(var f of files){
    if(f.size>8*1024*1024)throw new Error('الصورة أكبر من 8 ميغابايت.');
    var bytes=new Uint8Array(await f.arrayBuffer()),parts=[];
    for(var offset=0;offset<bytes.length;offset+=8192)parts.push(String.fromCharCode.apply(null,bytes.subarray(offset,offset+8192)));
    payload.files.push({name:f.name,data_b64:btoa(parts.join(''))});
   }
  }
  var response=await fetch(base+endpoint,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload),cache:'no-store',signal:controller?controller.signal:undefined});
  var data=await response.json();
  if(!response.ok)throw new Error(data.error||data.detail||('HTTP '+response.status));
  var solved=data.success===true&&typeof data.flag==='string'&&data.flag.length>0;
  out.innerHTML='<h2>'+(solved?'🚩 استخرج صقر العلم':'🔐 لم يُستخرج علم مؤكد')+'</h2><p>المحرك: '+esc(data.engine_version||health.version)+' · المحلل: '+esc(data.analyzer||'غير محدد')+'</p>'+(solved?'<div class="flag">'+esc(data.flag)+'</div>':'')+(data.explanation_ar||[]).map(function(t){return '<p>'+esc(t)+'</p>';}).join('')+(data.warnings||[]).map(function(t){return '<div class="finding warn">'+esc(t)+'</div>';}).join('')+solutionSteps(data)+'<details><summary>🔧 التفاصيل التقنية</summary><pre>'+esc(JSON.stringify(data,null,2))+'</pre></details>';
 }catch(error){out.innerHTML='<h2>⚠️ تعذر إكمال التحليل</h2><p>'+esc(error.message||error)+'</p><p>تأكد من تشغيل المحرك ومن صلاحية عنوان المثيل. لم يُطبّق ROT13 على وصف التحدي.</p>';}
 finally{if(timer)clearTimeout(timer);busy=false;if(button)button.disabled=previous;if(out.scrollIntoView)out.scrollIntoView({block:'start'});}
 return false;
}
global.FalconTcpCrypto={routePrompt:routePrompt,run:run,solutionSteps:solutionSteps};
})(window);
