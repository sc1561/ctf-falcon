import sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent/'local-engine'));sys.path.insert(0,str(HERE))
import web_session_audit as w
import mock_ssti1 as mock
server,base=mock.start_server()
try:
 result=w.run_audit(base)
 assert result['challenge']=='SSTI1' and result['analyzer']=='ssti1' and result['recognized']
 assert result['success'] and result['flag']==mock.FLAG, result
 assert len(result['steps'])==3 and result['discovered']['ssti_confirmed'] is True
 print('PASS: form detection, arithmetic confirmation, mock flag extraction')
finally: server.shutdown()

# The real target redirects POST / to POST /announce with status 307.
redirect_server,redirect_base=mock.start_redirect_server()
try:
 redirected=w.run_audit(redirect_base)
 assert redirected['success'] and redirected['flag']==mock.FLAG, redirected
 assert any(x['status']==307 and x['location']=='/announce' for x in redirected['steps'])
 assert [x['method'] for x in redirected['steps']]==['GET','POST','POST','POST','POST']
 print('PASS: same-origin 307 preserves POST and reaches /announce for both probe and flag')
finally: redirect_server.shutdown()

# Ordinary non-announcement POST forms must not trigger the SSTI analyzer.
plain={"html":"<form method=\"POST\"><input name=\"content\"></form>","forms":[{"method":"POST","action":"/","fields":["content"]}]}
assert w.detect_ssti1(plain) is None
print('PASS: generic POST forms do not trigger SSTI mode')
