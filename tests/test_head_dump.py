import sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
sys.path[:0]=[str(HERE.parent/'local-engine'),str(HERE)]
import web_session_audit as w
import mock_head_dump as mock

server,base=mock.start_server()
try:
    result=w.run_audit(base)
    assert result['challenge']=='head-dump' and result['analyzer']=='head-dump',result
    assert result['recognized'] and result['success'] and result['flag']==mock.FLAG,result
    assert result['discovered']['heapdump_path']=='/heapdump'
    assert result['discovered']['heapdump_bytes']>w.MAX_BODY,result['discovered']
    assert result['discovered']['artifact_filename']=='heapdump.heapsnapshot'
    assert any(s['status']==301 and s['location']=='/api-docs/' for s in result['steps'])
    assert [s['method'] for s in result['steps']]==['GET','GET','GET','GET','GET']
    print('PASS: followed observed same-origin docs redirect, read Swagger route, retrieved >2MiB dump, extracted flag')
finally:server.shutdown()

plain={'html':'<h1>API Documentation</h1><p>ordinary page</p>','forms':[]}
assert w.detect_head_dump(plain) is None
print('PASS: API docs title without a linked docs endpoint does not trigger head-dump')
