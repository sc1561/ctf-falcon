import sys,importlib.util,threading,json,urllib.request,urllib.error,http.client
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parent.parent
sys.path[:0]=[str(ROOT/'local-engine'),str(ROOT/'tests')]
import web_session_audit as w, mock_old_sessions as mock
spec=importlib.util.spec_from_file_location('falcon', str(ROOT/'local-engine/falcon_local.py'));engine=importlib.util.module_from_spec(spec);spec.loader.exec_module(engine)
server,base=mock.start_server();target_port=int(base.rstrip('/').rsplit(':',1)[1]);real=http.client.HTTPConnection
class LocalConnection(real):
 def __init__(self,host,port=None,**kw):super().__init__('127.0.0.1' if host=='mock.cylabacademy.net' else host,target_port if host=='mock.cylabacademy.net' else port,**kw)
engine_server=engine.ThreadingHTTPServer(('127.0.0.1',0),engine.H);threading.Thread(target=engine_server.serve_forever,daemon=True).start();url='http://127.0.0.1:'+str(engine_server.server_port)
try:
 health=json.load(urllib.request.urlopen(url+'/health'));assert health['version']=='2.26.0'
 artifact_req=urllib.request.Request(url+'/artifacts/analyze',data=b'picoCTF{local_artifact_scan}',headers={'Content-Type':'application/octet-stream','X-Filename':'sample.txt'})
 with urllib.request.urlopen(artifact_req) as r:
  artifact=json.load(r);assert artifact['ok'] and artifact['flags'][0]['flag']=='picoCTF{local_artifact_scan}'
  assert r.headers['Access-Control-Allow-Origin']=='https://sc1561.github.io'
 req=urllib.request.Request(url+'/web/session-audit',data=json.dumps({'url':'http://mock.cylabacademy.net:12345/login'}).encode(),headers={'Content-Type':'application/json'})
 with patch.object(w.http.client,'HTTPConnection',LocalConnection):
  with urllib.request.urlopen(req) as r:
   data=json.load(r);assert r.headers['Access-Control-Allow-Origin']=='https://sc1561.github.io'
 assert data['success'] and data['flag']==mock.FLAG and data['ok'];assert data['target'].endswith(':12345/');assert len(data['steps'])==8
 tcp_req=urllib.request.Request(url+'/web/session-audit',data=json.dumps({'url':'https://challenge-files.cylabacademy.net/library/test/creds-dump.txt','challenge_text':'Credential Stuffing\nWeb Exploitation\ncreds-dump.txt\nnc chatelaine.cylabacademy.net 34707'}).encode(),headers={'Content-Type':'application/json'})
 with urllib.request.urlopen(tcp_req) as r:
  tcp=json.load(r);assert tcp['analyzer']=='credential-stuffing' and tcp['steps']==[]
 assert tcp['target']=='TCP chatelaine.cylabacademy.net:34707' and not tcp['success']
 undo_req=urllib.request.Request(url+'/web/session-audit',data=json.dumps({'url':'','challenge_text':'Undo\npicoCTF\nnc chatelaine.cylabacademy.net 41550'}).encode(),headers={'Content-Type':'application/json'})
 with urllib.request.urlopen(undo_req) as r:
  undo=json.load(r);assert undo['analyzer']=='undo' and undo['discovered']['protocol']=='TCP'
 undo_body=urllib.request.Request(url+'/undo/analyze',data=json.dumps({'challenge_text':'Undo\npicoCTF','transcript':'ROT13 then rev'}).encode(),headers={'Content-Type':'application/json'})
 with urllib.request.urlopen(undo_body) as r:
  undo_result=json.load(r);assert [s['operation'] for s in undo_result['inverse_steps']]==['rev','rot13']
 no_confirm=urllib.request.Request(url+'/credential-stuffing/solve',data=json.dumps({'confirm':False}).encode(),headers={'Content-Type':'application/json'})
 try:urllib.request.urlopen(no_confirm)
 except urllib.error.HTTPError as e:assert e.code==400
 else:raise AssertionError('credential attempt started without confirmation')
 invalid_target=urllib.request.Request(url+'/credential-stuffing/solve',data=json.dumps({'confirm':True,'challenge_text':'Credential Stuffing\nnc example.net 22'}).encode(),headers={'Content-Type':'application/json'})
 try:urllib.request.urlopen(invalid_target)
 except urllib.error.HTTPError as e:assert e.code==400
 else:raise AssertionError('credential solver accepted a non-Cylab host')
 c=w.analyze_set_cookie('s=x; Max-Age=3600; Expires=Thu, 01 Jan 1970 00:00:00 GMT');assert c['intent']=='set'
 client=w.HttpClient();client.origin=('http','one',80)
 try:client.request('GET','http://two/')
 except ValueError:pass
 else:raise AssertionError('cross-origin')

 print('PASS: HTTP endpoint, CORS, health, Hashgate route, TCP-only credential challenge route, actual mock flag, cookie precedence, origin guard')
finally:engine_server.shutdown();server.shutdown()
