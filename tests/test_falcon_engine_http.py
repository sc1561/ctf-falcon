import sys,importlib.util,threading,json,urllib.request,http.client
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
 health=json.load(urllib.request.urlopen(url+'/health'));assert health['version']=='2.8.0'
 req=urllib.request.Request(url+'/web/session-audit',data=json.dumps({'url':'http://mock.cylabacademy.net:12345/login'}).encode(),headers={'Content-Type':'application/json'})
 with patch.object(w.http.client,'HTTPConnection',LocalConnection):
  with urllib.request.urlopen(req) as r:
   data=json.load(r);assert r.headers['Access-Control-Allow-Origin']=='https://sc1561.github.io'
 assert data['success'] and data['flag']==mock.FLAG and data['ok'];assert data['target'].endswith(':12345/');assert len(data['steps'])==8
 c=w.analyze_set_cookie('s=x; Max-Age=3600; Expires=Thu, 01 Jan 1970 00:00:00 GMT');assert c['intent']=='set'
 client=w.HttpClient();client.origin=('http','one',80)
 try:client.request('GET','http://two/')
 except ValueError:pass
 else:raise AssertionError('cross-origin')

 print('PASS: HTTP endpoint, CORS, health, /login normalization, eight steps, actual mock flag, cookie precedence, origin guard')
finally:engine_server.shutdown();server.shutdown()
