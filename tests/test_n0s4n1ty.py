import sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
sys.path[:0]=[str(HERE.parent/'local-engine'),str(HERE)]
import web_session_audit as w
import mock_n0s4n1ty as mock

def run_case(**kwargs):
    server,base=mock.start_server(**kwargs)
    try: return w.run_audit(base)
    finally: server.shutdown()

ok=run_case()
assert ok['challenge']=='n0s4n1ty 1' and ok['analyzer']=='n0s4n1ty-1',ok
assert ok['success'] and ok['flag']==mock.FLAG,ok
assert [step['method'] for step in ok['steps']]==['GET','POST','GET','GET','GET']
assert ok['discovered']['file_field']=='file' and ok['discovered']['sudo_nopasswd']
print('PASS: detected multipart file form, uploaded PHP, verified whoami/sudo, extracted mock flag')

failed=run_case(fail_upload=True)
assert not failed['success'] and len(failed['steps'])==2,failed
assert 'Sorry, there was an error uploading your file.' in failed['warnings'][0]
print('PASS: upload rejection is reported verbatim and halts before command execution')

blocked=run_case(kaspersky_block=True)
assert not blocked['success'] and len(blocked['steps'])==2,blocked
assert blocked['discovered']['upload_blocked_by_security']=='Kaspersky Endpoint Security'
assert 'لا تغيّر الحمولة لتجاوز الحماية' in blocked['warnings'][0]
print('PASS: Kaspersky HTTP 499 is identified as a local security block, not target rejection')

no_sudo=run_case(no_sudo=True)
assert not no_sudo['success'] and len(no_sudo['steps'])==4,no_sudo
assert not no_sudo['discovered']['sudo_nopasswd']
print('PASS: no /root read is attempted unless sudo -l confirms NOPASSWD')

form=w.find_forms('<form method="POST" enctype="multipart/form-data"><input type="file" name="avatar"></form>')[0]
assert form['file_fields']==['avatar'] and form['enctype']=='multipart/form-data'
assert w.detect_n0s4n1ty({'html':'<h1>Upload</h1>','forms':[form]}) is not None
print('PASS: multipart file input and field-name extraction')
