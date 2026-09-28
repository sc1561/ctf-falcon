from flask import Flask, request, jsonify, send_from_directory
from pathlib import Path
import sys, tempfile
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from engines.auto_triage import analyze
app=Flask(__name__, static_folder=str(ROOT/'frontend'), static_url_path='')
@app.get('/')
def home(): return send_from_directory(ROOT/'frontend','index.html')
@app.post('/api/analyze')
def api_analyze():
    if 'file' in request.files and request.files['file'].filename:
        f=request.files['file']
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/Path(f.filename).name; f.save(p)
            return jsonify(analyze(path=p))
    data=request.get_json(silent=True) or {}
    return jsonify(analyze(text=data.get('text','')))
if __name__=='__main__': app.run(host='127.0.0.1',port=8000,debug=False)
