"""Local-only model of the n0s4n1ty 1 upload challenge."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import urlsplit, parse_qs

FLAG = "academy{mock_n0s4n1ty_flag_only}"

class Handler(BaseHTTPRequestHandler):
    fail_upload = False
    no_sudo = False
    kaspersky_block = False
    def log_message(self, *args): pass
    def _send(self, body, status=200):
        data=body.encode(); self.send_response(status); self.send_header("Content-Type","text/html; charset=utf-8")
        self.send_header("Content-Length",str(len(data))); self.end_headers(); self.wfile.write(data)
    def do_GET(self):
        path=urlsplit(self.path)
        if path.path == "/":
            return self._send('<h1>Profile picture upload</h1><form method="POST" action="/index.php" enctype="multipart/form-data"><input type="file" name="file"><button>Upload</button></form>')
        if path.path == "/index.php":
            return self._send("<form method='POST' enctype='multipart/form-data'><input type='file' name='file'></form>")
        if path.path == "/uploads/falcon_cmd.php":
            cmd=parse_qs(path.query).get("cmd",[""])[0]
            if cmd == "whoami": return self._send("www-data")
            if cmd == "sudo -l":
                return self._send("User www-data may run the following commands on host:\n (ALL) NOPASSWD: ALL") if not self.no_sudo else self._send("Sorry, user www-data may not run sudo")
            if cmd == "sudo cat /root/flag.txt": return self._send(FLAG)
            return self._send("")
        return self._send("not found",404)
    def do_POST(self):
        size=int(self.headers.get("Content-Length",0)); data=self.rfile.read(size)
        assert "multipart/form-data" in self.headers.get("Content-Type","")
        assert b'name="file"; filename="falcon_cmd.php"' in data
        assert b"system($_GET['cmd'])" in data
        if self.kaspersky_block:
            return self._send('<!DOCTYPE html><html><head><title>Kaspersky Endpoint Security for Windows</title></head><body>Request has been forbidden by antivirus</body></html>',499)
        if self.fail_upload: return self._send("Sorry, there was an error uploading your file.")
        return self._send("The file falcon_cmd.php has been uploaded Path: uploads/falcon_cmd.php")

def start_server(fail_upload=False,no_sudo=False,kaspersky_block=False):
    Handler.fail_upload=fail_upload; Handler.no_sudo=no_sudo; Handler.kaspersky_block=kaspersky_block
    server=ThreadingHTTPServer(("127.0.0.1",0),Handler)
    Thread(target=server.serve_forever,daemon=True).start()
    return server,f"http://127.0.0.1:{server.server_port}/"
