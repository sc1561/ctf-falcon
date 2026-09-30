import socket
import sys
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "local-engine"))
import credential_stuffing as cs

FLAG = "picoCTF{mock_tcp_login_success}"


class MockService:
    def __init__(self):
        self.server = socket.socket()
        self.server.bind(("127.0.0.1", 0))
        self.server.listen()
        self.address = self.server.getsockname()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        while True:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            with conn:
                conn.sendall(b"Welcome\nUsername:")
                user = conn.makefile("rb").readline().strip()
                conn.sendall(b"Password:")
                password = conn.makefile("rb").readline().strip()
                if user == b"valid" and password == b"pair":
                    conn.sendall((FLAG + "\n").encode())
                else:
                    conn.sendall(b"Invalid username or password\n")

    def close(self):
        self.server.close()
        self.thread.join(timeout=1)


def main():
    mock = MockService()
    try:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "creds-dump.txt"
            path.write_text("wrong;pair\nvalid;pair\nbad-line\n", encoding="utf-8")
            connector = lambda _address, timeout: socket.create_connection(mock.address, timeout)
            result = cs.solve(path, connector=connector, delay=0)
            assert result["success"] and result["flag"] == FLAG, result
            assert result["attempts"] == 2 and result["malformed"] == 1
            assert result["username"] == "valid" and "password" not in result
            assert cs.TARGET_HOST == "xebec.cylabacademy.net" and cs.TARGET_PORT == 12360
    finally:
        mock.close()
    print("Credential Stuffing bounded TCP solver test passed")


if __name__ == "__main__":
    main()
