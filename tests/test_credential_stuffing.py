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
            def connector(address, timeout):
                assert address == ("chatelaine.cylabacademy.net", 34707)
                return socket.create_connection(mock.address, timeout)
            progress = []
            result = cs.solve(path, "chatelaine.cylabacademy.net", 34707, connector=connector,
                              delay=0, progress=lambda attempts, entries: progress.append((attempts, entries)))
            assert result["success"] and result["flag"] == FLAG, result
            assert result["attempts"] == 2 and result["malformed"] == 1
            assert progress[0] == (0, 2) and progress[-1] == (2, 2)
            assert result["username"] == "valid" and "password" not in result
            assert cs.parse_target("Credential Stuffing\nnc chatelaine.cylabacademy.net 34707") == ("chatelaine.cylabacademy.net", 34707)
            assert cs.parse_target("Credential Stuffing\nnc evil.example 34707") is None
    finally:
        mock.close()
    print("Credential Stuffing bounded TCP solver test passed")


def test_parallelism_is_capped_and_progress_counts_batches():
    import time
    mock = MockService()
    try:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "creds-dump.txt"
            path.write_text("wrong1;pair\nwrong2;pair\nwrong3;pair\nwrong4;pair\n", encoding="utf-8")
            progress = []
            def connector(address, timeout):
                return socket.create_connection(mock.address, timeout)
            result = cs.solve(path, "chatelaine.cylabacademy.net", 34707,
                              connector=connector, delay=0, parallelism=99,
                              progress=lambda attempts, total: progress.append((attempts, total)))
            assert not result["success"] and result["attempts"] == 4
            assert progress[0] == (0, 4) and progress[-1] == (4, 4)
            assert cs.MAX_PARALLEL == 3
    finally:
        mock.close()


if __name__ == "__main__":
    main()
    test_parallelism_is_capped_and_progress_counts_batches()
