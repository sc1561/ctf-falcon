import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import crypto_analysis as ca


class CryptoAnalysisTests(unittest.TestCase):
    def test_inline_rot13(self):
        with tempfile.TemporaryDirectory() as tmp:
            result=ca.analyze("## 13\nCryptographyEasy `npnqrzl{abg_gbb_onq_bs_n_ceboyrz}`",Path(tmp))
        self.assertTrue(result["success"])
        self.assertEqual(result["flag"],"academy{not_too_bad_of_a_problem}")

    def test_rotation_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp,"encrypted.txt").write_text("picoCTF{r0tat1on_d3crypt3d_949af1a1}")
            result=ca.analyze("## rotation\nCryptographyEasy",Path(tmp))
        self.assertTrue(result["success"])
        self.assertEqual(result["flag"],"picoCTF{r0tat1on_d3crypt3d_949af1a1}")

    def test_shared_secret_recovery(self):
        p,A,b=23,8,3
        key=pow(A,b,p)&255
        flag=b"picoCTF{shared_secret_test}"
        enc=bytes(x^key for x in flag).hex()
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp,"message.txt").write_text(f"p = {p}\nA = {A}\nb = {b}\nenc = {enc}\n")
            Path(tmp,"encryption.py").write_text("# reference only")
            result=ca.analyze("## Shared Secrets\nCryptographyEasy",Path(tmp))
        self.assertTrue(result["success"],result)
        self.assertEqual(result["flag"],flag.decode())

    def test_c3_decodes_tables_and_cube_indices_without_execution(self):
        l1='\n \"#()*+/1:=[]abcdefghijklmnopqrstuvwxyz'
        l2='ABCDEFGHIJKLMNOPQRSTabcdefghijklmnopqrst'
        # The second stage's self-sampling positions yield a recognizable inner token.
        stage="".join(chr(65+(i%26)) for i in range(100))
        target={1:'t',8:'e',27:'s',64:'t'}
        chars=list(stage)
        for i,ch in target.items():chars[i]=ch
        stage=''.join(chars)
        prev=0;cipher=[]
        for ch in stage:
            cur=l1.index(ch) if ch in l1 else l1.index(' ')
            cipher.append(l2[(cur-prev)%40]);prev=cur
        src=f"lookup1 = {l1!r}\nlookup2 = {l2!r}\n"
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp,"convert.py").write_text(src)
            Path(tmp,"ciphertext").write_text(''.join(cipher))
            result=ca.analyze("## C3\nCryptographyMedium",Path(tmp))
        self.assertTrue(result["success"],result)
        self.assertEqual(result["flag"],"academy{test}")

    def test_missing_files_are_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            result=ca.analyze("## cryptomaze\nCryptographyMedium",Path(tmp))
        self.assertEqual(result["missing_files"],["output.txt"])
        self.assertTrue(result["warnings"])


if __name__=="__main__":unittest.main()
