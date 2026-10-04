import sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import crypto_analysis as ca
PAYLOAD=b"YidhR3BvYTJ4MFpudHFhR3g2YUhsZmF6TnFlVGwzWVROclh6azVORGhyYldneWZRPT0nCg=="
class LayeredTests(unittest.TestCase):
 def test_actual_file_with_and_without_description(self):
  with tempfile.TemporaryDirectory() as root:
   Path(root,'enc_flag').write_bytes(PAYLOAD)
   for text in ('## interencdec\nCryptographyEasy',''):
    result=ca.analyze(text,root)
    self.assertTrue(result['success'],result)
    self.assertEqual(result['flag'],'academy{caesar_d3cr9pt3d_9948dfa2}')
    steps=[s for s in result['steps'] if s['phase']=='text-decode']
    self.assertEqual([s['operation'] for s in steps],['Base64','Python bytes literal','Base64','Caesar shift 7'])
    for a,b in zip(steps,steps[1:]):self.assertEqual(a['output'],b['input'])
 def test_literal_expression_is_not_evaluated(self):
  flag,steps=ca._decode_text_path(b"b'abc' + bytes([65])")
  self.assertIsNone(flag)
  self.assertFalse(any(s['operation']=='Python bytes literal' for s in steps))
 def test_unrelated_input_is_not_success(self):
  self.assertIsNone(ca._text_decodes(b'ordinary words without a flag')[0])
