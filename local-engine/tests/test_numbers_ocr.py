import sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import crypto_analysis as ca
import numbers_ocr as n
from PIL import Image,ImageFont,ImageDraw
class NumberOCRTests(unittest.TestCase):
 def test_supplied_image(self):
  source=Path(__file__).resolve().parents[3]/'upload'/'the_numbers.png'
  if not source.exists():self.skipTest('user fixture not bundled')
  for description in ('## The Numbers\nCryptographyEasy',''):
   r=ca.analyze(description,source.parent)
   self.assertTrue(r['success'],r);self.assertEqual(r['flag'],'PICOCTF{THENUMBERSMASON}')
   self.assertIn('16 9 3 15 3 20 6',r['steps'][0]['output'])
 def test_tokens_and_invalid_values(self):
  self.assertEqual(n.decode_tokens('16 9 3 15 3 20 6 { 20 5 19 20 }')[0],'PICOCTF{TEST}')
  self.assertIsNone(n.decode_tokens('16 9 3 15 3 20 6 { 27 }')[0])
  self.assertIsNone(n.decode_tokens('16 9 3 15 3 20 6 { error }')[0])
 def test_generated_different_image(self):
  fontpath='/usr/share/fonts/truetype/dejavu/DejaVuSerif.ttf'
  if not Path(fontpath).exists():self.skipTest('test font unavailable')
  font=ImageFont.truetype(fontpath,52)
  with tempfile.TemporaryDirectory() as root:
   im=Image.new('RGB',(1000,150),'white')
   ImageDraw.Draw(im).text((20,20),'16 9 3 15 3 20 6 { 20 5 19 20 }',font=font,fill='black')
   path=Path(root,'unrelated-name.png');im.save(path)
   r=ca.analyze('',root)
   self.assertTrue(r['success'],r);self.assertEqual(r['flag'],'PICOCTF{TEST}')
 def test_blank_image_no_false_flag(self):
  with tempfile.TemporaryDirectory() as root:
   path=Path(root,'blank.png');Image.new('RGB',(200,100),'white').save(path)
   self.assertFalse(n.analyze_image(path)['success'])
