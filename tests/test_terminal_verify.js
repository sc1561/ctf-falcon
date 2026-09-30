const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const source = fs.readFileSync('frontend/js/terminal-verify.js', 'utf8');

function run(challenge) {
  const input = { value: challenge };
  const result = { className: '', innerHTML: '', scrollIntoView() {} };
  const document = {
    getElementById(id) { return id === 'text' ? input : result; },
    querySelectorAll() { return []; }
  };
  const window = { FalconSmartRun() { return false; } };
  const context = { window, document, navigator: {}, setTimeout() {} };
  vm.runInNewContext(source, context);
  window.FalconTerminalVerifyRun();
  return result.innerHTML;
}

const withSsh = run('ssh -p 4567 ctf-player@rhea.picoctf.net Password: samplepass SHA-256: ' + 'a'.repeat(64));
assert.match(withSsh, /PowerShell/);
assert.match(withSsh, /Are you sure you want to continue connecting\?/);
assert.match(withSsh, /لن تظهر الأحرف أثناء الكتابة/);
assert.match(withSsh, /sha256sum files/);

const withoutSsh = run('SHA-256: ' + 'b'.repeat(64));
assert.match(withoutSsh, /ابحث عن أمر يبدأ بكلمة/);
assert.match(withoutSsh, /جهّز أمر الاتصال/);

console.log('terminal Verify student steps passed');
