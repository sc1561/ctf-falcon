const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

const source = fs.readFileSync(path.join(__dirname, '../frontend/js/web-sessions.js'), 'utf8');
const textarea = {value: ''};
const result = {classList: {remove() {}}, textContent: ''};
const document = {getElementById(id) { return id === 'text' ? textarea : id === 'result' ? result : null; }};
const window = {};
vm.runInNewContext(source, {window, document, URL, fetch() { throw new Error('fetch should not run in this extraction test'); }, console});

textarea.value = 'Hashgate\nWeb Exploitation\nhttp\\://xebec.cylabacademy.net:29063/';
assert.equal(window.FalconWebSessions.challengeUrl(), 'http://xebec.cylabacademy.net:29063/');
assert.equal(window.FalconWebSessions.isHashgatePrompt(textarea.value), true);

textarea.value = 'Hashgate\nWeb Exploitation\nThe URL is missing';
assert.equal(window.FalconWebSessions.challengeUrl(), null);
assert.equal(window.FalconWebSessions.isHashgatePrompt(textarea.value), true);

textarea.value = 'Jro Rkcybvgngvba Zrqvhz';
assert.equal(window.FalconWebSessions.isHashgatePrompt(textarea.value), false);

(async function () {
  textarea.value = 'Hashgate\nWeb Exploitation\nThe URL is missing';
  await window.FalconWebSessionRun();
  assert.match(result.textContent, /تعرّف صقر على Hashgate/);
  assert.match(result.textContent, /لن يحلل وصف التحدي كـ ROT13/);
  console.log('Hashgate challenge routing tests passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
