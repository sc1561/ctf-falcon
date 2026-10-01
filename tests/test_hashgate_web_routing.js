const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

const source = fs.readFileSync(path.join(__dirname, '../frontend/js/web-sessions.js'), 'utf8');
const textarea = {value: ''};
function element(tag){return {tagName:tag,children:[],classList:{remove(){},add(){}},appendChild(x){this.children.push(x);},scrollIntoView(){},textContent:'',innerHTML:''};}
const result = element('section');
const document = {head:element('head'),createElement:element,getElementById(id) { return id === 'text' ? textarea : id === 'result' ? result : null; }};
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

textarea.value = `Can you reverse a series of Linux text transformations to recover the original flag?
Start searching for the flag here nc chatelaine.cylabacademy.net 40561
For text translation and character replacement, see
tr
command documentation
https://man7.org/linux/man-pages/man1/tr.1.html`;
assert.equal(window.FalconWebSessions.isUndoPrompt(textarea.value), true);
assert.equal(window.FalconWebSessions.undoTarget(textarea.value).host, 'chatelaine.cylabacademy.net');
assert.equal(window.FalconWebSessions.undoTarget(textarea.value).port, 40561);

(async function () {
  textarea.value = 'Hashgate\nWeb Exploitation\nThe URL is missing';
  await window.FalconWebSessionRun();
  assert.match(result.textContent, /تعرّف صقر على Hashgate/);
  assert.match(result.textContent, /لن يحلل وصف التحدي كـ ROT13/);
  textarea.value = 'Credential Stuffing\nWeb Exploitation\nhttps://challenge-files.cylabacademy.net/library/test/creds-dump.txt\nnc chatelaine.cylabacademy.net 34707';
  assert.equal(window.FalconWebSessions.isCredentialStuffingPrompt(textarea.value), true);
  await window.FalconWebSessionRun();
  assert.equal(result.children.length, 2, 'credential challenge should render artifact and TCP guidance, not HTTP results');
  const visible=JSON.stringify(result.children);
  assert.match(visible,/Credential Stuffing/);
  assert.match(visible,/chatelaine\.cylabacademy\.net:34707/);
  console.log('Hashgate and Credential Stuffing challenge routing tests passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
