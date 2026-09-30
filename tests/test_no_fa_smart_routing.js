const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

const source = fs.readFileSync(path.join(__dirname, '../frontend/js/mobile-fallback.js'), 'utf8');

function analyze(text) {
  const result = {innerHTML: '', className: '', addedCards: [], scrollIntoView() {}, prepend(card) { this.addedCards.push(card); }};
  const textarea = {value: text};
  const fileInput = {files: []};
  const document = {getElementById(id) { return id === 'text' ? textarea : id === 'file' ? fileInput : id === 'result' ? result : null; }};
  const window = {FalconWebSessions: {renderArtifactGuidance() { return {artifactGuidance: true}; }}};
  vm.runInNewContext(source, {window, document, setTimeout(fn) { fn(); }, console});
  window.FalconSmartRun();
  return result;
}

const noFa = `No FA\nWeb Exploitation Medium\nby Darkraicg492 picoCTF 2026\nSeems like some data has been leaked! Can you get the flag?\nYou can get started here: http://xebec.cylabacademy.net:29016/\nApplication code: https://challenge-files.cylabacademy.net/library/app.py\nLeaked data: https://challenge-files.cylabacademy.net/library/users.db`;
const noFaResult = analyze(noFa);
assert.match(noFaResult.innerHTML, /No FA/);
assert.match(noFaResult.innerHTML, /app\.py/);
assert.match(noFaResult.innerHTML, /users\.db/);
assert.match(noFaResult.innerHTML, /C:\\Falcon\\analysis/);
assert.doesNotMatch(noFaResult.innerHTML, /درجة|أفضل مسارات التحليل/);
assert.equal(noFaResult.addedCards.length, 1, 'artifact guidance remains available for the challenge');

const cryptoResult = analyze('Jro Rkcybvgngvba Zrqvhz');
assert.match(cryptoResult.innerHTML, /ROT13/);
