const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

class FakeElement {
  constructor(tag) { this.tagName = tag; this.children = []; this._text = ""; }
  set textContent(value) { this._text = String(value); }
  get textContent() { return this._text + this.children.map((child) => child.textContent).join(""); }
  appendChild(child) { this.children.push(child); return child; }
}
const window = {};
const document = {getElementById: () => null, createElement: (tag) => new FakeElement(tag)};
vm.runInNewContext(fs.readFileSync("frontend/js/web-sessions.js", "utf8"), {
  window,
  document,
  URL,
  console
});

const extract = window.FalconWebSessions.challengeArtifacts;
const local = (value) => JSON.parse(JSON.stringify(value));
const challenge = `## No FA
Instance: http://xebec.cylabacademy.net:17332/
Database: [users.db](https://challenge-files.cylabacademy.net/library/abc/users.db)
Source: https://challenge-files.cylabacademy.net/library/abc/app.py`;
assert.deepEqual(
  local(extract(challenge)),
  [
    {name: "users.db", url: "https://challenge-files.cylabacademy.net/library/abc/users.db"},
    {name: "app.py", url: "https://challenge-files.cylabacademy.net/library/abc/app.py"}
  ]
);

assert.deepEqual(local(extract("## GET aHEAD\nhttp://chatelaine.cylabacademy.net:27372/")), []);
assert.deepEqual(
  local(extract("[capture.pcap](https://example.org/files/capture.pcap)")),
  [{name: "capture.pcap", url: "https://example.org/files/capture.pcap"}]
);

const pastedNoFa = `No FA
Web Exploitation Medium
The application code can be found here.
The leaked data can be found here.`;
assert.deepEqual(
  local(extract(pastedNoFa)),
  [
    {name: "app.py", url: null},
    {name: "users.db", url: null}
  ]
);
const pagesSource = fs.readFileSync("frontend/js/pages.js", "utf8");
const detectTypeSource = pagesSource.match(/function detectType\(name,raw,ext\)\{[^\n]+\}/)[0];
const detectType = vm.runInNewContext("(" + detectTypeSource + ")");
assert.equal(detectType("challenge", pastedNoFa, ""), "NO FA");
const guidance = window.FalconWebSessions.renderArtifactGuidance(pastedNoFa);
assert.match(guidance.textContent, /C:\\Falcon\\analysis/);
assert.match(guidance.textContent, /app\.py/);
assert.match(guidance.textContent, /users\.db/);
console.log("web-session artifact guidance tests passed");
