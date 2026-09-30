const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const window = {};
const document = {getElementById: () => null};
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
console.log("web-session artifact guidance tests passed");
