"use strict";

const os = require("node:os");
const path = require("node:path");

const triples = {
  "win32-x64": "aegis_native.win32-x64-msvc.node",
  "linux-x64": "aegis_native.linux-x64-gnu.node",
  "darwin-x64": "aegis_native.darwin-x64.node",
  "darwin-arm64": "aegis_native.darwin-arm64.node"
};

const key = `${process.platform}-${process.arch}`;
const binaryName = triples[key];

if (!binaryName) {
  throw new Error(`Unsupported Aegis native platform: ${key}`);
}

module.exports = require(path.join(__dirname, binaryName));

