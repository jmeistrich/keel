// Needed for wasm_exec
globalThis.crypto = require("crypto");

const { wasm } = require("./dist/wasm.js");
require("./lib/wasm_exec");

async function keel() {
  if (globalThis.keel) {
    return globalThis.keel;
  }

  const go = new globalThis.Go();

  const wasmModule = await WebAssembly.instantiate(wasm, go.importObject);
  go.run(wasmModule.instance);

  return globalThis.keel;
}

async function format() {
  const api = await keel();
  return api.format(...arguments);
}

async function validate() {
  const api = await keel();
  return api.validate(...arguments);
}

async function completions() {
  const api = await keel();
  return api.completions(...arguments);
}

module.exports = {
  format,
  validate,
  completions,
};
