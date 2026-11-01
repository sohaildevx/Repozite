"use strict";

const fs = require("fs");
const espree = require("espree");

const files = process.argv.slice(2);
const out = [];

const BASE_OPTIONS = {
  ecmaVersion: 2022,
  ecmaFeatures: { jsx: true },
};

for (const file of files) {
  let src;
  try {
    src = fs.readFileSync(file, "utf8");
  } catch (err) {
    out.push({ path: file, ok: false, line: 1, message: "File could not be read." });
    continue;
  }

  let ok = false;
  let firstError = null;
  for (const sourceType of ["module", "script"]) {
    try {
      espree.parse(src, { ...BASE_OPTIONS, sourceType });
      ok = true;
      break;
    } catch (err) {
      if (!firstError) firstError = err;
    }
  }

  if (ok) {
    out.push({ path: file, ok: true, line: 1, message: "" });
  } else {
    out.push({
      path: file,
      ok: false,
      line: (firstError && firstError.lineNumber) || 1,
      message: String((firstError && firstError.message) || "Syntax error").slice(0, 500),
    });
  }
}
process.stdout.write(JSON.stringify(out));
