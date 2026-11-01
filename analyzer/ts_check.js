"use strict";

const ts = require("typescript");
const path = require("path");

const args = process.argv.slice(2);

const syntaxOnly = args.includes("--syntax-only");
const inputs = args.filter((a) => !a.startsWith("--"));
if (inputs.length === 0) {
  process.stdout.write("[]");
  process.exit(0);
}

const prelude = path.join(__dirname, "ts_prelude.d.ts");
const files = [prelude, ...inputs];

const options = {
  noEmit: true,
  skipLibCheck: true,
  target: ts.ScriptTarget.ESNext,
  module: ts.ModuleKind.ESNext,
  moduleResolution: ts.ModuleResolutionKind.Bundler,
  jsx: ts.JsxEmit.Preserve,
  esModuleInterop: true,
  allowJs: false,
};

const IGNORED_CODES = new Set([
  2307, 
  2688, 
  7016, 
]);

let diagnostics;
let syntacticSet;
try {
  const program = ts.createProgram(files, options);
  
  syntacticSet = new Set(program.getSyntacticDiagnostics());
  diagnostics = syntaxOnly
    ? [...syntacticSet]
    : ts.getPreEmitDiagnostics(program);
} catch (err) {
  
  process.stdout.write(JSON.stringify([
    { file: "", line: 1, col: 1, code: 5000, kind: "type",
      text: "TypeScript compiler failed." },
  ]));
  process.exit(0);
}

const out = [];
for (const d of diagnostics) {
  if (IGNORED_CODES.has(d.code)) continue;
  let file = "";
  let line = 1;
  let col = 1;
  if (d.file && typeof d.start === "number") {
    file = d.file.fileName;
    const pos = d.file.getLineAndCharacterOfPosition(d.start);
    line = pos.line + 1;
    col = pos.character + 1;
  }
  out.push({
    file,
    line,
    col,
    code: d.code,
    kind: syntacticSet && syntacticSet.has(d) ? "syntax" : "type",
    text: ts.flattenDiagnosticMessageText(d.messageText, " ").slice(0, 500),
  });
}
process.stdout.write(JSON.stringify(out));
