import { copyFile, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const pkgDir = resolve(root, "bindings/wasm/pkg");
const packagePath = resolve(pkgDir, "package.json");
const pkg = JSON.parse(await readFile(packagePath, "utf8"));

Object.assign(pkg, {
  name: "@encypherai/c2pa",
  description: "Offline, verification-only C2PA + CAWG SDK for browsers",
  license: "Apache-2.0",
  repository: {
    type: "git",
    url: "git+https://github.com/encypherai/encypher-c2pa.git",
    directory: "bindings/wasm",
  },
  homepage: "https://github.com/encypherai/encypher-c2pa#readme",
  bugs: "https://github.com/encypherai/encypher-c2pa/issues",
  keywords: ["c2pa", "content-credentials", "provenance", "wasm", "verification"],
  exports: {
    ".": {
      types: "./encypher_c2pa_wasm.d.ts",
      import: "./encypher_c2pa_wasm.js",
    },
  },
});
pkg.files = [...new Set([...pkg.files, "LICENSE", "NOTICE", "README.md"])];

await writeFile(packagePath, `${JSON.stringify(pkg, null, 2)}\n`);
await copyFile(resolve(root, "LICENSE"), resolve(pkgDir, "LICENSE"));
await copyFile(resolve(root, "NOTICE"), resolve(pkgDir, "NOTICE"));
await copyFile(resolve(root, "README.md"), resolve(pkgDir, "README.md"));
