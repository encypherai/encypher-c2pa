// Public-API surface lock for the published crates.
//
// This repository publishes a verification-only SDK. The failure this guards
// against is not "someone named a function `embed`" - it is "something became
// publicly callable and nobody noticed". A denylist of suspicious names cannot
// catch that: the manifest-production chain shipped for four releases through a
// five-symbol sweep because `embed_manifest` matched none of the five.
//
// So the rule is inverted. Every publicly reachable item is enumerated and
// compared against a checked-in inventory (`public-surface.txt`). Any addition
// fails until a human puts it in the inventory deliberately. Renaming defeats a
// denylist; it cannot defeat an inventory.
//
// Reachability is computed the way rustc computes it: start at each published
// crate's lib.rs and walk `pub mod` declarations only. An item inside a private
// module is not public API no matter how it is declared, and items behind
// `#[cfg(test)]` or `#[cfg(feature = "test-support")]` are not in the default
// build that consumers get.
//
//   node scripts/check-public-surface.mjs           # verify against inventory
//   node scripts/check-public-surface.mjs --write   # regenerate the inventory

import { readFile, writeFile, access } from "node:fs/promises";
import { resolve, dirname, join } from "node:path";

const root = resolve(import.meta.dirname, "..");
const inventoryPath = resolve(root, "public-surface.txt");

// Crates whose contents reach crates.io. Keep in sync with release.yml.
const PUBLISHED_CRATES = [
  ["encypher-c2pa-cbor", "internal/c2pa-cbor"],
  ["encypher-c2pa-core", "internal/c2pa-core"],
  ["encypher-c2pa-crypto", "internal/c2pa-crypto"],
  ["encypher-c2pa-formats", "internal/c2pa-formats"],
  ["encypher-c2pa-trust", "internal/c2pa-trust"],
  ["encypher-c2pa-validate", "internal/c2pa-validate"],
  ["encypher-c2pa", "crates/encypher-c2pa"],
  ["encypher-c2pa-cli", "crates/encypher-c2pa-cli"],
];

const ITEM = /^\s*pub(?:\s*\(\s*crate\s*\))?\s+(?:(?:async|unsafe|extern\s+"[^"]*"|const)\s+)*(fn|struct|enum|trait|type|const|static|union|mod)\s+([A-Za-z_][A-Za-z0-9_]*)/;
const PUB_CRATE = /^\s*pub\s*\(\s*crate\s*\)/;
const CFG_EXCLUDED = /^\s*#\[cfg(_attr)?\s*\(\s*(test|feature\s*=\s*"test-support")/;
const CFG_ANY_EXCLUDED = /^\s*#\[cfg\s*\(\s*any\s*\([^)]*\b(test|feature\s*=\s*"test-support")/;

async function exists(p) {
  try { await access(p); return true; } catch { return false; }
}

// Resolve `mod name;` to its file: name.rs or name/mod.rs, relative to the
// declaring file's directory (or its module subdirectory for non-root files).
async function resolveModule(fromFile, name, isRoot) {
  const dir = dirname(fromFile);
  const bases = isRoot || fromFile.endsWith("/mod.rs")
    ? [dir]
    : [join(dir, fromFile.split("/").pop().replace(/\.rs$/, "")), dir];
  for (const b of bases) {
    for (const cand of [join(b, `${name}.rs`), join(b, name, "mod.rs")]) {
      if (await exists(cand)) return cand;
    }
  }
  return null;
}

// Walk a file, collecting public items and recursing only into `pub mod`.
async function walk(file, prefix, isRoot, out, seen) {
  if (seen.has(file)) return;
  seen.add(file);
  const lines = (await readFile(file, "utf8")).split("\n");

  let excluded = false;   // pending cfg attribute applies to the next item
  let depth = 0;          // brace depth; we only take items at module level

  for (const raw of lines) {
    const line = raw.replace(/\/\/.*$/, "");

    if (CFG_EXCLUDED.test(raw) || CFG_ANY_EXCLUDED.test(raw)) { excluded = true; }

    const m = depth === 0 ? raw.match(ITEM) : null;
    if (m && !PUB_CRATE.test(raw)) {
      const [, kind, name] = m;
      if (kind === "mod") {
        if (!excluded) {
          const child = await resolveModule(file, name, isRoot);
          if (child) await walk(child, `${prefix}::${name}`, false, out, seen);
        }
      } else if (!excluded) {
        out.add(`${prefix}::${name} (${kind})`);
      }
    }

    // A line that declares any item consumes the pending cfg.
    if (m || /^\s*(pub\s|fn\s|struct\s|impl\s|enum\s)/.test(raw)) excluded = false;

    depth += (line.match(/\{/g) || []).length;
    depth -= (line.match(/\}/g) || []).length;
    if (depth < 0) depth = 0;
  }
}

const surface = new Set();
for (const [crateName, dir] of PUBLISHED_CRATES) {
  for (const entry of ["src/lib.rs", "src/main.rs"]) {
    const f = resolve(root, dir, entry);
    if (await exists(f)) await walk(f, crateName, true, surface, new Set());
  }
}

const current = [...surface].sort();

if (process.argv.includes("--write")) {
  const header = [
    "# Public API surface of the published crates - REVIEWED INVENTORY.",
    "#",
    "# Regenerate with: node scripts/check-public-surface.mjs --write",
    "#",
    "# Adding a line here is a deliberate decision to publish that item. This",
    "# repository ships a verification-only SDK: nothing here may construct a",
    "# C2PA manifest or write one into an asset container. Construction lives",
    "# behind the `test-support` feature, which no published dependency enables.",
    "",
  ].join("\n");
  await writeFile(inventoryPath, `${header}${current.join("\n")}\n`);
  console.log(`wrote ${current.length} entries to public-surface.txt`);
  process.exit(0);
}

if (!(await exists(inventoryPath))) {
  console.error("public-surface.txt is missing; run with --write to create it.");
  process.exit(1);
}

const approved = (await readFile(inventoryPath, "utf8"))
  .split("\n").map(l => l.trim()).filter(l => l && !l.startsWith("#"));

const added = current.filter(x => !approved.includes(x));
const removed = approved.filter(x => !current.includes(x));

if (added.length === 0 && removed.length === 0) {
  console.log(`PASS: public surface matches the reviewed inventory (${current.length} items).`);
  process.exit(0);
}

if (added.length) {
  console.error(`FAIL: ${added.length} item(s) became public without review:`);
  for (const a of added) console.error(`  + ${a}`);
  console.error("\nIf this is intended, confirm it cannot construct or embed a");
  console.error("C2PA manifest, then run: node scripts/check-public-surface.mjs --write");
}
if (removed.length) {
  console.error(`\n${removed.length} item(s) left the public surface (breaking change):`);
  for (const r of removed) console.error(`  - ${r}`);
  console.error("\nIntentional? Regenerate the inventory in the same commit.");
}
process.exit(1);
