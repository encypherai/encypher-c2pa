// Public-API surface lock for the published crates.
//
// WHAT THIS GUARDS
//
// This repository publishes a verification-only SDK. Nothing in its public API
// may construct a C2PA manifest or write one into an asset container. That was
// not true until recently: releases rc.1 through rc.11 published the entire
// manifest-production chain, and the governance sweep of the day did not notice
// because it searched for five hard-coded strings and `embed_manifest` was not
// one of them. A denylist only catches what somebody already thought to name.
//
// So the rule is inverted: enumerate the whole public surface and diff it
// against a reviewed inventory. Anything newly public fails until a human adds
// it deliberately. Renaming defeats a denylist; it cannot defeat an inventory.
//
// WHY RUSTDOC JSON AND NOT A SOURCE SCANNER
//
// The first version of this gate parsed Rust source with regexes. Three
// separate reviewers each found a different way past it: a brace inside a
// string literal desynced its depth counter and silently hid every later item;
// a writer in a private module re-exported with `pub use` was invisible; and a
// multiline `impl ... where` header put the opening brace on its own line,
// which its impl regex did not match, so public methods went unrecorded. Each
// hole was patched and the next reviewer found another. A hand-written Rust
// parser is the wrong tool for a security control.
//
// This asks the compiler instead. `cargo rustdoc --output-format json` emits
// rustdoc's own view of the public API, so re-exports, macro-generated items,
// trait and inherent impls, fields and variants are resolved by rustc rather
// than guessed by us. The blind spots above cannot exist here by construction.
//
// COST OF THAT CHOICE: rustdoc JSON requires a nightly toolchain and its schema
// is unstable. Both are handled: CI pins the nightly, and FORMAT_VERSION below
// is asserted on every run so a schema change fails loudly instead of silently
// producing a wrong inventory.
//
//   node scripts/check-public-surface.mjs           # verify against inventory
//   node scripts/check-public-surface.mjs --write   # regenerate the inventory

import { readFile, writeFile, access } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const inventoryPath = resolve(root, "public-surface.txt");

// rustdoc JSON schema version this script understands. A bump means the schema
// changed under us: re-read the extraction below before trusting any output.
const FORMAT_VERSION = 61;

// Crates published to crates.io, with their lib names. Keep in sync with
// release.yml. `encypher-c2pa-cli` is a binary: it ships no API to link
// against, so it has no surface to lock.
const PUBLISHED_LIBS = [
  ["encypher-c2pa-cbor", "c2pa_cbor"],
  ["encypher-c2pa-core", "c2pa_core"],
  ["encypher-c2pa-crypto", "c2pa_crypto"],
  ["encypher-c2pa-formats", "c2pa_formats"],
  ["encypher-c2pa-trust", "c2pa_trust"],
  ["encypher-c2pa-validate", "c2pa_validate"],
  ["encypher-c2pa", "encypher_c2pa"],
];

const TOOLCHAIN = process.env.SURFACE_TOOLCHAIN ?? "+nightly";

function fail(message, detail) {
  console.error(`FAIL: ${message}`);
  if (detail) console.error(detail.split("\n").map(l => `  ${l}`).join("\n"));
  console.error("");
  console.error("This gate fails closed. It cannot distinguish 'no public writers'");
  console.error("from 'could not look', so anything it cannot determine is a");
  console.error("failure, never a pass.");
  process.exit(1);
}

async function exists(p) {
  try { await access(p); return true; } catch { return false; }
}

function emitRustdocJson(pkg) {
  const r = spawnSync(
    "cargo",
    [TOOLCHAIN, "rustdoc", "-q", "-p", pkg, "--lib", "--",
     "-Z", "unstable-options", "--output-format", "json",
     "-A", "rustdoc::broken_intra_doc_links"],
    { cwd: root, encoding: "utf8" },
  );
  if (r.status !== 0) {
    fail(`could not produce rustdoc JSON for ${pkg}`,
         (r.stderr || r.error?.message || "unknown error").trim().split("\n").slice(-8).join("\n"));
  }
}

// Extract the crate's OWN public surface. Everything rustdoc placed in `index`
// is already public and reachable; the work here is naming items canonically
// and dropping what belongs to other crates.
function extract(doc, crateName) {
  const out = new Set();
  const { index, paths } = doc;

  // Named items with canonical paths: functions, types, traits, constants.
  // Modules are containers, not surface, so their own entry is skipped - their
  // contents appear under their own paths.
  for (const [id, p] of Object.entries(paths)) {
    if (p.crate_id !== 0 || p.kind === "module") continue;
    if (!index[id]) continue; // present in paths but not documented => not public
    out.add(`${crateName}::${p.path.slice(1).join("::")} (${p.kind})`);
  }

  const typeName = (im) => im.for?.resolved_path?.path ?? null;

  for (const item of Object.values(index)) {
    if (item.crate_id !== 0) continue;
    const inner = item.inner ?? {};

    // Inherent impls only. Trait impls are governed by the trait's own contract
    // and include blanket impls (Borrow, From, ...) that are not our surface.
    if (inner.impl && !inner.impl.trait) {
      const owner = typeName(inner.impl);
      if (owner) {
        for (const mid of inner.impl.items ?? []) {
          const m = index[mid];
          if (m?.name) out.add(`${crateName}::${owner}::${m.name} (method)`);
        }
      }
    }

    // Public fields of public structs.
    const fields = inner.struct?.kind?.plain?.fields;
    if (fields && item.name) {
      for (const fid of fields) {
        const f = index[fid];
        if (f?.name) out.add(`${crateName}::${item.name}::${f.name} (field)`);
      }
    }

    // Enum variants.
    if (inner.enum?.variants && item.name) {
      for (const vid of inner.enum.variants) {
        const v = index[vid];
        if (v?.name) out.add(`${crateName}::${item.name}::${v.name} (variant)`);
      }
    }
  }

  return out;
}

const surface = new Set();
for (const [pkg, lib] of PUBLISHED_LIBS) {
  emitRustdocJson(pkg);
  const jsonPath = resolve(root, "target/doc", `${lib}.json`);
  if (!(await exists(jsonPath))) fail(`rustdoc produced no JSON for ${pkg} at ${jsonPath}`);

  let doc;
  try {
    doc = JSON.parse(await readFile(jsonPath, "utf8"));
  } catch (err) {
    fail(`rustdoc JSON for ${pkg} is unreadable`, err.message);
  }

  if (doc.format_version !== FORMAT_VERSION) {
    fail(
      `rustdoc JSON schema changed for ${pkg}: expected format_version ${FORMAT_VERSION}, got ${doc.format_version}`,
      "The extraction in this script was written against the expected schema.\n" +
      "Re-read it against the new one, then update FORMAT_VERSION and regenerate\n" +
      "the inventory in the same commit.",
    );
  }

  for (const entry of extract(doc, pkg)) surface.add(entry);
}

const current = [...surface].sort();

if (process.argv.includes("--write")) {
  const header = [
    "# Public API surface of the published crates - REVIEWED INVENTORY.",
    "#",
    "# Derived from rustdoc JSON (the compiler's own view), not a source scan.",
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
  fail("public-surface.txt is missing", "Run with --write to create it.");
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
  console.error("");
  console.error("If this is intended, confirm the item cannot construct a C2PA");
  console.error("manifest or write one into an asset, then regenerate:");
  console.error("  node scripts/check-public-surface.mjs --write");
}
if (removed.length) {
  console.error(`${removed.length} item(s) left the public surface (breaking change):`);
  for (const r of removed) console.error(`  - ${r}`);
  console.error("");
  console.error("Intentional? Regenerate the inventory in the same commit.");
}
process.exit(1);
