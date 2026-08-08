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
     // `#[doc(hidden)] pub` is still callable by a downstream crate. Without
     // this flag rustdoc omits those items and the gate would read their
     // absence as "not public" - a reviewer demonstrated a doc-hidden writer
     // passing the gate while a consumer embedded a real PNG manifest chunk.
     "--document-hidden-items",
     "-A", "rustdoc::broken_intra_doc_links"],
    { cwd: root, encoding: "utf8" },
  );
  if (r.status !== 0) {
    fail(`could not produce rustdoc JSON for ${pkg}`,
         (r.stderr || r.error?.message || "unknown error").trim().split("\n").slice(-8).join("\n"));
  }
}

// Extract the crate's OWN public surface.
//
// This is EXHAUSTIVE by construction, and that property is the whole point.
// Earlier revisions enumerated the item families someone had thought of -
// named paths, impls, plain struct fields, variant names - and reviewers kept
// finding a family that was never walked. Struct-like enum variant FIELDS were
// the last: `AssetFormat::TextStructured` gained a writer field, the gate said
// PASS, and a consumer called it. Patching families one at a time did not
// converge across four review cycles.
//
// So the walk visits every crate-local item rustdoc emitted, and anything it
// cannot name or cannot reach is a FAILURE rather than a silent omission. A
// family nobody anticipated now breaks the build instead of opening a hole.
function extract(doc, crateName) {
  const out = new Set();
  const { index, root } = doc;
  const visited = new Set();

  // Name the type an impl block is written for. Receivers are not always a
  // bare nominal path: `impl Trait for &Format` is legal because references
  // are #[fundamental], and a reviewer hid a writer that way. Returns null
  // only when genuinely unnameable; callers MUST treat null as failure.
  const typeName = (ty) => {
    if (!ty) return null;
    if (ty.resolved_path?.path) return ty.resolved_path.path;
    if (ty.borrowed_ref?.type) { const i = typeName(ty.borrowed_ref.type); return i ? `&${i}` : null; }
    if (ty.raw_pointer?.type) { const i = typeName(ty.raw_pointer.type); return i ? `*${i}` : null; }
    if (ty.slice) { const i = typeName(ty.slice); return i ? `[${i}]` : null; }
    if (ty.array?.type) { const i = typeName(ty.array.type); return i ? `[${i}; N]` : null; }
    if (ty.tuple) { const p = ty.tuple.map(typeName); return p.every(Boolean) ? `(${p.join(", ")})` : null; }
    if (typeof ty.primitive === "string") return ty.primitive;
    if (typeof ty.generic === "string") return ty.generic;
    return null;
  };

  const record = (path, kind) => out.add(`${crateName}::${path} (${kind})`);

  // Visit one item, record it, and recurse into everything it contains.
  // `path` is the qualified name of this item.
  const visit = (id, path) => {
    if (id === null || id === undefined) return; // private tuple field slot
    const item = index[id];
    if (!item) return;                            // belongs to another crate
    if (item.crate_id !== 0) return;
    if (visited.has(id)) return;
    visited.add(id);

    const inner = item.inner ?? {};
    const kind = Object.keys(inner)[0];

    switch (kind) {
      case "module":
        // Containers are not surface themselves; their contents are.
        for (const cid of inner.module.items ?? []) {
          const c = index[cid];
          // A `pub use` item carries no `name`; its public name lives on the
          // re-export record. Without this the re-exported item is walked
          // under the parent's path and inventoried under the wrong name.
          const childName = c?.name ?? c?.inner?.use?.name ?? null;
          visit(cid, childName ? (path ? `${path}::${childName}` : childName) : path);
        }
        return;

      case "struct": {
        record(path, "struct");
        const k = inner.struct.kind;
        const fieldIds = k?.plain?.fields ?? k?.tuple ?? [];
        for (const [i, fid] of fieldIds.entries()) {
          const f = fid === null ? null : index[fid];
          if (f) visit(fid, `${path}::${f.name ?? i}`);
        }
        for (const iid of inner.struct.impls ?? []) visitImpl(iid);
        return;
      }

      case "enum":
        record(path, "enum");
        for (const vid of inner.enum.variants ?? []) {
          const v = index[vid];
          if (v) visit(vid, `${path}::${v.name}`);
        }
        for (const iid of inner.enum.impls ?? []) visitImpl(iid);
        return;

      case "variant": {
        record(path, "variant");
        const vk = inner.variant.kind;
        // Struct-like and tuple variants carry FIELDS, which are public API.
        // Missing these was the seventh evasion found against this gate.
        const fieldIds = vk?.struct?.fields ?? vk?.tuple ?? [];
        for (const [i, fid] of fieldIds.entries()) {
          const f = fid === null ? null : index[fid];
          if (f) visit(fid, `${path}::${f.name ?? i}`);
        }
        return;
      }

      case "union":
        record(path, "union");
        for (const fid of inner.union.fields ?? []) {
          const f = index[fid];
          if (f) visit(fid, `${path}::${f.name}`);
        }
        for (const iid of inner.union.impls ?? []) visitImpl(iid);
        return;

      case "trait":
        record(path, "trait");
        // A trait's own members are callable through any implementor, and a
        // default-bodied method needs no impl at all. Inventory them.
        for (const tid of inner.trait.items ?? []) {
          const t = index[tid];
          if (t?.name) visit(tid, `${path}::${t.name}`);
        }
        return;

      case "use": {
        // Re-export. `is_glob` means the names it introduces are not listed
        // here, so the walk cannot enumerate them - refuse rather than guess.
        if (inner.use.is_glob) {
          fail(
            "a glob re-export cannot be inventoried",
            `${crateName}::${path} -> ${inner.use.source}::*\n\n` +
            "Name the re-exported items explicitly so the surface is reviewable.",
          );
        }
        record(path, "use");
        const target = inner.use.id;
        if (target !== null && target !== undefined && index[target]) visit(target, path);
        return;
      }

      case "impl":
        visitImpl(id);
        return;

      // Leaves. Each is surface in its own right.
      case "function":       record(path, "function"); return;
      case "struct_field":   record(path, "field"); return;
      case "constant":       record(path, "constant"); return;
      case "static":         record(path, "static"); return;
      case "type_alias":     record(path, "type_alias"); return;
      case "trait_alias":    record(path, "trait_alias"); return;
      case "assoc_const":    record(path, "assoc_const"); return;
      case "assoc_type":     record(path, "assoc_type"); return;
      case "macro":          record(path, "macro"); return;
      case "proc_macro":     record(path, "proc_macro"); return;
      case "primitive":      record(path, "primitive"); return;
      case "extern_crate":   return; // not surface

      default:
        fail(
          `rustdoc emitted an item kind this script does not handle: ${kind}`,
          `${crateName}::${path}\n\n` +
          "Add a naming rule for it and regenerate the inventory. Ignoring an\n" +
          "unknown kind is how a public writer slips through: four review\n" +
          "cycles each found a family an earlier revision never walked.",
        );
    }
  };

  function visitImpl(id) {
    const item = index[id];
    if (!item || item.crate_id !== 0 || visited.has(id)) return;
    visited.add(id);
    const im = item.inner?.impl;
    if (!im) return;

    // Auto-trait and blanket impls come from other crates' generic impls.
    if (im.is_synthetic || im.blanket_impl) return;

    const owner = typeName(im.for);
    if (!owner) {
      fail(
        "an impl block in this crate has a receiver type this script cannot name",
        `${crateName}: impl ${im.trait?.path ?? "(inherent)"} for <unnameable>\n` +
        `receiver JSON: ${JSON.stringify(im.for).slice(0, 300)}\n\n` +
        "Teach typeName() this shape, then regenerate the inventory.",
      );
    }

    if (im.trait) {
      // One line per (type, trait) pair. The trait's own member list is
      // inventoried at the trait, so per-method entries here would only add
      // derive noise without adding review signal.
      out.add(`${crateName}::${owner}: ${im.trait.path} (trait impl)`);
      for (const mid of im.items ?? []) visited.add(mid);
    } else {
      for (const mid of im.items ?? []) {
        const m = index[mid];
        visited.add(mid);
        if (m?.name) out.add(`${crateName}::${owner}::${m.name} (method)`);
      }
    }
  }

  visit(root, "");

  // Anything rustdoc emitted for this crate that the walk never reached is a
  // containment shape we do not model. Refuse rather than assume it is private.
  //
  // `Object.entries` yields string keys while rustdoc ids (and therefore
  // `visited`) are numbers, so both sides are normalised before comparison.
  const unreached = Object.entries(index)
    .filter(([id, it]) => it.crate_id === 0 && !visited.has(Number(id)))
    .map(([id, it]) => `${Object.keys(it.inner ?? {})[0]} ${it.name ?? "<unnamed>"} (id ${id})`);
  if (unreached.length) {
    fail(
      `${unreached.length} crate-local item(s) were emitted by rustdoc but never reached by the walk`,
      unreached.slice(0, 10).join("\n") +
      "\n\nThe walk must reach every item so none can hide. Model the missing\n" +
      "containment and regenerate the inventory.",
    );
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
