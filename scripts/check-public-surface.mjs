// Public-API surface lock for the published crates.
//
// This repository publishes a verification-only SDK. The failure this guards
// against is not "someone named a function `embed`" - it is "something became
// publicly callable and nobody noticed". A denylist of suspicious names cannot
// catch that: the manifest-production chain shipped for four releases through a
// five-symbol sweep because `embed_manifest` matched none of the five.
//
// So the rule is inverted. Every module-level item, public re-export, public
// field, enum variant, inherent public method, and trait implementation
// reachable under this gate's reviewed module inventory is enumerated and
// compared against a checked-in inventory (`public-surface.txt`). Any addition
// fails until a human puts it in the inventory deliberately. Renaming defeats a
// denylist; it cannot defeat an inventory.
//
// The inventory starts at each published crate's lib.rs, walks file-backed
// `pub mod` declarations, records `pub use` leaves, descends into local modules
// behind those re-exports, records public type members, and fails closed on
// inline public modules, `#[path]` public modules, wildcard re-exports, and
// module-level macro invocations. Items behind `#[cfg(test)]` or
// `#[cfg(feature = "test-support")]` are not in the default build that
// consumers get.
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
const PUB_USE = /^\s*pub\s+use\s+/;
const ITEMISH = /^\s*(?:pub(?:\s*\([^)]*\))?\s+)?(?:(?:async|unsafe|extern\s+"[^"]*"|const)\s+)*(?:fn|struct|enum|trait|type|const|static|union|mod|impl|use|extern\s+crate|macro_rules!)\b/;
const MOD_ITEM = /^\s*(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\b/;
const ATTR = /^\s*#\[/;
const PATH_ATTR = /^#\[\s*path\s*=/;
const MACRO_INVOKE = /^\s*(?!macro_rules\b)(?:[A-Za-z_][A-Za-z0-9_]*::)*[A-Za-z_][A-Za-z0-9_]*!\s*[({]/;
const IMPL = /^\s*impl(?:\s*<[^>{}]*>)?\s+([^{]+)\{/;
const PUBLIC_FIELD = /^\s*pub\s+(?!\()([A-Za-z_][A-Za-z0-9_]*)\s*:/;
const PUBLIC_METHOD = /^\s*pub\s+(?!\()(?:(?:async|unsafe|extern\s+"[^"]*"|const)\s+)*(fn|const)\s+([A-Za-z_][A-Za-z0-9_]*)/;
const TRAIT_MEMBER = /^\s*(?:(?:async|unsafe|extern\s+"[^"]*"|const)\s+)*(fn|type|const)\s+([A-Za-z_][A-Za-z0-9_]*)/;
const ENUM_VARIANT = /^\s*([A-Za-z_][A-Za-z0-9_]*)\b/;

function splitTopLevel(s) {
  const parts = [];
  let start = 0;
  let depth = 0;
  let quote = false;
  let escape = false;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (quote) {
      if (escape) escape = false;
      else if (ch === "\\") escape = true;
      else if (ch === "\"") quote = false;
    } else if (ch === "\"") {
      quote = true;
    } else if (ch === "(" || ch === "[" || ch === "{") {
      depth++;
    } else if (ch === ")" || ch === "]" || ch === "}") {
      depth--;
    } else if (ch === "," && depth === 0) {
      parts.push(s.slice(start, i).trim());
      start = i + 1;
    }
  }
  parts.push(s.slice(start).trim());
  return parts.filter(Boolean);
}

function callBody(s, name) {
  const m = s.trim().match(new RegExp(`^${name}\\s*\\(([\\s\\S]*)\\)$`));
  return m ? m[1].trim() : null;
}

function cfgEnabled(expr) {
  expr = expr.trim();
  let body = callBody(expr, "any");
  if (body !== null) return splitTopLevel(body).some(cfgEnabled);
  body = callBody(expr, "all");
  if (body !== null) return splitTopLevel(body).every(cfgEnabled);
  body = callBody(expr, "not");
  if (body !== null) {
    const parts = splitTopLevel(body);
    return parts.length === 1 ? !cfgEnabled(parts[0]) : true;
  }
  if (expr === "test") return false;
  const feature = expr.match(/^feature\s*=\s*"([^"]+)"/);
  return feature?.[1] !== "test-support";
}

function attributeExcludes(attr) {
  const body = attr.trim().replace(/^#\[\s*/, "").replace(/\]\s*$/, "").trim();
  let cfg = callBody(body, "cfg");
  if (cfg !== null) return !cfgEnabled(cfg);

  const cfgAttr = callBody(body, "cfg_attr");
  if (cfgAttr === null) return false;
  const parts = splitTopLevel(cfgAttr);
  if (parts.length < 2 || !cfgEnabled(parts[0])) return false;
  return parts.slice(1).some(part => {
    cfg = callBody(part, "cfg");
    return cfg !== null && !cfgEnabled(cfg);
  });
}

function matchingBrace(s, open) {
  let depth = 0;
  let quote = false;
  let escape = false;
  for (let i = open; i < s.length; i++) {
    const ch = s[i];
    if (quote) {
      if (escape) escape = false;
      else if (ch === "\\") escape = true;
      else if (ch === "\"") quote = false;
    } else if (ch === "\"") {
      quote = true;
    } else if (ch === "{") {
      depth++;
    } else if (ch === "}") {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

function exportedUseNames(tree, prefixParts = []) {
  tree = tree.trim();
  const brace = tree.indexOf("{");
  if (brace !== -1) {
    const close = matchingBrace(tree, brace);
    if (close === -1 || tree.slice(close + 1).trim()) {
      throw new Error(`unsupported pub use tree: ${tree}`);
    }
    const prefix = tree.slice(0, brace).trim().replace(/::$/, "");
    const nextPrefix = prefix
      ? prefixParts.concat(prefix.split("::").filter(Boolean))
      : prefixParts;
    return splitTopLevel(tree.slice(brace + 1, close))
      .flatMap(part => exportedUseNames(part, nextPrefix));
  }

  if (tree === "*") throw new Error("wildcard pub use is not inventoried");
  const alias = tree.match(/\s+as\s+([A-Za-z_][A-Za-z0-9_]*)$/);
  if (alias) return [alias[1]];
  const parts = tree.split("::").map(part => part.trim()).filter(Boolean);
  const last = parts.at(-1);
  if (!last) throw new Error(`unsupported pub use tree: ${tree}`);
  if (last === "self") {
    const self = prefixParts.at(-1);
    if (!self) throw new Error(`unsupported pub use tree: ${tree}`);
    return [self];
  }
  return [last];
}

function localUseRoots(tree, prefixParts = []) {
  tree = tree.trim();
  const brace = tree.indexOf("{");
  if (brace !== -1) {
    const close = matchingBrace(tree, brace);
    if (close === -1 || tree.slice(close + 1).trim()) {
      throw new Error(`unsupported pub use tree: ${tree}`);
    }
    const prefix = tree.slice(0, brace).trim().replace(/::$/, "");
    const nextPrefix = prefix
      ? prefixParts.concat(prefix.split("::").filter(Boolean))
      : prefixParts;
    return splitTopLevel(tree.slice(brace + 1, close))
      .flatMap(part => localUseRoots(part, nextPrefix));
  }

  if (tree === "*") throw new Error("wildcard pub use is not inventoried");
  const parts = prefixParts.concat(
    tree
      .replace(/\s+as\s+[A-Za-z_][A-Za-z0-9_]*$/, "")
      .split("::")
      .map(part => part.trim())
      .filter(Boolean),
  );
  const root = parts[0];
  if (!root || root === "crate" || root === "self" || root === "super") return [];
  return parts.length > 1 ? [root] : [];
}

function pubUseModuleRoots(statement) {
  const body = statement
    .trim()
    .replace(/^pub\s+use\s+/, "")
    .replace(/;\s*$/, "")
    .trim();
  return [...new Set(localUseRoots(body))];
}

function pubUseNames(statement) {
  const body = statement
    .trim()
    .replace(/^pub\s+use\s+/, "")
    .replace(/;\s*$/, "")
    .trim();
  return exportedUseNames(body);
}

function collectStatement(lines, start) {
  let text = "";
  const state = { blockDepth: 0, rawEnd: null, quote: null, escape: false };
  for (let i = start; i < lines.length; i++) {
    const line = stripRustTrivia(lines[i], state);
    text += `${text ? " " : ""}${line.trim()}`;
    if (!state.blockDepth && !state.rawEnd && !state.quote && line.includes(";")) {
      return { text, end: i };
    }
  }
  throw new Error(`unterminated Rust statement starting at line ${start + 1}`);
}

function collectAttribute(lines, start) {
  let text = "";
  let depth = 0;
  let rawEnd = null;
  let quote = false;
  let escape = false;
  for (let i = start; i < lines.length; i++) {
    const raw = lines[i];
    text += `${text ? " " : ""}${raw.trim()}`;
    for (let j = 0; j < raw.length;) {
      if (rawEnd) {
        if (raw.startsWith(rawEnd, j)) { j += rawEnd.length; rawEnd = null; }
        else j++;
      } else if (quote) {
        if (escape) escape = false;
        else if (raw[j] === "\\") escape = true;
        else if (raw[j] === "\"") quote = false;
        j++;
      } else {
        const rs = rawString(raw, j);
        if (rs) { rawEnd = rs.end; j = rs.start; }
        else if (raw.startsWith("//", j)) break;
        else if (raw[j] === "\"") { quote = true; j++; }
        else {
          if (raw[j] === "[") depth++;
          else if (raw[j] === "]") depth--;
          j++;
        }
      }
    }
    if (depth <= 0 && !rawEnd && !quote) return { text, end: i };
  }
  return { text, end: lines.length - 1 };
}

function memberContext(prefix, kind, name, line) {
  if ((kind === "struct" || kind === "enum" || kind === "trait") && line.includes("{")) {
    return { kind, path: `${prefix}::${name}`, excluded: false };
  }
  return null;
}

function implContext(prefix, line) {
  const m = line.match(IMPL);
  if (!m) return null;
  const header = m[1].trim();
  const forParts = header.split(/\s+for\s+/);
  const typeExpr = (forParts.length === 2 ? forParts[1] : header)
    .replace(/\s+where\b[\s\S]*$/, "")
    .trim();
  const name = typeExpr
    .split("::")
    .at(-1)
    .replace(/<[\s\S]*$/, "")
    .trim();
  if (!name) return null;
  if (forParts.length === 2) {
    return {
      kind: "trait-impl",
      path: `${prefix}::${name}`,
      traitName: forParts[0].trim(),
      excluded: false,
    };
  }
  return { kind: "impl", path: `${prefix}::${name}`, excluded: false };
}

function recordMember(out, ctx, line) {
  if (ctx.kind === "struct") {
    const m = line.match(PUBLIC_FIELD);
    if (!m) return false;
    if (!ctx.excluded) out.add(`${ctx.path}::${m[1]} (field)`);
    ctx.excluded = false;
    return true;
  }

  if (ctx.kind === "enum") {
    const m = line.match(ENUM_VARIANT);
    if (!m || ["pub", "fn", "impl", "where"].includes(m[1])) return false;
    if (!ctx.excluded) out.add(`${ctx.path}::${m[1]} (variant)`);
    ctx.excluded = false;
    return true;
  }

  if (ctx.kind === "trait") {
    const m = line.match(TRAIT_MEMBER);
    if (!m) return false;
    if (!ctx.excluded) out.add(`${ctx.path}::${m[2]} (${m[1]})`);
    ctx.excluded = false;
    return true;
  }

  if (ctx.kind === "impl") {
    const m = line.match(PUBLIC_METHOD);
    if (!m) return false;
    if (!ctx.excluded) out.add(`${ctx.path}::${m[2]} (${m[1]})`);
    ctx.excluded = false;
    return true;
  }

  return false;
}

function rawString(line, i) {
  let j = i;
  if ((line[j] === "b" || line[j] === "c") && line[j + 1] === "r") j++;
  if (line[j] !== "r") return null;
  j++;
  let hashes = 0;
  while (line[j + hashes] === "#") hashes++;
  if (line[j + hashes] !== "\"") return null;
  return { start: j + hashes + 1, end: `"${"#".repeat(hashes)}` };
}

function charLiteralEnd(line, i) {
  let j = i + 1;
  if (line[j] === "\\") j += 2;
  else j += 1;
  return line[j] === "'" ? j + 1 : null;
}

function stripRustTrivia(line, state) {
  let out = "";
  for (let i = 0; i < line.length;) {
    if (state.blockDepth) {
      if (line.startsWith("/*", i)) { state.blockDepth++; i += 2; }
      else if (line.startsWith("*/", i)) { state.blockDepth--; i += 2; }
      else i++;
      out += " ";
    } else if (state.rawEnd) {
      if (line.startsWith(state.rawEnd, i)) { i += state.rawEnd.length; state.rawEnd = null; }
      else i++;
      out += " ";
    } else if (state.quote) {
      if (state.escape) state.escape = false;
      else if (line[i] === "\\") state.escape = true;
      else if (line[i] === state.quote) state.quote = null;
      i++;
      out += " ";
    } else if (line.startsWith("//", i)) {
      break;
    } else if (line.startsWith("/*", i)) {
      state.blockDepth++;
      i += 2;
      out += " ";
    } else {
      const raw = rawString(line, i);
      if (raw) {
        state.rawEnd = raw.end;
        i = raw.start;
        out += " ";
      } else if (line[i] === "\"" || (line[i] === "b" && line[i + 1] === "\"")) {
        state.quote = "\"";
        i += line[i] === "b" ? 2 : 1;
        out += " ";
      } else if (line[i] === "'" || (line[i] === "b" && line[i + 1] === "'")) {
        const end = charLiteralEnd(line, i + (line[i] === "b" ? 1 : 0));
        if (end === null) out += line[i++];
        else { out += " "; i = end; }
      } else {
        out += line[i++];
      }
    }
  }
  return out;
}

async function exists(p) {
  try { await access(p); return true; } catch { return false; }
}

function moduleDeclarations(lines) {
  const names = new Set();
  const pathOverrides = new Set();
  let excluded = false;
  let pathOverride = false;
  let depth = 0;
  const lexical = { blockDepth: 0, rawEnd: null, quote: null, escape: false };

  for (let i = 0; i < lines.length; i++) {
    const line = stripRustTrivia(lines[i], lexical);
    if (depth === 0 && ATTR.test(line)) {
      const attr = collectAttribute(lines, i);
      if (PATH_ATTR.test(attr.text)) pathOverride = true;
      if (attributeExcludes(attr.text)) excluded = true;
      i = attr.end;
      continue;
    }

    const m = depth === 0 ? line.match(MOD_ITEM) : null;
    if (m) {
      if (!excluded) {
        names.add(m[1]);
        if (pathOverride || line.includes("{")) pathOverrides.add(m[1]);
      }
      excluded = false;
      pathOverride = false;
    } else if (depth === 0 && ITEMISH.test(line)) {
      excluded = false;
      pathOverride = false;
    }

    depth += (line.match(/\{/g) || []).length;
    depth -= (line.match(/\}/g) || []).length;
    if (depth < 0) depth = 0;
  }

  return { names, pathOverrides };
}

// Resolve `mod name;` to its file: name.rs or name/mod.rs, relative to the
// declaring file's directory (or its module subdirectory for non-root files).
async function resolveModule(fromFile, name, isRoot) {
  const dir = dirname(fromFile);
  const bases = [isRoot || fromFile.endsWith("/mod.rs")
    ? dir
    : join(dir, fromFile.split("/").pop().replace(/\.rs$/, ""))];
  for (const b of bases) {
    for (const cand of [join(b, `${name}.rs`), join(b, name, "mod.rs")]) {
      if (await exists(cand)) return cand;
    }
  }
  return null;
}

// Walk a file, collecting public items and recursing only into file-backed
// `pub mod` declarations. Inline public modules fail closed; otherwise their
// contents could become public without an inventory line.
async function walk(file, prefix, isRoot, out, seen) {
  if (seen.has(file)) return;
  seen.add(file);
  const lines = (await readFile(file, "utf8")).split("\n");
  const localModules = moduleDeclarations(lines);

  let excluded = false;   // pending cfg attribute applies to the next item
  let pathOverride = false;
  let depth = 0;          // brace depth; we only take items at module level
  const lexical = { blockDepth: 0, rawEnd: null, quote: null, escape: false };
  const contexts = [];

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const line = stripRustTrivia(raw, lexical);

    const ctx = contexts.at(-1);
    if (ctx && depth === ctx.depth && ATTR.test(line)) {
      const attr = collectAttribute(lines, i);
      if (attributeExcludes(attr.text)) ctx.excluded = true;
      i = attr.end;
      continue;
    }

    if (ctx && depth === ctx.depth) {
      recordMember(out, ctx, line);
    }

    if (depth === 0 && ATTR.test(line)) {
      const attr = collectAttribute(lines, i);
      if (PATH_ATTR.test(attr.text)) pathOverride = true;
      if (attributeExcludes(attr.text)) excluded = true;
      i = attr.end;
      continue;
    }

    if (depth === 0 && PUB_USE.test(line) && !PUB_CRATE.test(line)) {
      const statement = collectStatement(lines, i);
      if (!excluded) {
        for (const name of pubUseNames(statement.text)) {
          out.add(`${prefix}::${name} (use)`);
        }
        for (const rootName of pubUseModuleRoots(statement.text)) {
          if (localModules.pathOverrides.has(rootName)) {
            throw new Error(`pub use of inline or #[path] module is not inventoried: ${file}:${i + 1}`);
          }
          const child = await resolveModule(file, rootName, isRoot);
          if (child) await walk(child, `${prefix}::${rootName}`, false, out, seen);
          else if (localModules.names.has(rootName)) {
            throw new Error(`pub use of non-file-backed local module is not inventoried: ${file}:${i + 1}`);
          }
        }
      }
      excluded = false;
      pathOverride = false;
      i = statement.end;
      continue;
    }

    let nextContext = null;
    const m = depth === 0 ? line.match(ITEM) : null;
    if (m && !PUB_CRATE.test(line)) {
      const [, kind, name] = m;
      if (kind === "mod") {
        if (!excluded) {
          if (pathOverride) {
            throw new Error(`#[path] public module is not inventoried: ${file}:${i + 1}`);
          }
          const child = await resolveModule(file, name, isRoot);
          if (child) await walk(child, `${prefix}::${name}`, false, out, seen);
          else if (line.includes("{")) {
            throw new Error(`inline public module is not inventoried: ${file}:${i + 1}`);
          } else {
            throw new Error(`public module is not file-backed: ${file}:${i + 1}`);
          }
        }
      } else if (!excluded) {
        out.add(`${prefix}::${name} (${kind})`);
        nextContext = memberContext(prefix, kind, name, line);
      }
    }

    const implCtx = depth === 0 ? implContext(prefix, line) : null;
    if (implCtx && !excluded) {
      if (implCtx.kind === "trait-impl") {
        out.add(`${implCtx.path} as ${implCtx.traitName} (impl)`);
      } else {
        nextContext = implCtx;
      }
    }


    // Any item consumes pending attributes, even when it is not part of the
    // public surface. That prevents a cfg on `use`, `impl`, or a private item
    // from leaking onto the following public item.
    if (depth === 0 && ITEMISH.test(line)) {
      excluded = false;
      pathOverride = false;
    }
    if (depth === 0 && MACRO_INVOKE.test(line)) {
      if (!excluded) throw new Error(`module-level macro invocation is not inventoried: ${file}:${i + 1}`);
      excluded = false;
      pathOverride = false;
    }

    const beforeDepth = depth;
    depth += (line.match(/\{/g) || []).length;
    depth -= (line.match(/\}/g) || []).length;
    if (depth < 0) depth = 0;
    if (nextContext && depth > beforeDepth) contexts.push({ ...nextContext, depth });
    while (contexts.length && depth < contexts.at(-1).depth) contexts.pop();
  }

  if (depth !== 0 || lexical.blockDepth || lexical.rawEnd || lexical.quote) {
    throw new Error(`unterminated Rust syntax while scanning ${file}`);
  }
}

// The scanner refuses to guess. Every construct it cannot inventory raises,
// and raising must read as a deliberate gate failure rather than a broken
// script - a gate that looks crashed is a gate someone disables.
const surface = new Set();
try {
  for (const [crateName, dir] of PUBLISHED_CRATES) {
    for (const entry of ["src/lib.rs", "src/main.rs"]) {
      const f = resolve(root, dir, entry);
      if (await exists(f)) await walk(f, crateName, true, surface, new Set());
    }
  }
} catch (err) {
  console.error("FAIL: the public surface could not be determined.");
  console.error(`  ${err.message}`);
  console.error("");
  console.error("This gate fails closed: a construct it cannot inventory is a");
  console.error("failure, never a pass, because an uninventoried item may be a");
  console.error("manifest constructor or container writer. Either express it in a");
  console.error("form the scanner understands - a file-backed module, an explicit");
  console.error("re-export - or teach the scanner that construct.");
  process.exit(1);
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
