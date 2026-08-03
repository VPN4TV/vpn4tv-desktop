// VPN4TV: fail the build on circular imports in the main process.
//
// A cycle is not a style problem here. daemon.ts assigns an imported binding at
// module scope on Windows, so when `daemon → worker → repair → daemon` closed,
// the packaged Windows app died before its window appeared with "Cannot access
// 'daemonWorkerTransport' before initialization". That path runs only on
// Windows in a packaged build, so nothing on macOS could catch it — this can.
//
//   node scripts/check-cycles.mjs [directory...]

import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const defaultRoots = ["src/main", "src/preload", "src/renderer", "src/shared"];
const roots = process.argv.length > 2 ? process.argv.slice(2) : defaultRoots;

const SOURCE_PATTERN = /\.(ts|tsx|mts|cts|js|mjs)$/u;
const IMPORT_PATTERN = /(?:from|import)\s*\(?\s*["'](\.[^"']+)["']/gu;

function sourceFiles(directory) {
  const found = [];
  const walk = (current) => {
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const path = join(current, entry.name);
      if (entry.isDirectory()) {
        walk(path);
      } else if (SOURCE_PATTERN.test(entry.name) && !/\.d\.ts$/u.test(entry.name)) {
        found.push(path);
      }
    }
  };
  walk(directory);
  return found;
}

/** Resolve a relative specifier the way the bundler does. */
function resolveImport(fromFile, specifier) {
  const base = resolve(dirname(fromFile), specifier);
  const candidates = [
    base,
    ...[".ts", ".tsx", ".mts", ".cts", ".js", ".mjs"].map((extension) => base + extension),
    ...[".ts", ".tsx", ".js"].map((extension) => join(base, "index" + extension)),
  ];
  for (const candidate of candidates) {
    try {
      if (statSync(candidate).isFile()) {
        return candidate;
      }
    } catch {
      // keep looking
    }
  }
  return null;
}

const graph = new Map();
for (const root of roots) {
  const directory = resolve(repositoryRoot, root);
  let entries;
  try {
    entries = sourceFiles(directory);
  } catch {
    continue; // a root that does not exist is not an error
  }
  for (const file of entries) {
    const dependencies = new Set();
    for (const match of readFileSync(file, "utf-8").matchAll(IMPORT_PATTERN)) {
      const target = resolveImport(file, match[1]);
      if (target !== null) {
        dependencies.add(target);
      }
    }
    graph.set(file, dependencies);
  }
}

// Depth-first search; every back edge to a node still on the stack is a cycle.
const state = new Map();
const stack = [];
const cycles = [];

function visit(node) {
  state.set(node, "open");
  stack.push(node);
  for (const dependency of graph.get(node) ?? []) {
    if (!graph.has(dependency)) {
      continue;
    }
    if (state.get(dependency) === "open") {
      cycles.push([...stack.slice(stack.indexOf(dependency)), dependency]);
    } else if (!state.has(dependency)) {
      visit(dependency);
    }
  }
  stack.pop();
  state.set(node, "done");
}

for (const node of [...graph.keys()].sort()) {
  if (!state.has(node)) {
    visit(node);
  }
}

const show = (file) => relative(repositoryRoot, file);

if (cycles.length > 0) {
  console.error(`circular imports (${cycles.length}):`);
  for (const cycle of cycles) {
    console.error("  " + cycle.map(show).join(" -> "));
  }
  console.error(
    "\nBreak the cycle — move the shared value into a module that imports nothing\n" +
      "from the cluster. A binding read at module scope inside a cycle throws at\n" +
      "startup, and only on the platform that reaches that line.",
  );
  process.exit(1);
}

console.log(`no circular imports (${graph.size} modules)`);
