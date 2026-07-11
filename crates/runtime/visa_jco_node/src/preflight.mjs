import { readFileSync } from 'node:fs';

for (const path of process.argv.slice(2)) {
  new WebAssembly.Module(readFileSync(path));
}

process.stdout.write(JSON.stringify({
  node: process.versions.node,
  v8: process.versions.v8,
}));
