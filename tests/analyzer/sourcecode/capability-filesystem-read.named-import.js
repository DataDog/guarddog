// The same reads reached through a destructured or named import. There is no
// `fs.` at the call site, which is what the member-expression strings key on.
const { createReadStream } = require('node:fs');
import { readFileSync } from 'fs';
import { readFile } from 'node:fs/promises';

export function loadSync(p) {
  return readFileSync(p, 'utf8');
}

export async function loadAsync(p) {
  return readFile(p, 'utf8');
}

export function stream(p) {
  return createReadStream(p);
}
