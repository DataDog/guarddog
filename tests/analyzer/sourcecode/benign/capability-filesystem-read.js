// A local helper that happens to share a name with the fs export. The import
// specifier is what decides, so this must not match.
import { readFileSync, createReadStream } from './cache-layer';
import { readFile } from '@acme/virtual-fs';

export function warm(key) {
  return readFileSync(key);
}

export function pipe(key) {
  return createReadStream(key);
}

export async function fetchEntry(key) {
  return readFile(key);
}
