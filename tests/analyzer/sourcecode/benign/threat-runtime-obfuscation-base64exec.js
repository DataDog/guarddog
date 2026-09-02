// Benign regression test for threat-runtime-obfuscation-base64exec.
// A base64-encoded fixture blob sits in the same file as Playwright's
// page.$eval selector method, which is not the bare execution builtin.
// This must not trigger.
const fixture = Buffer.from(rawFixture, 'base64');

async function readCount(page) {
  return page.$eval('#count', (el) => el.textContent);
}
