// Benign regression test for the image-obfuscation runtime detection rule.
// Buffer.concat() and a PNG asset path sit near Playwright's page.$eval
// selector method, which is not the bare execution builtin, so this must
// not trigger.
const icon = './assets/logo.png';
const combined = Buffer.concat([a, b]);

async function readCount(page) {
  return page.$eval('#count', (el) => el.textContent);
}
