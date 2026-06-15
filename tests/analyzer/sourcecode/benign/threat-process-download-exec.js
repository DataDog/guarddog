// Legit: a Map lookup and a regex match. These resemble Python download +
// exec to a naive matcher but are ordinary JS and must NOT trip download-exec.
function trackRequest(requestId, input) {
  const info = this._requests.get(requestId);
  const match = urlRegex.exec(input);
  return { info, match };
}
