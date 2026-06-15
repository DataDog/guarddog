// Legitimate dynamic evaluation patterns that must NOT match:
// - eval of a plain expression string (e.g. a math/config expression)
// - calling a named function (not eval-ing a function literal)
// - using String.fromCharCode for normal string building, far from any eval
function evaluateExpression(expr) {
  return eval(expr);
}

function decodeLabel(codes) {
  return String.fromCharCode.apply(null, codes);
}

const handler = function (req, res) {
  res.end("ok");
};
server.on("request", handler);

module.exports = { evaluateExpression, decodeLabel };
