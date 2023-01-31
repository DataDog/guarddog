// ruleid: npm-serialize-environment
JSON.stringify(process.env);

// ruleid: npm-serialize-environment
JSON.stringify(process["env"]);
// ok: npm-serialize-environment
JSON.stringify({});
