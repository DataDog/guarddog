// ruleid: serialize-environment
JSON.stringify(process.env);

// ruleid: serialize-environment
JSON.stringify(process["env"]);
// ok: serialize-environment
JSON.stringify({});
