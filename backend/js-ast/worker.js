/* CodeShield AI — persistent JS AST worker (NFR-01).
 * Length-prefixed JSON over stdio: [4-byte BE len][payload] <-> reply.
 * Reuses scan.js logic by requiring it as a module.
 */
const { scan } = require("./scan.js");

let buf = Buffer.alloc(0);
process.stdin.on("data", (chunk) => {
  buf = Buffer.concat([buf, chunk]);
  while (buf.length >= 4) {
    const len = buf.readUInt32BE(0);
    if (buf.length < 4 + len) break;
    const payload = buf.slice(4, 4 + len).toString("utf8");
    buf = buf.slice(4 + len);
    let out;
    try {
      const req = JSON.parse(payload || "{}");
      out = scan(String(req.code || ""), String(req.filename || "untitled"));
    } catch (e) {
      out = { findings: [], error: String((e && e.message) || e) };
    }
    const resp = Buffer.from(JSON.stringify(out), "utf8");
    const head = Buffer.alloc(4);
    head.writeUInt32BE(resp.length, 0);
    process.stdout.write(Buffer.concat([head, resp]));
  }
});
process.stdin.resume();
