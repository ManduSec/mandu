// fake-classifier — a stand-in for inspect-mcp's classify-main.ts in the
// arbiter's own tests (confidentiality-plan-14 §14.3): the same stdin/stdout
// contract, no model. argv: <mode> <record file>.
//
//   describe  → the default helper, "Claude (fake)", port 443
//   classify  → records the request (the batches it was handed) to the
//               record file (one JSON line per run), then answers, per batch:
//               a valid folder rule over `clients/`, a folder rule over
//               `src/` (too broad), and in `hostile` mode every malformed
//               shape a compromised classifier could send: an unknown id, a
//               level and a reason outside the enums, an extra field holding
//               a canary, a free-text failure, a batch out of range, a
//               negative drop count.
import { appendFileSync } from "node:fs";

const [mode, record] = process.argv.slice(2);
const CANARY = "CLASSIFIER-CANARY-7f3a9c";

let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (c) => { input += c; });
process.stdin.on("end", () => {
  const req = JSON.parse(input);
  if (req.op === "describe") {
    out({ ok: true, destination: { name: "Claude (fake)", vendor: "Anthropic", mode: "api", port: 443 } });
    return;
  }
  if (record) appendFileSync(record, JSON.stringify({ argv: process.argv.slice(2), env: Object.keys(process.env).sort(), req }) + "\n");
  if (mode === "refuse") { out({ ok: false, error: "no model is configured" }); return; }
  if (mode === "garbage") { process.stdout.write(`not json ${CANARY}\n`); return; }
  if (req.tier === "contents") {
    // Plan 14 §14.11: one answer per document, by what its text says:
    // CONTRACT → no-model/legal, SALARY → local-model/personnel, anything
    // else (a document that asks to be called public included) → public. In
    // `hostile` mode, every malformed shape too.
    const answers = req.batches.map((text, batch) => {
      if (mode === "hostile" && text.includes("SALARY")) return { batch, answer: { level: "no-model", reason: `free text ${CANARY}` } };
      if (text.includes("CONTRACT")) return { batch, answer: { level: "no-model", reason: "legal", ...(mode === "hostile" ? { why: CANARY } : {}) } };
      if (text.includes("SALARY")) return { batch, answer: { level: "local-model", reason: "personnel" } };
      if (mode === "hostile") return { batch, answer: { level: CANARY, reason: CANARY } };
      return { batch, answer: { level: "public" } };
    });
    if (mode === "hostile") {
      answers.push({ batch: 99, answer: { level: "no-model", reason: "legal" } });
      answers.push({ batch: 0, failed: `free text ${CANARY}` });
      answers.push(CANARY);
    }
    out({ ok: true, answers, dropped: mode === "hostile" ? -5 : 0, model: CANARY, note: CANARY });
    return;
  }
  const answers = req.batches.map((text, batch) => {
    const idOf = (name) => {
      const m = new RegExp(`^([fd][0-9]+) root [0-9]+ ${JSON.stringify(name).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`, "m").exec(text);
      return m ? m[1] : null;
    };
    const rules = [];
    const clients = idOf("clients/");
    if (clients) rules.push({ candidate: clients, level: "local-model", reason: "customer-data" });
    const src = idOf("src/");
    if (src) rules.push({ candidate: src, level: "no-model", reason: "unreleased-work" });
    if (mode === "hostile") {
      rules.push({ candidate: "f99999", level: "no-model", reason: "credentials" });
      rules.push({ candidate: clients ?? "d1", level: "public", reason: "customer-data" });
      rules.push({ candidate: clients ?? "d1", level: "no-model", reason: `free text ${CANARY}` });
      rules.push({ candidate: `${CANARY}`, level: "no-model", reason: "legal" });
      rules.push(`${CANARY}`);
      if (clients) rules.push({ candidate: clients, level: "no-model", reason: "customer-data", note: CANARY });
    }
    return { batch, rules };
  });
  if (mode === "hostile") {
    answers.push({ batch: 99, rules: [{ candidate: "d1", level: "no-model", reason: "legal" }] });
    answers.push({ batch: 0, failed: `free text ${CANARY}` });
  }
  out({ ok: true, answers, dropped: mode === "hostile" ? -5 : 0, model: CANARY, note: CANARY });
});

function out(v) {
  process.stdout.write(JSON.stringify(v) + "\n");
}
