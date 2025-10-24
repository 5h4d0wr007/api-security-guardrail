import fs from "fs/promises";

const RUN = "run.json";
const OUT = "results.sarif";

const RULES = {
  "auth.missing": { id: "auth.missing", short: "Missing authentication" },
  "idor.heuristic": { id: "idor.heuristic", short: "Insecure Direct Object Reference" },
  "mass_assignment.probe": { id: "mass_assignment.probe", short: "Mass assignment accepted" },
  "cache_control.missing_sensitive_get": { id: "cache_control.missing_sensitive_get", short: "Missing Cache-Control no-store" },
  "security.test": { id: "security.test", short: "Security test failed" }
};

function guessRule(assertionName) {
  const a = (assertionName || "").toLowerCase();
  if (a.includes("no-auth") || a.includes("no auth")) return "auth.missing";
  if (a.includes("idor")) return "idor.heuristic";
  if (a.includes("mass")) return "mass_assignment.probe";
  if (a.includes("cache-control")) return "cache_control.missing_sensitive_get";
  return "security.test";
}
function toLevel(ruleId) {
  if (ruleId === "auth.missing" || ruleId === "idor.heuristic") return "error";
  if (ruleId === "mass_assignment.probe") return "warning";
  return "note";
}

const run = JSON.parse(await fs.readFile(RUN, "utf8"));
const sarifResults = [];

for (const e of run.run.executions || []) {
  const itemName = e.item?.name || "unknown";
  for (const a of e.assertions || []) {
    if (a.error) {
      const ruleId = guessRule(a.assertion);
      sarifResults.push({
        ruleId,
        level: toLevel(ruleId),
        message: { text: `${a.assertion}: ${a.error.message || "assertion failed"}` },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: `postman://${itemName}` },
            region: { startLine: 1, startColumn: 1 }
          }
        }],
        fingerprints: { postmanItem: itemName }
      });
    }
  }
}

const sarif = {
  $schema: "https://json.schemastore.org/sarif-2.1.0.json",
  version: "2.1.0",
  runs: [{
    tool: {
      driver: {
        name: "api-security-guardrail",
        rules: Object.values(RULES).map(r => ({
          id: r.id,
          shortDescription: { text: r.short },
          fullDescription: { text: r.short }
        }))
      }
    },
    results: sarifResults
  }]
};

await fs.writeFile(OUT, JSON.stringify(sarif, null, 2));
console.log(`✅ Wrote ${sarifResults.length} findings to ${OUT}`);
