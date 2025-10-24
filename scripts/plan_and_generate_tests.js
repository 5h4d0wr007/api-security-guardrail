import fs from "fs/promises";
import path from "path";
import OpenAI from "openai";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const REPO = process.cwd();

const baseCollPath = path.join(REPO, "postman/base.collection.json");
const baseEnvPath  = path.join(REPO, "postman/base.environment.json");
const prCollPath   = path.join(REPO, "postman/pr.collection.json");
const prEnvPath    = path.join(REPO, "postman/pr.environment.json");

function envGet(env, key, def="") {
  const v = (env.values || []).find(x => x.key === key);
  return (v && v.value !== undefined) ? v.value : def;
}
function envSet(env, key, value) {
  env.values ||= [];
  const idx = env.values.findIndex(v => v.key === key);
  if (idx >= 0) { env.values[idx].value = value; env.values[idx].enabled = true; }
  else env.values.push({ key, value, enabled: true });
}

function summarizeCollection(coll) {
  const endpoints = [];
  const walk = (items, folder=[]) => {
    for (const it of items || []) {
      if (it.item) { walk(it.item, folder.concat(it.name || "Folder")); continue; }
      if (!it.request) continue;
      const r = it.request;
      const method = (r.method || "GET").toUpperCase();
      const raw = typeof r.url === "string" ? r.url : (r.url?.raw || "");
      const pathOnly = raw.replace(/^https?:\/\/[^/]+/i, "").replace(/\{\{[^}]+\}\}/g, "{}");
      const hasAuthHeader = (r.header || []).some(h => /^authorization$/i.test(h.key));
      const pathParams = (r.url?.variable || []).map(v => v.key);
      endpoints.push({
        name: it.name,
        folder: folder.join(" / "),
        method,
        path: pathOnly || raw,
        hasAuthHeader,
        pathParams
      });
    }
  };
  walk(coll.item, []);
  const uniq = new Map();
  for (const e of endpoints) uniq.set(e.method + " " + e.path, e);
  return Array.from(uniq.values()).slice(0, 200);
}

async function main() {
  const baseCollection = JSON.parse(await fs.readFile(baseCollPath, "utf8"));
  const baseEnv = JSON.parse(await fs.readFile(baseEnvPath, "utf8"));

  const baseUrl = process.env.PR_BASEURL || envGet(baseEnv, "baseUrl", "http://localhost:8888");
  const policy = "Block on High; warn on Medium/Low.";
  const apiSummary = summarizeCollection(baseCollection);
  const recentChanges = process.env.PR_DIFF_SUMMARY || "(none)";

  // Build prompt via concatenation only (NO backticks), and assert no ${ sneaks in.
  const prompt =
    "You are an API security test planner. Goal: generate targeted, minimal, high-signal\n" +
    "tests for the API described below, mapped to OWASP API Security Top 10 (2023).\n\n" +
    "=== CONTEXT ===\n" +
    "- API summary (from Postman collection):\n" +
    JSON.stringify(apiSummary, null, 2) + "\n\n" +
    "- Recent PR changes (optional; may be empty):\n" +
    recentChanges + "\n\n" +
    "- Execution base URL: " + baseUrl + "\n\n" +
    "- Org policy: " + policy + "\n\n" +
    "=== RULES & PRIORITIES ===\n" +
    "Use OWASP API Security Top 10 (2023) as your compass:\n" +
    "API1 Broken Object Level Authorization (BOLA)\n" +
    "API2 Broken Authentication\n" +
    "API3 Broken Object Property Level Authorization (BOPLA / mass-assign)\n" +
    "API4 Unrestricted Resource Consumption\n" +
    "API5 Broken Function Level Authorization (BFLA)\n" +
    "API6 Unrestricted Access to Sensitive Business Flows\n" +
    "API7 Server-Side Request Forgery (SSRF)\n" +
    "API8 Security Misconfiguration\n" +
    "API9 Improper Inventory Management\n" +
    "API10 Unsafe Consumption of APIs\n" +
    "Focus first on API1, API5, API3, API2, API8. Be surgical: prefer 3–12 tests.\n\n" +
    "=== TEST DESIGN GUIDELINES ===\n" +
    "- Prefer dynamic tests that prove risk with concrete assertions (status codes, headers,\n" +
    "  response fields, negative cases). Keep payloads minimal.\n" +
    "- DO NOT include secrets in outputs. Use placeholders referencing environment vars:\n" +
    "  {{user_token}}, {{admin_token}}, {{expired_token}}\n" +
    "- For auth/BOLA/BFLA:\n" +
    "  * Create variants: no token, user token, admin token, expired token.\n" +
    "  * For GET/PUT/DELETE /resource/{id}, try neighbor/foreign IDs (IDOR).\n" +
    "- For BOPLA (mass-assign):\n" +
    "  * POST/PUT/PATCH: inject extra fields like \"role\":\"admin\", \"status\":\"APPROVED\",\n" +
    "    or immutable/derived fields; expect they are ignored/rejected.\n" +
    "- For Misconfiguration:\n" +
    "  * On sensitive reads, assert Cache-Control includes \"no-store\".\n" +
    "  * Check security headers presence if relevant (optional).\n" +
    "- For rate/quotas (API4):\n" +
    "  * Small burst (3–10 rapid calls) and assert RateLimit-* / Retry-After\n" +
    "    (if the API claims limits). Keep load tiny to be CI-safe.\n" +
    "- For SSRF (API7):\n" +
    "  * Only suggest safe, inert SSRF checks (e.g., reject internal hostnames);\n" +
    "    do NOT probe internal networks.\n" +
    "- For sensitive business flows (API6):\n" +
    "  * If endpoints look like account takeover, password reset, coupon abuse,\n" +
    "    create light tests that validate guardrails (e.g., OTP required).\n\n" +
    "=== OUTPUT FORMAT (STRICT JSON) ===\n" +
    "{\n" +
    "  \"tests\": [\n" +
    "    {\n" +
    "      \"name\": \"short, descriptive\",\n" +
    "      \"owasp\": \"API1:2023\",\n" +
    "      \"risk\": \"high|medium|low\",\n" +
    "      \"request\": {\n" +
    "        \"method\": \"GET|POST|PUT|PATCH|DELETE\",\n" +
    "        \"path\": \"/path/with/{id}\",\n" +
    "        \"auth\": \"none|user|admin|expired\",\n" +
    "        \"headers\": [{\"key\":\"Authorization\",\"value\":\"Bearer {{user_token}}\"}],\n" +
    "        \"body\": { }\n" +
    "      },\n" +
    "      \"assertions\": [\n" +
    "        {\"type\":\"status\",\"op\":\"eq\",\"value\":403},\n" +
    "        {\"type\":\"headerContains\",\"key\":\"Cache-Control\",\"value\":\"no-store\"},\n" +
    "        {\"type\":\"jsonPath\",\"path\":\"$.status\",\"op\":\"notEq\",\"value\":\"APPROVED\"}\n" +
    "      ],\n" +
    "      \"notes\": \"why this proves/denies the risk\"\n" +
    "    }\n" +
    "  ]\n" +
    "}\n" +
    "- Keep to 3–12 tests. Choose the most promising endpoints for each risk class.\n" +
    "- Use concrete IDs or simple neighbor ids when path params are present (e.g., 1→2).\n" +
    "- Never echo secrets or real tokens. Rely on placeholders and environment variables.\n";

  if (prompt.indexOf("${") !== -1) {
    throw new Error("Prompt contains '${...}'. Remove any template-literal placeholders.");
  }

  const res = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: prompt }],
    response_format: { type: "json_object" }
  });

  const plan = JSON.parse(res.choices[0].message.content || "{}");
  const tests = Array.isArray(plan.tests) ? plan.tests : [];

  const securityFolder = {
    name: "Security Tests",
    item: tests.map(t => {
      const headers = Array.isArray(t.request?.headers) ? t.request.headers : [];
      const bodyObj = t.request?.body;
      return {
        name: "[" + (t.owasp || "N/A") + "][" + (t.risk || "low") + "] " + t.name,
        request: {
          method: t.request?.method || "GET",
          url: { raw: "{{baseUrl}}" + (t.request?.path || "/") },
          header: headers,
          body: bodyObj ? { mode: "raw", raw: JSON.stringify(bodyObj) } : undefined
        },
        event: [{
          listen: "test",
          script: {
            exec: (t.assertions || []).map(a => {
              if (a.type === "status") {
                if (a.op === "eq")  return "pm.test(\"status == " + a.value + "\", function(){ pm.response.to.have.status(" + a.value + "); });";
                if (a.op === "not") return "pm.test(\"status != " + a.value + "\", function(){ pm.expect(pm.response.code).to.not.equal(" + a.value + "); });";
              }
              if (a.type === "headerContains") {
                return "pm.test(\"header " + a.key + " contains " + a.value + "\", function(){ pm.expect(pm.response.headers.get(\"" + a.key + "\")||\"\").to.include(\"" + a.value + "\"); });";
              }
              if (a.type === "jsonPath") {
                const p = String(a.path || "").replace(/"/g,'\\"');
                const val = JSON.stringify(a.value);
                if (a.op === "exists")      return "pm.test(\"jsonPath exists " + p + "\", function(){ var j=pm.response.json(); pm.expect(_.get(j, \"" + p + "\")).to.not.equal(undefined); });";
                if (a.op === "eq")          return "pm.test(\"jsonPath eq " + p + "\", function(){ var j=pm.response.json(); pm.expect(_.get(j, \"" + p + "\")).to.eql(" + val + "); });";
                if (a.op === "notEq")       return "pm.test(\"jsonPath notEq " + p + "\", function(){ var j=pm.response.json(); pm.expect(_.get(j, \"" + p + "\")).to.not.eql(" + val + "); });";
                if (a.op === "notContains") return "pm.test(\"jsonPath notContains " + p + "\", function(){ var j=pm.response.json(); var s = String(_.get(j, \"" + p + "\")||\"\"); pm.expect(s).to.not.include(\"" + a.value + "\"); });";
              }
              return "pm.test(\"no-op\", function(){ pm.expect(true).to.be.true; });";
            })
          }
        }]
      };
    })
  };

  const prCollection = JSON.parse(JSON.stringify(baseCollection));
  prCollection.item ||= [];
  prCollection.item.push(securityFolder);

  const prEnv = JSON.parse(JSON.stringify(baseEnv));
  envSet(prEnv, "baseUrl", baseUrl);

  await fs.writeFile(prCollPath, JSON.stringify(prCollection, null, 2));
  await fs.writeFile(prEnvPath, JSON.stringify(prEnv, null, 2));

  console.log("✅ Generated " + tests.length + " generic security tests mapped to OWASP 2023.");
}

main().catch(e => { console.error(e); process.exit(1); });
