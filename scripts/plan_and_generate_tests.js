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

// Build compact summary of endpoints from the collection
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
        name: it.name, folder: folder.join(" / "),
        method, path: pathOnly || raw, hasAuthHeader, pathParams
      });
    }
  };
  walk(coll.item, []);
  const uniq = new Map();
  for (const e of endpoints) uniq.set(`${e.method} ${e.path}`, e);
  return Array.from(uniq.values()).slice(0, 200);
}

async function main() {
  const baseCollection = JSON.parse(await fs.readFile(baseCollPath, "utf8"));
  const baseEnv = JSON.parse(await fs.readFile(baseEnvPath, "utf8"));

  const baseUrl = process.env.PR_BASEURL || envGet(baseEnv, "baseUrl", "http://localhost:8888");
  const policy = "Block on High; warn on Medium/Low.";
  const apiSummary = summarizeCollection(baseCollection);
  const recentChanges = process.env.PR_DIFF_SUMMARY || "(none)";

  const PROMPT_TEMPLATE = `
  <<<PROMPT>>>
  `.trim();

  // Paste the prompt from section 6 and replace these tokens:
  const PROMPT = PROMPT_TEMPLATE
    .replace("<<<PROMPT>>>", `You are an API security test planner. Goal: generate targeted, minimal, high-signal
tests for the API described below, mapped to OWASP API Security Top 10 (2023).

=== CONTEXT ===
- API summary (from Postman collection):
${api_summary}

- Recent PR changes (optional; may be empty):
${recent_changes}

- Execution base URL: ${url}

- Org policy: ${policy}

=== RULES & PRIORITIES ===
Use OWASP API Security Top 10 (2023) as your compass:
API1 Broken Object Level Authorization (BOLA)
API2 Broken Authentication
API3 Broken Object Property Level Authorization (BOPLA / mass-assign)
API4 Unrestricted Resource Consumption
API5 Broken Function Level Authorization (BFLA)
API6 Unrestricted Access to Sensitive Business Flows
API7 Server-Side Request Forgery (SSRF)
API8 Security Misconfiguration
API9 Improper Inventory Management
API10 Unsafe Consumption of APIs
Focus first on API1, API5, API3, API2, API8. Be surgical: prefer 3–12 tests.

=== TEST DESIGN GUIDELINES ===
- Prefer dynamic tests that prove risk with concrete assertions (status codes, headers,
  response fields, negative cases). Keep payloads minimal.
- DO NOT include secrets in outputs. Use placeholders referencing environment vars:
  {{user_token}}, {{admin_token}}, {{expired_token}}
- For auth/BOLA/BFLA:
  * Create variants: no token, user token, admin token, expired token.
  * For GET/PUT/DELETE /resource/{id}, try neighbor/foreign IDs (IDOR).
- For BOPLA (mass-assign):
  * POST/PUT/PATCH: inject extra fields like "role":"admin", "status":"APPROVED",
    or immutable/derived fields; expect they are ignored/rejected.
- For Misconfiguration:
  * On sensitive reads, assert Cache-Control includes "no-store".
  * Check security headers presence if relevant (optional).
- For rate/quotas (API4):
  * Small burst (3–10 rapid calls) and assert RateLimit-* / Retry-After
    (if the API claims limits). Keep load tiny to be CI-safe.
- For SSRF (API7):
  * Only suggest safe, inert SSRF checks (e.g., reject internal hostnames);
    do NOT probe internal networks.
- For sensitive business flows (API6):
  * If endpoints look like account takeover, password reset, create light tests that validate guardrails (e.g., OTP required).

=== OUTPUT FORMAT (STRICT JSON) ===
{
  "tests": [
    {
      "name": "short, descriptive",
      "owasp": "API1:2023",
      "risk": "high|medium|low",
      "request": {
        "method": "GET|POST|PUT|PATCH|DELETE",
        "path": "/path/with/{id}",
        "auth": "none|user|admin|expired",
        "headers": [{"key":"Authorization","value":"Bearer {{user_token}}"}],  // only if auth != none
        "body": { ... }   // omit if not needed
      },
      "assertions": [
        {"type":"status","op":"eq","value":403},
        {"type":"headerContains","key":"Cache-Control","value":"no-store"},
        {"type":"jsonPath","path":"$.status","op":"notEq","value":"APPROVED"}
      ],
      "notes": "why this proves/denies the risk; link to endpoint/folder if provided"
    }
  ]
}
- Keep to 3–12 tests. Choose the most promising endpoints for each risk class.
- Use concrete IDs or simple neighbor ids when path params are present (e.g., 1→2).
- Never echo secrets or real tokens. Rely on placeholders and environment variables.
`) 
    .replace("${api_summary}", JSON.stringify(apiSummary, null, 2))
    .replace("${recent_changes}", recentChanges)
    .replace("${policy}", policy)
    .replace("${base_url}", baseUrl);

  const res = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: PROMPT }],
    response_format: { type: "json_object" }
  });

  const plan = JSON.parse(res.choices[0].message.content);
  const tests = Array.isArray(plan.tests) ? plan.tests : [];

  const securityFolder = {
    name: "Security Tests",
    item: tests.map(t => {
      const headers = Array.isArray(t.request?.headers) ? t.request.headers : [];
      const bodyObj = t.request?.body;
      return {
        name: `[${t.owasp || "N/A"}][${t.risk || "low"}] ${t.name}`,
        request: {
          method: t.request?.method || "GET",
          url: { raw: `{{baseUrl}}${t.request?.path || "/"}` },
          header: headers,
          body: bodyObj ? { mode: "raw", raw: JSON.stringify(bodyObj) } : undefined
        },
        event: [{
          listen: "test",
          script: {
            exec: (t.assertions || []).map(a => {
              if (a.type === "status") {
                if (a.op === "eq")  return `pm.test("status == ${a.value}", ()=>pm.response.to.have.status(${a.value}))`;
                if (a.op === "not") return `pm.test("status != ${a.value}", ()=>pm.expect(pm.response.code).to.not.equal(${a.value}))`;
              }
              if (a.type === "headerContains") {
                return `pm.test("header ${a.key} contains ${a.value}", ()=>pm.expect(pm.response.headers.get("${a.key}")||"").to.include("${a.value}"))`;
              }
              if (a.type === "jsonPath") {
                const p = a.path.replace(/"/g,'\\"');
                if (a.op === "exists")   return `pm.test("jsonPath exists ${p}", ()=>pm.expect(_.get(pm.response.json(), "${p}")).to.not.equal(undefined))`;
                if (a.op === "eq")       return `pm.test("jsonPath eq ${p}", ()=>pm.expect(_.get(pm.response.json(), "${p}")).to.eql(${JSON.stringify(a.value)}))`;
                if (a.op === "notEq")    return `pm.test("jsonPath notEq ${p}", ()=>pm.expect(_.get(pm.response.json(), "${p}")).to.not.eql(${JSON.stringify(a.value)}))`;
                if (a.op === "notContains") return `pm.test("jsonPath notContains ${p}", ()=>pm.expect(String(_.get(pm.response.json(), "${p}")||"")).to.not.include("${a.value}"))`;
              }
              return `pm.test("no-op", ()=>pm.expect(true).to.be.true)`;
            })
          }
        }]
      }
    })
  };

  // Inject folder into PR-scoped copy
  const prCollection = JSON.parse(JSON.stringify(baseCollection));
  prCollection.item ||= [];
  prCollection.item.push(securityFolder);

  // Derive PR env
  const prEnv = JSON.parse(JSON.stringify(baseEnv));
  envSet(prEnv, "baseUrl", baseUrl);

  await fs.writeFile(prCollPath, JSON.stringify(prCollection, null, 2));
  await fs.writeFile(prEnvPath, JSON.stringify(prEnv, null, 2));
  console.log(`✅ Generated ${tests.length} generic security tests mapped to OWASP 2023.`);
}

main().catch(e => { console.error(e); process.exit(1); });
