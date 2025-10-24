// scripts/plan_and_generate_tests.js
import fs from "fs/promises";
import path from "path";
import OpenAI from "openai";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const REPO = process.cwd();

const baseCollPath = path.join(REPO, "postman/base.collection.json");
const baseEnvPath  = path.join(REPO, "postman/base.environment.json");
const prCollPath   = path.join(REPO, "postman/pr.collection.json");
const prEnvPath    = path.join(REPO, "postman/pr.environment.json");
const promptPath   = path.join(REPO, "scripts/planner_prompt.txt");

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

  // Load prompt text from file
  let prompt = await fs.readFile(promptPath, "utf8");

  // Hard guard: fail fast if any ${ is present (would cause your earlier error)
  if (prompt.includes("${")) {
    throw new Error("Planner prompt contains '${...}'. Replace with custom tokens like __API_SUMMARY__.");
  }

  // Fill tokens
  prompt = prompt
    .replaceAll("__API_SUMMARY__", JSON.stringify(apiSummary, null, 2))
    .replaceAll("__RECENT_CHANGES__", recentChanges)
    .replaceAll("__BASE_URL__", baseUrl)
    .replaceAll("__POLICY__", policy);

  const res = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: prompt }],
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
                if (a.op === "exists")        return `pm.test("jsonPath exists ${p}", ()=>pm.expect(_.get(pm.response.json(), "${p}")).to.not.equal(undefined))`;
                if (a.op === "eq")            return `pm.test("jsonPath eq ${p}", ()=>pm.expect(_.get(pm.response.json(), "${p}")).to.eql(${JSON.stringify(a.value)}))`;
                if (a.op === "notEq")         return `pm.test("jsonPath notEq ${p}", ()=>pm.expect(_.get(pm.response.json(), "${p}")).to.not.eql(${JSON.stringify(a.value)}))`;
                if (a.op === "notContains")   return `pm.test("jsonPath notContains ${p}", ()=>pm.expect(String(_.get(pm.response.json(), "${p}")||"")).to.not.include("${a.value}"))`;
              }
              return `pm.test("no-op", ()=>pm.expect(true).to.be.true)`;
            })
          }
        }]
      };
    })
  };

  // Inject into PR-scoped copies
  const prCollection = JSON.parse(JSON.stringify(baseCollection));
  prCollection.item ||= [];
  prCollection.item.push(securityFolder);

  const prEnv = JSON.parse(JSON.stringify(baseEnv));
  envSet(prEnv, "baseUrl", baseUrl);

  await fs.writeFile(prCollPath, JSON.stringify(prCollection, null, 2));
  await fs.writeFile(prEnvPath, JSON.stringify(prEnv, null, 2));
  console.log(`✅ Generated ${tests.length} generic security tests mapped to OWASP 2023.`);
}

main().catch(e => { console.error(e); process.exit(1); });
