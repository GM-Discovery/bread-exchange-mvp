"use strict";

const http = require("http");
const https = require("https");

const BASE = String(process.env.SMOKE_BASE_URL || "http://127.0.0.1:8787").replace(/\/+$/, "");
const OPERATOR_KEY = String(process.env.SMOKE_OPERATOR_KEY || "");

function getJson(pathname, headers = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(BASE + pathname);
    const mod = url.protocol === "https:" ? https : http;
    const req = mod.request(
      {
        protocol: url.protocol,
        hostname: url.hostname,
        port: url.port || (url.protocol === "https:" ? 443 : 80),
        path: url.pathname + (url.search || ""),
        method: "GET",
        headers,
      },
      (res) => {
        let body = "";
        res.on("data", (c) => (body += c));
        res.on("end", () => {
          let json = null;
          try { json = JSON.parse(body); } catch (_) {}
          resolve({ status: Number(res.statusCode || 0), json, body });
        });
      }
    );
    req.on("error", reject);
    req.end();
  });
}

async function run() {
  const checks = [
    { path: "/api/health", ok: (r) => r.status === 200 && r.json && r.json.ok === true },
    { path: "/api/polls", ok: (r) => r.status === 200 && r.json && Array.isArray(r.json.polls) },
    { path: "/federation/status", ok: (r) => r.status === 200 && r.json && r.json.ok === true },
  ];

  for (const c of checks) {
    const r = await getJson(c.path);
    if (!c.ok(r)) {
      throw new Error(`Smoke failed: GET ${c.path} status=${r.status} body=${String(r.body).slice(0, 300)}`);
    }
  }

  if (OPERATOR_KEY) {
    const r = await getJson("/api/discovery/status", { "X-Operator-Key": OPERATOR_KEY });
    if (!(r.status === 200 && r.json && r.json.ok === true)) {
      throw new Error(`Smoke failed: GET /api/discovery/status status=${r.status} body=${String(r.body).slice(0, 300)}`);
    }
  } else {
    console.log("Skipping /api/discovery/status smoke (SMOKE_OPERATOR_KEY not set).");
  }

  console.log(`API smoke passed against ${BASE}`);
}

run().catch((e) => {
  console.error(e && e.message ? e.message : e);
  process.exit(1);
});

