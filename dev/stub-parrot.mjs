// A stand-in for parrot's /api/agent/* endpoints (see docs/parrot-agent-api.md), for local runs.
//   node dev/stub-parrot.mjs [port]       GET /portal/_stub/state shows devices, heartbeats, reports
// Env: STUB_MONITORING=0 (policy disabled), STUB_NO_EMPLOYEE=1, STUB_NO_BYPASS=1.
import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";

const port = Number(process.argv[2] ?? 8787);
const WORKSPACE_ID = "ws-dev";
const SECRET = "rbx_dev";
const devices = new Map(); // token -> device
const reports = new Map(); // session_id -> report (upsert, like parrot)
const heartbeats = [];

// The policy every device gets, shared with the stub the fleet package bundles
// (core/riot-daemon/src/bin/stub_parrot.rs).
const basePolicy = JSON.parse(
  readFileSync(new URL("./stub-policy.json", import.meta.url), "utf8"),
);
const policy = () => ({
  ...basePolicy,
  enabled: process.env.STUB_MONITORING !== "0",
  allow_bypass_redaction: process.env.STUB_NO_BYPASS !== "1",
});

const json = (res, status, body) => {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(body === undefined ? "" : JSON.stringify(body));
};
const bearer = (req) =>
  (req.headers.authorization ?? "").replace(/^Bearer /, "");
const readBody = (req) =>
  new Promise((ok) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => ok(b ? JSON.parse(b) : null));
  });

createServer(async (req, res) => {
  const url = new URL(req.url, "http://x");
  const body = req.method === "POST" ? await readBody(req) : null;
  const log = (what) =>
    console.log(new Date().toISOString(), req.method, url.pathname, what ?? "");

  if (url.pathname === "/portal/_stub/state")
    return json(res, 200, {
      devices: [...devices.values()],
      heartbeats: heartbeats.slice(-5),
      reports: [...reports.values()],
    });

  if (url.pathname === "/portal/api/agent/enroll" && req.method === "POST") {
    if (
      bearer(req) !== SECRET ||
      req.headers["x-workspace-id"] !== WORKSPACE_ID
    ) {
      log("401");
      return json(res, 401, { error: "unauthenticated" });
    }
    const device = {
      device_id: randomUUID(),
      ...body,
      enrolled_at: new Date().toISOString(),
    };
    const token = `rad_${randomUUID().replaceAll("-", "")}`;
    devices.set(token, device);
    log(
      `device ${device.device_id} ${body.hostname} ${body.employee_email ?? "(no email)"}`,
    );
    return json(res, 200, { device_id: device.device_id, device_token: token });
  }

  const device = devices.get(bearer(req));
  if (url.pathname.startsWith("/portal/api/agent/") && !device) {
    log("401");
    return json(res, 401, { error: "unauthenticated" });
  }

  if (url.pathname === "/portal/api/agent/config" && req.method === "GET") {
    log();
    const redactions = [...reports.values()].filter(
      (r) => r.text?.redacted,
    ).length;
    return json(res, 200, {
      employee:
        process.env.STUB_NO_EMPLOYEE === "1"
          ? null
          : {
              id: "emp-1",
              name: "Camille Martin",
              emails: [device.employee_email ?? "camille.martin@example.com"],
              redactions_last_30_days: 12 + redactions,
              locale: "fr",
            },
      workspace: {
        id: WORKSPACE_ID,
        branding_name: "Acme",
        logo_url: null,
        portal_url: "https://portal.example.com",
        default_locale: "fr",
        bot_branding: { name: "Albert", icon_url: "https://content.tryriot.com/Course/albert-avatar.png" },
      },
      policies: [policy()],
    });
  }
  if (url.pathname === "/portal/api/agent/heartbeat" && req.method === "POST") {
    heartbeats.push({
      device_id: device.device_id,
      at: new Date().toISOString(),
      ...body,
    });
    log(JSON.stringify(body.components));
    return json(res, 204);
  }
  if (
    url.pathname === "/portal/api/agent/sensitive_data_report" &&
    req.method === "POST"
  ) {
    if (!body?.session_id || !body?.service_id)
      return json(res, 422, { error: "invalid" });
    reports.set(body.session_id, { device_id: device.device_id, ...body });
    log(
      JSON.stringify({
        service: body.service_id,
        text: body.text,
        files: body.files,
      }),
    );
    return json(res, 200, { recorded: true });
  }
  log("404");
  json(res, 404, { error: "not found" });
}).listen(port, "127.0.0.1", () =>
  console.log(`stub parrot on http://127.0.0.1:${port}/portal`),
);
