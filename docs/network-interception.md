# Network interception

Redacting what AI apps send at the network level, rather than at the clipboard, drag or file
open: it also covers text typed in the app, and every way into it at once.

## Approach

- **Transparent proxy** (`NETransparentProxyProvider`, a Network Extension system extension) for
  the desktop apps: the only macOS hook that can _change_ traffic, is deployed and authorized by
  MDM with no user step (`com.apple.vpn.managed` with `VPNType = TransparentProxy`,
  `com.apple.system-extension-policy`), and does not depend on each app honouring proxy settings.
  Unlike Endpoint Security, its entitlement needs no approval from Apple. TLS is terminated with a
  Riot CA installed by MDM (`com.apple.security.root`), for the AI hosts only.
  - Same split as RiotES: the extension only hands flows over; TLS, HTTP, rewriting and
    detokenization live in the daemon, which a Windows redirect (WFP) can reuse.
  - Not a content filter (`NEFilterDataProvider`): it sees encrypted bytes and can only allow or
    drop. It fits blocking unauthorized AI services by server name, not redaction.
  - Not a system proxy or PAC file: many clients ignore them (see the ChatGPT finding below).
- **Local gateway** for API clients (CLIs, SDKs): the client's base URL points at the daemon
  (`ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`), which forwards over TLS. No certificate, no pinning
  question, and the API formats are documented. Implemented for the Anthropic API:
  [Local gateway](#local-gateway).
- The gateway's protocol adapters do not depend on how traffic reaches them. Until the
  transparent proxy exists, the gateway is also an `HTTPS_PROXY` for development, which
  terminates TLS the same way: [TLS termination](#tls-termination-https_proxy-entry). Behind
  it, the Responses API adapter covers Codex: [Responses API](#responses-api-codex-chatgpt).

## Measurements (Nov 2026, macOS 27.2)

Each client sent the same message with fake data (an email address and an IBAN) through
mitmproxy and a throwaway CA, removed afterwards. Versions: Claude Code 2.1.325, Codex CLI
0.167.0, Claude Desktop 5.11492.5, ChatGPT 26.1111.21308.

| Client         | How its traffic was routed                                                                                 | Accepts a CA from the system keychain                                                                                | Conversation format                                                                                           |
| -------------- | ---------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| Claude Code    | `HTTPS_PROXY`; or `ANTHROPIC_BASE_URL` to a plain-HTTP local endpoint, no CA                                | Yes (2.1.326, measured with the Riot CA); an untrusted CA needs `NODE_EXTRA_CA_CERTS`                                | JSON `POST /v1/messages`, SSE response                                                                        |
| Codex CLI      | `HTTPS_PROXY`                                                                                              | Yes                                                                                                                  | WebSocket `chatgpt.com/backend-api/codex/responses`, Responses API events                                     |
| Claude Desktop | `--proxy-server`                                                                                           | Yes. It refuses chains holding keys from a fixed list (`setCertificateVerifyProc`), and pins nothing                 | Binary protobuf over Connect RPC: `claude.ai/claudeai-rpc/…ConversationService/PerformAction`, `StreamTimeline` |
| ChatGPT        | The conversation goes through an embedded `codex` app server, which ignores the app's `--proxy-server`; it needed `HTTPS_PROXY` | Yes                                                                                                                  | The same WebSocket as Codex                                                                                   |

### Findings

1. **Interception has to be per process, descendants included, and by signature.** ChatGPT's
   conversation left directly while the app itself went through the proxy: the request is made
   by a child process (`Contents/Resources/codex-cli/CodexCLI.app`). The interactive Codex CLI
   goes further: it hands the conversation over a Unix socket to a background
   `codex app-server --managed-daemon` (in `~/.codex/packages/app-server-daemon/`, launched by
   launchd, not a descendant of the terminal), which calls the API itself. Only the signature
   (team `2DC432GLL2`) ties it to OpenAI: the transparent proxy must match signing team ids, as
   RiotES does, not only process trees.
2. **One CA in the keychain covers every client measured**, Claude Code included (2.1.326). No
   client pinned.
3. **Three protocols, not one:**
   - Anthropic Messages API, JSON and SSE (Claude Code);
   - Responses API events over a WebSocket (Codex and ChatGPT: one adapter, two products);
   - protobuf over Connect RPC (Claude Desktop). Its schema is unpublished but ships with the
     app: the message definitions (`anthropic.bard.api.v1alpha.*`) are in
     `Contents/Resources/ion-dist.asar`. Replacing text changes its length, and so every
     enclosing message's length: the message has to be re-encoded, not patched in place.
4. **Values are split across stream events**: `"OK jean"` then `".dupont@example.com"` in the
   Anthropic stream, six pieces in the Codex one. A token (`[EMAIL_1]`) will be split the same
   way, so the detokenizer holds back a possible token prefix until it is complete. The full text
   comes again in the closing events (`response.output_text.done`, `response.completed`, the
   last timeline item): they need detokenizing too.
5. **The prompt also travels in side requests.** ChatGPT sends a separate title-generation
   request carrying the user's message. Every request to the service must be handled, not only
   the conversation endpoint.
6. **Tokens must be stable for the whole conversation.** Claude Code resends the full history on
   every turn (and relies on prompt caching of that prefix); Codex resends history items as well
   as `previous_response_id`.
7. **Attachments.** Claude Desktop sends an attached `.txt` inline in the protobuf request
   (name, `text/plain`, content), so it can be redacted in flight. ChatGPT sends only the path;
   the model then reads the file locally through a tool, which RiotES covers.
8. **HTTP/3.** `claude.ai` and `ws.chatgpt.com` advertise `h3` (`Alt-Svc`). The transparent
   proxy must drop UDP 443 to these hosts to force TCP.
9. **The proxy sees credentials.** Claude Desktop's `bridge` WebSocket carried an OAuth token in
   its first message. Nothing in the proxy may log headers or bodies.

Not measured: whether Claude Desktop fetches history separately on reload. ChatGPT reads its
history from disk (`~/.codex/sessions`), not from the network.

## Plan

1. Measurements (above).
2. Local gateway for the Anthropic API, Claude Code first: small, reuses `redact` and
   `detokenize`, and proves streaming detokenization.
3. Transparent proxy and TLS termination for the desktop apps, one protocol adapter at a time
   (Responses over WebSocket covers ChatGPT and Codex), scoped to the protected apps:
   1. TLS termination in the daemon, behind a development `HTTPS_PROXY` entry (done, below);
   2. Responses over WebSocket (done for Codex CLI, below; the ChatGPT app is still to test);
   3. the `NETransparentProxyProvider` extension, which replaces the development entry (code
      and daemon side done, below; not run yet: it needs a signed build);
   4. protobuf over Connect RPC (Claude Desktop).

## Local gateway

`core/riot-daemon/src/gateway/`: the daemon listens on `127.0.0.1:7591` (`RIOT_GATEWAY_ADDR`,
loopback only) and forwards `/anthropic/*` to `https://api.anthropic.com/*` with the client's
own headers and credentials.

```sh
ANTHROPIC_BASE_URL=http://127.0.0.1:7591/anthropic claude
```

Under MDM, Claude Code takes it from its managed settings,
`/Library/Application Support/ClaudeCode/managed-settings.json`:

```json
{ "env": { "ANTHROPIC_BASE_URL": "http://127.0.0.1:7591/anthropic" } }
```

**Which requests.** A host is redacted when the active policy lists it in a service's
`api_hosts` ([parrot-agent-api.md](parrot-agent-api.md)); requests to other hosts, or with
monitoring off, pass through untouched. Only `POST /v1/messages` and
`/v1/messages/count_tokens` are rewritten; every other path is forwarded as is.

**What is redacted.** Every text sent upstream, not only the user's turns: the client keeps the
detokenized answers and resends them as history.

- `system`, and in every message: `text` blocks, `tool_result` contents, every string of
  `tool_use` / `server_tool_use` inputs, text `document` sources, titles and context.
- Not touched: `thinking` and `redacted_thinking` blocks (signed: the API rejects a thinking
  block that differs from what it produced, so they keep the tokens the model wrote), images,
  base64 pdfs, tool definitions.
- Not touched either: the head of `system` up to the last block cached with
  `scope: "global"`. That scope shares the prompt cache across every API user, so the client
  declares the text identical for everyone: its own fixed prompt, not user data. The API also
  rejects a global block whose preceding blocks changed (`cache_control.scope: "global" is only
  valid when every preceding block is also globally scoped`): Claude Code's identity line, "You
  are a Claude agent, built on Anthropic's Claude Agent SDK.", became `[NAME_7]` / `[NAME_8]`
  and every request failed. Claude Code sends this scope when it talks to `api.anthropic.com`,
  not to a custom base URL. The environment block that follows (paths, git status, the user's
  email) is not globally scoped and is redacted.

**What is detokenized.** SSE `text_delta` and `input_json_delta` (values JSON-escaped inside the
tool input), with a per-block detokenizer that holds back a possible token prefix and flushes it
before `content_block_stop`; non-streamed JSON responses alike. Thinking deltas are left as
they are.

**Tokens.** Scoped per credential (a hash of `x-api-key` or `Authorization`): over TCP the
gateway cannot tell which local user is calling, but a value only resolves for requests carrying
the credential that redacted it. Within a scope a value keeps its token, so a resent
conversation is byte-identical upstream and its prompt-cache prefix holds. Redacted texts are
cached per scope (4,096 entries): only new texts reach the engine, and only their detections are
reported, one report per request (`textRedacted` in the popup).

**Fail closed.** A request that cannot be checked is not sent and gets a Messages API error
(`400 invalid_request_error`, shown by Claude Code): a single text over 1 MiB, an engine error,
or a compressed request body. An unreachable API is a `502`.

### Seeing what leaves the gateway

`RIOT_GATEWAY_UPSTREAM` replaces `https://<host>` with a loopback URL, per host:
comma-separated `host=url` entries (a bare URL applies to every host, which only suits a single
API). Anything but loopback is refused: the gateway forwards the client's credentials. Put
mitmproxy there, one reverse mode per API host, no certificate needed:

```sh
mitmweb --mode reverse:https://api.anthropic.com@127.0.0.1:18081 \
        --mode reverse:https://chatgpt.com@127.0.0.1:18082          # UI on http://127.0.0.1:8081
RIOT_GATEWAY_UPSTREAM=api.anthropic.com=http://127.0.0.1:18081,chatgpt.com=http://127.0.0.1:18082 \
  dev/run-dev.sh
ANTHROPIC_BASE_URL=http://127.0.0.1:7591/anthropic claude
```

The `POST /v1/messages` request holds tokens (`[EMAIL_2]`, `[IBAN_1]`) where Claude Code shows
the values, and so does the raw answer. mitmweb also shows the `Authorization` header (and
ChatGPT's `chatgpt-account-id`): do not share its screens.

### Measured (Claude Code 2.1.325, Haiku)

- The answer comes back with the real values; the model sees tokens (asked to write an address
  backwards, it wrote `]2_LIAME[`); a `Write` tool call wrote the real address to disk.
- Cost: a first request (79 KB, Claude Code's system prompt included) takes 1.0 s to redact;
  the same texts again take 0 ms (cache). End to end, 4.9 s through the gateway on the first
  request against 3.7 s direct, then 3.8 s against 3.7 s.

### Limits

- **"Claude" is a person name to the engine.** Through the base URL, Claude Code's own prompt
  had "Claude Code" as `[NAME_4]` and "Claude Agent SDK" as `[NAME_2]`, along with other false
  positives ("mark specs"); the first report of a session counts these names. Its fixed prompt
  is now left alone when globally cached (above), but the same words in the rest of the request
  are still caught. The fix belongs in `sonar-detection`, shared with the extension.
- The model may comment on what it receives ("this looks like a masking marker"); once
  detokenized, the comment reads oddly.
- An OAuth token refresh changes the scope: the history is redacted and reported again once.
- Tokens written markdown-escaped (`\[EMAIL\_1\]`) are not detokenized in the stream.
- The engine has one thread: a large first request delays concurrent pastes and file scans.
- The base URL entry only knows the Anthropic API (`/anthropic`); the Responses API goes through
  the `HTTPS_PROXY` entry.
- **Nothing is protected before the first policy sync.** The daemon keeps the policy in memory
  only: after a restart, until parrot answers, no host is redacted and CONNECTs are tunnelled
  untouched (measured: a Claude Code request started with the daemon went out unredacted). The
  same holds for pastes and file opens. The last policy should be persisted and used at start.

## TLS termination (`HTTPS_PROXY` entry)

With `RIOT_DEV_PROXY=1` (on in `dev/run-dev.sh`), the gateway's port also answers `CONNECT`.
It stands in for the transparent proxy, which will hand the daemon the same flows; everything
after the TLS handshake is shared with the base URL entry.

- **Which connections.** A `CONNECT` to port 443 of a host the policy lists in `api_hosts` is
  answered with a certificate from the Riot CA, and its requests go through the same relay as
  `/anthropic/*` (redaction on `/v1/messages`, other paths as they are). Any other `CONNECT`, or
  any host when monitoring is off, is a plain tunnel: nothing is decrypted.
- **The CA.** `gateway-ca.pem` and `gateway-ca-key.pem` (mode `0600`) in the data directory,
  created at first start, valid one year. It is name-constrained to `anthropic.com`,
  `claude.ai`, `openai.com` and `chatgpt.com` (critical `nameConstraints`, `pathlen:0`): even
  with its key, nothing it signs is valid for another site. A policy host outside these domains
  is refused (`400`), not tunnelled unchecked.
- **Leaves.** One P-256 key per daemon run, a certificate per host valid 7 days, reissued after
  a day; ALPN offers `http/1.1` only.

```sh
dev/run-dev.sh
HTTPS_PROXY=http://127.0.0.1:7591 NODE_EXTRA_CA_CERTS=$TMPDIR/riot-dev/gateway-ca.pem claude
```

`RIOT_GATEWAY_UPSTREAM` applies here too, to see what leaves the gateway.

### Measured (Claude Code 2.1.326, Haiku)

- Claude Code accepted the Riot CA, name constraints included, both through
  `NODE_EXTRA_CA_CERTS` and, with no variable, from the login keychain (trusted for the test,
  then removed). Its requests to `api.anthropic.com` went through it; Datadog and
  `mcp-proxy.anthropic.com` went through tunnels.
- Upstream, `/v1/messages` held tokens and neither the email nor the IBAN; the identity line
  arrived unchanged. The client printed the real email; asked to write it backwards, the model
  answered that it only saw a placeholder.
- The other requests to `api.anthropic.com` (`/api/event_logging/v2/batch` up to 548 KB,
  `/api/eval/…`, `/api/oauth/…`) are forwarded as is: in this run none held the prompt's email
  or a token.

### To decide: the CA in production

The development CA lives on the machine that uses it, and is trusted by hand. Under MDM, the CA
certificate is pushed by a profile (`com.apple.security.root`), so it is known in advance and
the same for every device, while its key must not be shared by every device. One shape: a root
per organization, kept by parrot, in the MDM profile; each daemon generates its key, sends a
CSR, and gets back an intermediate CA, name-constrained to the AI domains, whose key never
leaves the Mac.

## Responses API (Codex, ChatGPT)

`core/riot-daemon/src/gateway/responses.rs` and `websocket.rs`. On a host the policy lists
(`chatgpt.com` for the `openai` service in the stub), any path ending in `/responses` is
rewritten: Codex's WebSocket (`GET /backend-api/codex/responses`, upgraded) and its HTTPS
transport (`POST`, SSE). Other WebSockets on the host are relayed message by message, untouched.

```sh
HTTPS_PROXY=http://127.0.0.1:7591 SSL_CERT_FILE=<system roots + gateway-ca.pem> codex --no-daemon
```

`--no-daemon` keeps the conversation in the CLI process: otherwise it goes through the
background app-server daemon (finding 1), which never saw these variables. `codex exec` runs in
process.

(`SSL_CERT_FILE` replaces Codex's roots: build it from
`security find-certificate -a -p /System/Library/Keychains/SystemRootCertificates.keychain` and
the Riot CA. With the CA in the keychain, nothing is needed.)

**WebSocket.** The handshake goes upstream with the client's headers, so the upstream's
`Sec-WebSocket-Accept` answers the client's key; `Sec-WebSocket-Extensions` is dropped, so no
compression is negotiated and every message can be read. A refused handshake (`401`…) is
relayed as is. Pings are answered on each side; binary messages from the client are dropped
(none seen: they could not be checked).

**What is redacted.** In each `response.create` (a WebSocket message, or the HTTP body):
`instructions` and every string of `input`, walked generically so that item types Codex adds
later are covered, except under keys that hold identifiers or opaque data (`id`, `call_id`,
`role`, `name`, `encrypted_content`, `internal_chat_message_metadata_passthrough`, image and
file data…). `additional_tools` items (tool definitions) are skipped. A function call's
`arguments` is JSON in a string: each string inside is redacted, and it is re-serialized only
when something changed. Other client messages pass as they are (only `response.create` seen).

With `previous_response_id`, Codex sends only the new items (the user's message, tool outputs);
the rest of the conversation stays on the server, which only ever saw tokens.

**What is detokenized.** Every `*.delta` event goes through a detokenizer of its own (by type,
item and part); any other event of the same item flushes what it held back first, as a delta.
Every other event has its tokens replaced in every string, so the full text is fixed wherever
it comes back (`output_text.done`, `content_part.done`, `output_item.done`,
`response.completed`). Function call arguments are JSON-escaped; the input of a freeform tool
(`exec`, whose input is JavaScript code; patches) is written as is.

**Refusals.** A request that cannot be checked gets, instead of being sent,
`{"type":"error","status":400,"error":{"code":"riot_blocked","message":…}}`, which Codex shows
as a final error. A `response.failed` was tried first: Codex took it for a broken stream,
retried five times, then fell back to HTTPS.

**HTTPS transport.** Codex compresses that request body with zstd: the gateway decompresses it
(32 MiB at most), sends it on uncompressed, and refuses any other encoding. The SSE answer has
no `Content-Type`: on a rewritten path, a response without one is read as SSE (anything that is
not an event passes unchanged).

### Measured (Codex CLI 0.167.0)

- Asked for its email, its IBAN, `echo` of the email and the email backwards: the model wrote
  `]1_LIAME[`, the `exec` tool ran `echo 'jean.dupont@example.com'`, and Codex printed the real
  values. Upstream (mitmproxy behind the gateway), no message held the email or the IBAN.
- The first `response.create` of a session is 88 KB (Codex's prompt as developer messages);
  4.2 s to redact in a debug build, then only new texts.
- Same answer over the HTTPS transport (a provider with `supports_websockets = false`).
- The other requests to `chatgpt.com` (plugins, MCP, `analytics-events`) are forwarded as is: in
  these runs none held the email.

### Limits

- A false positive in Codex's own prompt: a numeric directory in skill paths
  (`spreadsheets/<number>/skills`) becomes `[PHONE_1]`. A command the model writes with it is
  detokenized before it runs.
- A value written into the `exec` tool's code is inserted as is: one holding a quote would break
  the string literal around it.
- The ChatGPT app is not tested yet: its title-generation request (finding 5) and its own
  WebSocket hosts (`ws.chatgpt.com`) are still to look at.

## Network extension (`apple/RiotNE`)

`com.tryriot.agent.network.systemextension`, a `NETransparentProxyProvider` in Riot.app
(`WITH_NE=1 apple/build-app.sh`), activated by Riot.app like RiotES, configured by the MDM
profile (`com.apple.vpn.managed`, `VPNType` `TransparentProxy`).

- **Which flows.** The system hands it every outbound TCP and UDP flow to port 443. It claims
  those whose process belongs to a protected app: the signing team id from the flow's audit
  token, or the executable's folder for apps without one (the daemon's `esConfig`, as RiotES).
  A flow is not claimed by process tree: Codex's app-server daemon is launched by launchd.
  Other processes' flows, and every flow while the daemon is unreachable, are left to the
  system.
- **TCP.** A claimed flow becomes a CONNECT on `flows.sock` (next to the daemon's socket, mode
  `0600`, root or the daemon's user only), to the name the app asked for when the system knows
  it, else to the address. The flow is opened once the daemon answers `200`, then bytes go both
  ways. `Riot-App` names the process for the daemon's log.
- **The daemon's side** is the `HTTPS_PROXY` entry's: it reads the ClientHello, decrypts when
  its server name (or the CONNECT host without one) is a policy host, drops the connection when
  the CA cannot cover that host or the traffic to it is not TLS, and otherwise tunnels to the
  CONNECT target, replaying the bytes it read. Ports other than 443 are tunnelled without a look.
- **UDP.** A claimed flow is opened and closed: QUIC fails and the app falls back to TCP
  (finding 8).
- **Signing.** The `app-proxy-provider-systemextension` value of
  `com.apple.developer.networking.networkextension`, and the app group its `NEMachServiceName`
  is prefixed with, come with a Developer ID provisioning profile with the Network Extensions
  capability: any team can create one, no request to Apple. Riot.app needs
  `com.apple.developer.system-extension.install` to activate it, in the same way. Both
  signatures also carry `com.apple.application-identifier` and
  `com.apple.developer.team-identifier` (Xcode adds them), which tie them to their profiles.
- **Logs.** `log stream --predicate 'subsystem == "com.tryriot.agent.network"'`: each claimed
  flow (app, process, `host:port`) and each failure. NSLog's arguments show as `<private>` in a
  system extension, so the extension logs through `os.Logger` with public fields that carry
  no content.

### Run in a VM

Signed with a test team (`APP_ID=… TEAM_ID=… BUILD_NUMBER=… WITH_NE=1
NE_PROVISIONING_PROFILE=… APP_PROVISIONING_PROFILE=… apple/build-app.sh`), on macOS 26 in
the VM of `docs/es-vm.md`, without notarization and without `systemextensionsctl developer
on`. The profile's payloads that need an MDM (extension policy, TCC, service management) are
replaced by a manual approval of the extension in System Settings; the transparent proxy
payload installs from a manual profile.

- **The payload.** `NEConfiguration` rejects it ("The VPN service could not be created",
  `unsupported authen type (null)` in mdmclient's log) without `AuthenticationMethod`, though
  nothing authenticates. Installed, the session stays idle until something starts it:
  `OnDemandEnabled` with a single `Connect` rule keeps it running.
- **An update.** A new extension with the same `CFBundleVersion` is not taken; with a higher
  one (`BUILD_NUMBER`), Riot.app's activation request replaces the running one without a prompt.
- **Claude Code** (2.1.326, logged in, no `HTTPS_PROXY`): its flows to `api.anthropic.com`
  are claimed by team id, decrypted and redacted; its other hosts (`mcp-proxy.anthropic.com`,
  Datadog, `downloads.claude.ai`) are tunnelled. A flow to a bare IPv6 address was routed by
  its ClientHello to `api.anthropic.com` and decrypted.
- **Codex CLI** (0.169.0, logged in, without `--no-daemon`): the launchd-started `codex
  app-server` is claimed by team id; its Responses WebSocket to `chatgpt.com` is decrypted and
  rewritten; `ab.chatgpt.com`, `auth.openai.com` and the `oaiusercontent.com` CDNs are
  tunnelled.
- **False positives** in the apps' own prompts, as names: "Claude Code", "Claude Opus",
  "Claude Agent", spans such as "Claude Tag (Claude" or a whole Markdown link to
  `claude.com/claude-code`, "mark specs"; in Codex's, "Atkinson Hyperlegible Next" (a font)
  and "Skip action". For sonar-detection.
- **Other processes'** flows (Apple's daemons, TCP and QUIC) are rejected by the extension and
  go out untouched. Some claimed flows are aborted by the app before the daemon answers: the
  losers of its parallel IPv4/IPv6 connects.

To check: the ChatGPT app (its title request, `ws.chatgpt.com`), Claude Desktop (step 4), the
fallback from QUIC, and the daemon down.

