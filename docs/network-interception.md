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

## Measurements (Nov 2026, macOS 27.2)

Each client sent the same message with fake data (an email address and an IBAN) through
mitmproxy and a throwaway CA, removed afterwards. Versions: Claude Code 2.1.325, Codex CLI
0.167.0, Claude Desktop 5.11492.5, ChatGPT 26.1111.21308.

| Client         | How its traffic was routed                                                                                 | Accepts a CA from the system keychain                                                                                | Conversation format                                                                                           |
| -------------- | ---------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| Claude Code    | `HTTPS_PROXY`; or `ANTHROPIC_BASE_URL` to a plain-HTTP local endpoint, no CA                                | Its own store: rejects the CA unless given `NODE_EXTRA_CA_CERTS` (keychain trust not measured)                       | JSON `POST /v1/messages`, SSE response                                                                        |
| Codex CLI      | `HTTPS_PROXY`                                                                                              | Yes                                                                                                                  | WebSocket `chatgpt.com/backend-api/codex/responses`, Responses API events                                     |
| Claude Desktop | `--proxy-server`                                                                                           | Yes. It refuses chains holding keys from a fixed list (`setCertificateVerifyProc`), and pins nothing                 | Binary protobuf over Connect RPC: `claude.ai/claudeai-rpc/…ConversationService/PerformAction`, `StreamTimeline` |
| ChatGPT        | The conversation goes through an embedded `codex` app server, which ignores the app's `--proxy-server`; it needed `HTTPS_PROXY` | Yes                                                                                                                  | The same WebSocket as Codex                                                                                   |

### Findings

1. **Interception has to be per process, descendants included.** ChatGPT's conversation left
   directly while the app itself went through the proxy: the request is made by a child process
   (`Contents/Resources/codex-cli/CodexCLI.app`). The transparent proxy must match the app and
   its descendants, as RiotES does.
2. **One CA in the system keychain covers the desktop apps and Codex.** No client pinned. Claude
   Code keeps its own store; the gateway avoids the question.
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
   (Responses over WebSocket covers ChatGPT and Codex), scoped to the protected apps.

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

`RIOT_GATEWAY_UPSTREAM` replaces `https://api.anthropic.com` with a loopback URL (anything else
is refused: the gateway forwards the client's credentials). Put mitmproxy there in reverse mode,
no certificate needed:

```sh
mitmweb --mode reverse:https://api.anthropic.com@18081        # UI on http://127.0.0.1:8081
RIOT_GATEWAY_UPSTREAM=http://127.0.0.1:18081 dev/run-dev.sh
ANTHROPIC_BASE_URL=http://127.0.0.1:7591/anthropic claude
```

The `POST /v1/messages` request holds tokens (`[EMAIL_2]`, `[IBAN_1]`) where Claude Code shows
the values, and so does the raw answer. mitmweb also shows the `Authorization` header: do not
share its screens.

### Measured (Claude Code 2.1.325, Haiku)

- The answer comes back with the real values; the model sees tokens (asked to write an address
  backwards, it wrote `]2_LIAME[`); a `Write` tool call wrote the real address to disk.
- Cost: a first request (79 KB, Claude Code's system prompt included) takes 1.0 s to redact;
  the same texts again take 0 ms (cache). End to end, 4.9 s through the gateway on the first
  request against 3.7 s direct, then 3.8 s against 3.7 s.

### Limits

- **"Claude" is a person name to the engine.** In Claude Code's own prompt, "Claude Code"
  becomes `[NAME_4]` and "Claude Agent SDK" `[NAME_2]`, along with other false positives
  ("mark specs"). The model then reads about itself through tokens, and the first report of a
  session counts these names. The fix belongs in `sonar-detection`, shared with the extension.
- The model may comment on what it receives ("this looks like a masking marker"); once
  detokenized, the comment reads oddly.
- An OAuth token refresh changes the scope: the history is redacted and reported again once.
- Tokens written markdown-escaped (`\[EMAIL\_1\]`) are not detokenized in the stream.
- The engine has one thread: a large first request delays concurrent pastes and file scans.
- No WebSocket upgrade, and only the Anthropic API so far (`/anthropic`).
