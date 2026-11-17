import os

/// The extension's log (`log stream --predicate 'subsystem == "com.tryriot.agent.network"'`).
/// NSLog's arguments are redacted in a system extension; these are marked public, and none of
/// them carries content: counts, bundle ids, `host:port`, error descriptions.
let log = Logger(subsystem: "com.tryriot.agent.network", category: "proxy")
