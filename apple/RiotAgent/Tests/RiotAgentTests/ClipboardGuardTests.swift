import XCTest
@testable import RiotAgent

private let plain = "public.utf8-plain-text"

private final class FakePasteboard: PasteboardAccess {
    var changeCount = 1
    var items: [[String: Data]] = []
    /// The plain text we promised, until an app reads it.
    private var promise: (() -> String)?
    /// Content reads, the ones macOS may surface as a privacy alert.
    var contentReads = 0

    func copy(_ text: String, rich: Bool = false) {
        var item = [plain: Data(text.utf8)]
        if rich { item["public.rtf"] = Data("{\\rtf1 \(text)}".utf8) }
        copy(item)
    }

    func copy(_ item: [String: Data]) {
        items = [item]
        promise = nil
        changeCount += 1
    }

    /// Another app reads the text, e.g. to paste it. Like the pasteboard server, the promise
    /// is resolved once and the answer cached.
    @discardableResult
    func simulateRead() -> String? {
        if let promise {
            items[0][plain] = Data(promise().utf8)
            self.promise = nil
        }
        return text(plain)
    }

    func text(_ type: String) -> String? {
        items.first?[type].map { String(decoding: $0, as: UTF8.self) }
    }

    var isPromised: Bool { promise != nil }
    var types: [String] { items.first.map { Array($0.keys) } ?? [] }

    func plainText() -> String? {
        contentReads += 1
        return simulateRead()
    }
    func hasType(_ type: String) -> Bool { items.contains { $0[type] != nil } }
    func snapshot() -> [[String: Data]] {
        contentReads += 1
        return items
    }
    func restore(_ snapshot: [[String: Data]], marker: String) {
        items = snapshot
        promise = nil
        if !marker.isEmpty, !items.isEmpty { items[0][marker] = Data() }
        changeCount += 1
    }
    func texts(_ types: [String]) -> [String: String] {
        contentReads += 1
        var out: [String: String] = [:]
        for type in types { out[type] = text(type) }
        return out
    }
    func writeTexts(_ texts: [String: String]) {
        copy(texts.mapValues { Data($0.utf8) })
    }
    func writePromisedText(markers: [String], provide: @escaping () -> String) {
        items = [Dictionary(uniqueKeysWithValues: markers.map { ($0, Data()) })]
        promise = provide
        changeCount += 1
    }
}

private final class FakeKeyboard: KeyboardState {
    var commandHeld = false
    var secondsSinceKeyDown: TimeInterval = 1000
}

private final class FakeKeystrokes: KeystrokeSender {
    var allowed = true
    var sent = 0
    func undoThenPaste() -> Bool {
        if allowed { sent += 1 }
        return allowed
    }
}

/// Stands in for the daemon: redacts one IBAN, remembers the tokens for detokenization.
private final class FakeBackend: GuardBackend {
    static let iban = "FR76 3000 6000 0112 3456 7890 189"
    static let vault = ["[IBAN_1]": iban, "[NAME_1]": "Zoé <Dupont> & {Cie}"]
    var redactCalls = 0
    var pastes: [String] = []
    var overrides: [String] = []
    var onRedact: (() -> Void)?

    func redactText(_ text: String, bundleId: String) async throws -> RedactTextResult {
        redactCalls += 1
        onRedact?()
        guard text.contains(Self.iban) else {
            return RedactTextResult(action: "clean", text: nil, types: [], eventId: nil, allowBypass: true)
        }
        return RedactTextResult(action: "redacted", text: text.replacingOccurrences(of: Self.iban, with: "[IBAN_1]"),
                                types: [TypeCount(flag: "iban", label: "redaction.flag.iban", count: 1)],
                                eventId: "ev-1", allowBypass: true)
    }
    func reportPaste(eventId: String) async throws -> String {
        pastes.append(eventId)
        return "paste-\(pastes.count)"
    }
    func detokenize(_ text: String, bundleId: String) async throws -> DetokenizeResult {
        var out = text
        for (token, value) in Self.vault { out = out.replacingOccurrences(of: token, with: value) }
        return DetokenizeResult(text: out, replaced: out == text ? 0 : 1)
    }
    func reportOverride(pasteId: String) async throws { overrides.append(pasteId) }
}

@MainActor
final class ClipboardGuardTests: XCTestCase {
    private let chatgpt = "com.openai.codex"
    private let claude = "com.anthropic.claudefordesktop"
    private var pb: FakePasteboard!
    private var backend: FakeBackend!
    private var keyboard: FakeKeyboard!
    private var keys: FakeKeystrokes!
    private var clock = Date(timeIntervalSince1970: 1_000_000)
    private var guardian: ClipboardGuard!
    private var pastedEvents = 0

    override func setUp() async throws {
        pb = FakePasteboard()
        backend = FakeBackend()
        keyboard = FakeKeyboard()
        keys = FakeKeystrokes()
        pastedEvents = 0
        guardian = makeGuard(rearmDelay: 0)
    }

    private func makeGuard(rearmDelay: TimeInterval) -> ClipboardGuard {
        let guardian = ClipboardGuard(pasteboard: pb, backend: backend, keyboard: keyboard, keys: keys,
                                      now: { [unowned self] in self.clock }, rearmDelay: rearmDelay)
        guardian.targets = [chatgpt, claude]
        guardian.onPasted = { [weak self] _, _ in self?.pastedEvents += 1 }
        return guardian
    }

    private func text() -> String? { pb.text(plain) }

    /// An app reads `after` seconds from now, ⌘ held or not.
    private func read(after: TimeInterval, command: Bool) async -> String? {
        clock.addTimeInterval(after)
        keyboard.commandHeld = command
        let read = pb.simulateRead()
        await guardian.waitIdle()
        return read
    }

    /// A ⌘V a moment later.
    private func paste() async -> String? { await read(after: 2, command: true) }

    private func copyIBANAndActivate(_ app: String? = nil) async {
        pb.copy("Mon IBAN \(FakeBackend.iban)", rich: true)
        guardian.activated(bundleId: app ?? chatgpt)
        await guardian.waitIdle()
    }

    // MARK: paste detection

    func testActivationAloneShowsNothingButPromisesTheRedactedText() async {
        guardian.activated(bundleId: "com.apple.mail")
        pb.copy("Mon IBAN \(FakeBackend.iban)", rich: true)
        guardian.tick()
        await guardian.waitIdle()
        XCTAssertEqual(pb.contentReads, 0, "never reads while a non-protected app is frontmost")

        guardian.activated(bundleId: chatgpt)
        await guardian.waitIdle()
        XCTAssertTrue(pb.isPromised)
        XCTAssertTrue(pb.hasType(ClipboardGuard.marker))
        XCTAssertTrue(pb.hasType("org.nspasteboard.TransientType"), "clipboard managers skip it unread")
        XCTAssertNil(pb.items.first?["public.rtf"], "rich representations would leak the value")
        XCTAssertEqual(pastedEvents, 0)
        XCTAssertEqual(backend.pastes, [])

        // Our own write is not inspected again.
        guardian.tick()
        await guardian.waitIdle()
        XCTAssertEqual(backend.redactCalls, 1)
    }

    func testEachPasteShowsTheHUDAndIsReported() async {
        await copyIBANAndActivate()
        let first = await paste()
        XCTAssertEqual(first, "Mon IBAN [IBAN_1]")
        XCTAssertEqual(pastedEvents, 1)
        try? await Task.sleep(nanoseconds: 20_000_000)
        XCTAssertEqual(backend.pastes, ["ev-1"])
        XCTAssertTrue(pb.isPromised, "re-armed for the next paste")

        let second = await paste()
        XCTAssertEqual(second, "Mon IBAN [IBAN_1]")
        XCTAssertEqual(pastedEvents, 2)
        try? await Task.sleep(nanoseconds: 20_000_000)
        XCTAssertEqual(backend.pastes, ["ev-1", "ev-1"])
    }

    func testTheFirstPasteNeedsNoCommandKey() async {
        // Edit > Paste or the context menu: no ⌘, the read still comes well after our write.
        await copyIBANAndActivate(claude)
        _ = await read(after: 0.3, command: false)
        XCTAssertEqual(pastedEvents, 1)
    }

    func testAnEarlyReadIsSilentAndReArmsOnce() async {
        await copyIBANAndActivate(claude)
        let read = await read(after: 0.05, command: false) // a clipboard manager reacting to our write
        XCTAssertEqual(read, "Mon IBAN [IBAN_1]", "still redacted")
        XCTAssertEqual(pastedEvents, 0)
        XCTAssertTrue(pb.isPromised, "re-armed once, so the real paste is still seen")

        _ = await self.read(after: 0.05, command: false) // again: the budget is spent
        XCTAssertFalse(pb.isPromised)
        XCTAssertEqual(pastedEvents, 0)
    }

    func testThePasteAfterAnEarlyReadShowsTheHUD() async {
        await copyIBANAndActivate(claude)
        _ = await read(after: 0.05, command: false)
        _ = await paste()
        XCTAssertEqual(pastedEvents, 1)
    }

    func testAReadOfTheReArmedPromiseWithoutCommandIsNotAPaste() async {
        // After a paste, a clipboard manager reads each re-armed promise: no HUD loop.
        await copyIBANAndActivate()
        _ = await paste()
        _ = await read(after: 0.6, command: false)
        XCTAssertEqual(pastedEvents, 1)
    }

    func testPastesReadLateAreStillPastes() async {
        // Claude reads 0.3 to 1.7 s after ⌘V (13/11 logs), ⌘ still held.
        await copyIBANAndActivate(claude)
        _ = await read(after: 1.2, command: true)
        _ = await read(after: 1.7, command: true)
        XCTAssertEqual(pastedEvents, 2)
    }

    func testAReadOnceTheAppIsLeftGetsTheOriginal() async {
        await copyIBANAndActivate()
        // The paste in Notes beats the queued restore: the provider still answers.
        guardian.activated(bundleId: "com.apple.Notes")
        let read = pb.simulateRead()
        XCTAssertEqual(read, "Mon IBAN \(FakeBackend.iban)")
        await guardian.waitIdle()
        XCTAssertEqual(pastedEvents, 0)
    }

    // MARK: leaving, copy out

    func testLeavingTheAppRestoresTheOriginal() async {
        await copyIBANAndActivate()
        guardian.activated(bundleId: "com.apple.Notes")
        await guardian.waitIdle()
        XCTAssertEqual(text(), "Mon IBAN \(FakeBackend.iban)")
        XCTAssertNotNil(pb.items.first?["public.rtf"], "the user gets back exactly what they copied")
        XCTAssertFalse(pb.hasType(ClipboardGuard.marker))
    }

    func testAnswerCopiedInsideTheAppIsDetokenizedOnLeaving() async {
        await copyIBANAndActivate()
        pb.copy("Virement prêt vers [IBAN_1].") // the user copies the AI's answer
        guardian.tick()
        await guardian.waitIdle()
        guardian.activated(bundleId: "com.apple.mail")
        await guardian.waitIdle()
        XCTAssertEqual(text(), "Virement prêt vers \(FakeBackend.iban).")
    }

    func testACopyFollowedAtOnceByASwitchIsDetokenized() async {
        await copyIBANAndActivate()
        pb.copy("Virement prêt vers [IBAN_1].")
        // ⌘C then ⌘Tab within the same timer period: no tick in between.
        guardian.activated(bundleId: "com.apple.mail")
        await guardian.waitIdle()
        XCTAssertEqual(text(), "Virement prêt vers \(FakeBackend.iban).")
    }

    func testARichCopyIsRestoredInEveryRepresentation() async {
        guardian.activated(bundleId: claude)
        await guardian.waitIdle()
        // Claude's copy: markdown escapes in the plain text, HTML and RTF alongside.
        pb.copy([
            plain: Data(#"Pour \[NAME\_1\] : [IBAN_1]"#.utf8),
            "public.html": Data("<p>Pour [NAME_1] : <b>[IBAN_1]</b></p>".utf8),
            "public.rtf": Data(#"{\rtf1 Pour [NAME_1] : [IBAN_1]}"#.utf8),
            "org.chromium.web-custom-data": Data("[IBAN_1]".utf8),
        ])
        guardian.activated(bundleId: "com.apple.mail")
        await guardian.waitIdle()
        XCTAssertEqual(text(), "Pour Zoé <Dupont> & {Cie} : \(FakeBackend.iban)")
        XCTAssertEqual(pb.text("public.html"),
                       "<p>Pour Zoé &lt;Dupont&gt; &amp; {Cie} : <b>\(FakeBackend.iban)</b></p>")
        XCTAssertEqual(pb.text("public.rtf"), #"{\rtf1 Pour Zo\u233? <Dupont> & \{Cie\} : "# + FakeBackend.iban + "}")
        XCTAssertNil(pb.items.first?["org.chromium.web-custom-data"], "other types could still hold the tokens")
    }

    func testEscaping() {
        XCTAssertEqual(ClipboardGuard.escapeHTML(#"a<b>&"c""#), "a&lt;b&gt;&amp;&quot;c&quot;")
        XCTAssertEqual(ClipboardGuard.escapeRTF("a{b}\\c\u{e9}\u{1F600}"), #"a\{b\}\\c\u233?\u-10179?\u-8704?"#)
        XCTAssertEqual(ClipboardGuard.tokens(in: #"[EMAIL_1], \[API\_KEY\_2\] et [x_1]"#), ["[EMAIL_1]", "[API_KEY_2]"])
    }

    // MARK: races, bypass

    func testCleanTextIsLeftAlone() async {
        pb.copy("Bonjour, peux-tu résumer ce texte ?")
        let before = pb.changeCount
        guardian.activated(bundleId: chatgpt)
        await guardian.waitIdle()
        XCTAssertEqual(pb.changeCount, before)
        XCTAssertFalse(pb.isPromised)
    }

    func testANewerCopyWinsOverAnInFlightRedaction() async {
        pb.copy("Mon IBAN \(FakeBackend.iban)")
        backend.onRedact = { [pb] in pb!.copy("autre chose") } // user copies again meanwhile
        guardian.activated(bundleId: chatgpt)
        await guardian.waitIdle()
        XCTAssertEqual(text(), "autre chose")
        XCTAssertFalse(pb.isPromised)
    }

    func testPasteOriginalPutsItBackAndOverridesTheLastPaste() async {
        await copyIBANAndActivate()
        _ = await paste()
        clock.addTimeInterval(5) // reading the HUD, clicking through the confirmation
        XCTAssertEqual(guardian.pasteOriginal(), .pasted)
        XCTAssertEqual(keys.sent, 1, "⌘Z then ⌘V over the redacted paste")
        XCTAssertEqual(text(), "Mon IBAN \(FakeBackend.iban)")
        guardian.tick()
        await guardian.waitIdle()
        XCTAssertEqual(backend.redactCalls, 1, "the original the user chose is not re-redacted")
        try? await Task.sleep(nanoseconds: 50_000_000)
        XCTAssertEqual(backend.overrides, ["paste-1"])
    }

    func testPasteOriginalLeavesItOnTheClipboardIfTheUserTypedSinceThePaste() async {
        await copyIBANAndActivate()
        _ = await paste()
        clock.addTimeInterval(5)
        keyboard.secondsSinceKeyDown = 2 // a key 3 s after the paste: ⌘Z would undo that
        XCTAssertEqual(guardian.pasteOriginal(), .onClipboard)
        XCTAssertEqual(keys.sent, 0)
        XCTAssertEqual(text(), "Mon IBAN \(FakeBackend.iban)")
    }

    func testPasteOriginalWithoutAccessibilityLeavesItOnTheClipboard() async {
        keys.allowed = false
        await copyIBANAndActivate()
        _ = await paste()
        keyboard.secondsSinceKeyDown = 0.5 // the ⌘V itself, seen late
        XCTAssertEqual(guardian.pasteOriginal(), .onClipboard)
        XCTAssertEqual(text(), "Mon IBAN \(FakeBackend.iban)")
    }

    func testPasteOriginalSendsNoKeysToAnotherApp() async {
        await copyIBANAndActivate()
        _ = await paste()
        guardian.activated(bundleId: "com.apple.Notes") // the leave step has not run yet
        XCTAssertEqual(guardian.pasteOriginal(), .onClipboard)
        XCTAssertEqual(keys.sent, 0, "⌘Z in Notes would undo something else")
    }

    func testTheReArmWaitsUntilTheReadingAppHasItsData() async {
        guardian = makeGuard(rearmDelay: 0.2)
        await copyIBANAndActivate()
        clock.addTimeInterval(2)
        keyboard.commandHeld = true
        XCTAssertEqual(pb.simulateRead(), "Mon IBAN [IBAN_1]")
        try? await Task.sleep(nanoseconds: 50_000_000)
        XCTAssertEqual(pastedEvents, 1, "the HUD does not wait")
        XCTAssertFalse(pb.isPromised, "clearing the clipboard now could empty the paste in progress")
        XCTAssertEqual(text(), "Mon IBAN [IBAN_1]")
        await guardian.waitIdle()
        XCTAssertTrue(pb.isPromised)
    }

    func testACopyDuringTheReArmDelayIsKept() async {
        guardian = makeGuard(rearmDelay: 0.2)
        await copyIBANAndActivate()
        clock.addTimeInterval(2)
        keyboard.commandHeld = true
        pb.simulateRead() // a paste: re-arm pending
        try? await Task.sleep(nanoseconds: 50_000_000)
        pb.copy("autre chose") // the user copies something else meanwhile
        await guardian.waitIdle()
        XCTAssertEqual(text(), "autre chose")
        XCTAssertFalse(pb.isPromised)
    }

    func testOwnPopupTakingFocusIsNotLeavingTheApp() async {
        await copyIBANAndActivate()
        guardian.activated(bundleId: Bundle.main.bundleIdentifier)
        await guardian.waitIdle()
        XCTAssertEqual(guardian.frontmost, chatgpt)
        XCTAssertTrue(pb.isPromised)
        let pasted = await paste()
        XCTAssertEqual(pasted, "Mon IBAN [IBAN_1]")
    }
}

// MARK: - Drag and drop

private final class FakePointer: PointerState {
    var leftButtonDown = true
    var under: String?
    var frontmostApp: String?
    func appUnderPointer() -> String? { under }
}

@MainActor
private final class FakeBlockingBackend: BlockingBackend {
    let inner = FakeBackend()
    var redactions = 0
    func redactTextNow(_ text: String, bundleId: String) -> RedactTextResult? {
        redactions += 1
        guard text.contains(FakeBackend.iban) else {
            return RedactTextResult(action: "clean", text: nil, types: [], eventId: nil, allowBypass: true)
        }
        return RedactTextResult(action: "redacted", text: text.replacingOccurrences(of: FakeBackend.iban, with: "[IBAN_1]"),
                                types: [TypeCount(flag: "iban", label: "redaction.flag.iban", count: 1)],
                                eventId: "ev-drag", allowBypass: true)
    }
    func detokenizeNow(_ text: String, bundleId: String) -> DetokenizeResult? {
        var out = text
        for (token, value) in FakeBackend.vault { out = out.replacingOccurrences(of: token, with: value) }
        return DetokenizeResult(text: out, replaced: out == text ? 0 : 1)
    }
    func reportPaste(eventId: String) async throws -> String { try await inner.reportPaste(eventId: eventId) }
}

@MainActor
final class DragGuardTests: XCTestCase {
    private let claude = "com.anthropic.claudefordesktop"
    private var board: FakePasteboard!
    private var backend: FakeBlockingBackend!
    private var pointer: FakePointer!
    private var guardian: DragGuard!
    private var drops: [(RedactTextResult, String)] = []

    override func setUp() async throws {
        board = FakePasteboard()
        backend = FakeBlockingBackend()
        pointer = FakePointer()
        guardian = DragGuard(board: board, backend: backend, pointer: pointer)
        guardian.targets = [claude]
        guardian.onDropped = { [weak self] result, app in self?.drops.append((result, app)) }
        drops = []
    }

    /// The user starts dragging `text` out of `from`.
    private func startDrag(_ text: String, from: String = "com.sublimetext.4") {
        pointer.frontmostApp = from
        pointer.under = from
        pointer.leftButtonDown = true
        board.copy(text)
        guardian.tick()
    }

    private func release() async {
        pointer.leftButtonDown = false
        guardian.tick()
        try? await Task.sleep(nanoseconds: 20_000_000)
    }

    func testTextDroppedIntoAProtectedAppIsRedactedAndShown() async {
        startDrag("Mon IBAN \(FakeBackend.iban)")
        XCTAssertTrue(board.isPromised)
        pointer.under = claude
        guardian.tick()
        XCTAssertEqual(board.simulateRead(), "Mon IBAN [IBAN_1]")
        XCTAssertEqual(drops.count, 0, "entering the app is not dropping")
        await release()
        XCTAssertEqual(drops.map(\.1), [claude])
        XCTAssertFalse(drops[0].0.allowBypass, "nothing to swap back after a drop")
        XCTAssertEqual(backend.inner.pastes, ["ev-drag"])
    }

    func testTextDroppedElsewhereIsUntouched() async {
        startDrag("Mon IBAN \(FakeBackend.iban)")
        pointer.under = "com.apple.Notes"
        XCTAssertEqual(board.simulateRead(), "Mon IBAN \(FakeBackend.iban)")
        await release()
        XCTAssertTrue(drops.isEmpty)
        XCTAssertEqual(backend.redactions, 0, "no detection outside the protected apps")
    }

    func testCrossingBackOutAfterARead() async {
        // Chromium reads the drag when the pointer enters; the user then drops it elsewhere.
        startDrag("Mon IBAN \(FakeBackend.iban)")
        pointer.under = claude
        XCTAssertEqual(board.simulateRead(), "Mon IBAN [IBAN_1]")
        pointer.under = "com.apple.Notes"
        guardian.tick()
        XCTAssertTrue(board.isPromised, "promised again for where it may land")
        XCTAssertEqual(board.simulateRead(), "Mon IBAN \(FakeBackend.iban)")
        await release()
        XCTAssertTrue(drops.isEmpty)
    }

    func testTextDraggedOutOfTheAppGetsTheValuesBack() async {
        startDrag("Virement vers [IBAN_1]", from: claude)
        pointer.under = "com.apple.mail"
        XCTAssertEqual(board.simulateRead(), "Virement vers \(FakeBackend.iban)")
    }

    func testFileDragsAreLeftAlone() {
        pointer.frontmostApp = "com.apple.finder"
        board.copy([plain: Data("/Users/me/IBAN.pdf".utf8), "public.file-url": Data("file:///Users/me/IBAN.pdf".utf8)])
        let before = board.changeCount
        guardian.tick()
        XCTAssertEqual(board.changeCount, before)
        XCTAssertFalse(board.isPromised)
        XCTAssertTrue(DragGuard.isPlainTextDrag(["public.utf8-plain-text", "public.rtf", "public.html"]))
        XCTAssertFalse(DragGuard.isPlainTextDrag(["public.png", "public.utf8-plain-text"]))
        XCTAssertFalse(DragGuard.isPlainTextDrag(["com.apple.pasteboard.promised-file-url"]))
    }
}
