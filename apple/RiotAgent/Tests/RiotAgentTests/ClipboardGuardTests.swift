import XCTest
@testable import RiotAgent

private final class FakePasteboard: PasteboardAccess {
    var changeCount = 1
    var items: [[String: Data]] = []
    /// The plain text we promised, until an app reads it.
    private var promise: (() -> String)?
    /// Content reads, the ones macOS may surface as a privacy alert.
    var contentReads = 0

    func copy(_ text: String, rich: Bool = false) {
        var item = ["public.utf8-plain-text": Data(text.utf8)]
        if rich { item["public.rtf"] = Data("{\\rtf1 \(text)}".utf8) }
        items = [item]
        promise = nil
        changeCount += 1
    }

    /// Another app reads the text, e.g. to paste it. Like the pasteboard server, the promise
    /// is resolved once and the answer cached.
    @discardableResult
    func simulateRead() -> String? {
        if let promise {
            items[0]["public.utf8-plain-text"] = Data(promise().utf8)
            self.promise = nil
        }
        return items.first?["public.utf8-plain-text"].map { String(decoding: $0, as: UTF8.self) }
    }

    var isPromised: Bool { promise != nil }

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
    func writePlainText(_ text: String, marker: String) {
        var item = ["public.utf8-plain-text": Data(text.utf8)]
        if !marker.isEmpty { item[marker] = Data() }
        items = [item]
        promise = nil
        changeCount += 1
    }
    func writePromisedText(marker: String, provide: @escaping () -> String) {
        items = [[marker: Data()]]
        promise = provide
        changeCount += 1
    }
}

/// The user's last paste gesture, `age` seconds before the read.
private final class FakeGestures: GestureProbe {
    var age: TimeInterval?
    func secondsSincePasteGesture() -> TimeInterval? { age }
}

/// Stands in for the daemon: redacts one IBAN, remembers it for detokenization.
private final class FakeBackend: GuardBackend {
    static let iban = "FR76 3000 6000 0112 3456 7890 189"
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
        let out = text.replacingOccurrences(of: "[IBAN_1]", with: Self.iban)
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
    private var gestures: FakeGestures!
    private var clock = Date(timeIntervalSince1970: 1_000_000)
    private var guardian: ClipboardGuard!
    private var pastedEvents = 0

    override func setUp() async throws {
        pb = FakePasteboard()
        backend = FakeBackend()
        gestures = FakeGestures()
        pastedEvents = 0
        guardian = makeGuard(rearmDelay: 0)
    }

    private func makeGuard(rearmDelay: TimeInterval) -> ClipboardGuard {
        let guardian = ClipboardGuard(pasteboard: pb, backend: backend, gestures: gestures,
                                      now: { [unowned self] in self.clock }, rearmDelay: rearmDelay)
        guardian.targets = [chatgpt, claude]
        guardian.onPasted = { [weak self] _, _ in self?.pastedEvents += 1 }
        return guardian
    }

    private func text() -> String? {
        pb.items.first?["public.utf8-plain-text"].map { String(decoding: $0, as: UTF8.self) }
    }

    /// Time passes, then the user presses ⌘V (or clicks Paste) and the app reads.
    private func paste() async -> String? {
        clock.addTimeInterval(2)
        gestures.age = 0.05
        let read = pb.simulateRead()
        await guardian.waitIdle()
        return read
    }

    /// A read with no fresh gesture: an app reading on activation, a clipboard manager.
    private func backgroundRead() async -> String? {
        clock.addTimeInterval(0.1)
        gestures.age = nil
        let read = pb.simulateRead()
        await guardian.waitIdle()
        return read
    }

    private func copyIBANAndActivate(_ app: String? = nil) async {
        pb.copy("Mon IBAN \(FakeBackend.iban)", rich: true)
        guardian.activated(bundleId: app ?? chatgpt)
        await guardian.waitIdle()
    }

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

    func testAReadWithoutGestureIsSilentAndReArmsOnce() async {
        await copyIBANAndActivate(claude)
        let read = await backgroundRead() // Electron reading on activation
        XCTAssertEqual(read, "Mon IBAN [IBAN_1]", "still redacted")
        XCTAssertEqual(pastedEvents, 0)
        XCTAssertTrue(pb.isPromised, "re-armed once, so the real paste is still seen")

        _ = await backgroundRead() // a second background read: the budget is spent
        XCTAssertFalse(pb.isPromised)
        XCTAssertEqual(pastedEvents, 0)
    }

    func testTheRealPasteAfterABackgroundReadShowsTheHUD() async {
        await copyIBANAndActivate(claude)
        _ = await backgroundRead()
        _ = await paste()
        XCTAssertEqual(pastedEvents, 1)
    }

    func testAGestureOlderThanOurWriteIsNotAPaste() async {
        // ⌘Tab (or a click) activated the app; the app reads right after we wrote the promise.
        await copyIBANAndActivate(claude)
        clock.addTimeInterval(0.2)
        gestures.age = 0.5 // the activation gesture, before the write
        pb.simulateRead()
        await guardian.waitIdle()
        XCTAssertEqual(pastedEvents, 0)
    }

    func testAReadOnceTheAppIsLeftGetsTheOriginal() async {
        await copyIBANAndActivate()
        guardian.targets = [chatgpt] // so Notes is not a target either way
        // The paste in Notes beats the queued restore: the provider still answers.
        guardian.activated(bundleId: "com.apple.Notes")
        let read = pb.simulateRead()
        XCTAssertEqual(read, "Mon IBAN \(FakeBackend.iban)")
        await guardian.waitIdle()
        XCTAssertEqual(pastedEvents, 0)
    }

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
        guardian.pasteOriginal()
        XCTAssertEqual(text(), "Mon IBAN \(FakeBackend.iban)")
        guardian.tick()
        await guardian.waitIdle()
        XCTAssertEqual(backend.redactCalls, 1, "the original the user chose is not re-redacted")
        try? await Task.sleep(nanoseconds: 50_000_000)
        XCTAssertEqual(backend.overrides, ["paste-1"])
    }

    func testTheReArmWaitsUntilTheReadingAppHasItsData() async {
        guardian = makeGuard(rearmDelay: 0.2)
        await copyIBANAndActivate()
        clock.addTimeInterval(2)
        gestures.age = 0.05
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
        gestures.age = 0.05
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
