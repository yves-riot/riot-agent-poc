import XCTest
@testable import RiotAgent

private final class FakePasteboard: PasteboardAccess {
    var changeCount = 1
    var items: [[String: Data]] = []
    /// Content reads, the ones macOS may surface as a privacy alert.
    var contentReads = 0

    func copy(_ text: String, rich: Bool = false) {
        var item = ["public.utf8-plain-text": Data(text.utf8)]
        if rich { item["public.rtf"] = Data("{\\rtf1 \(text)}".utf8) }
        items = [item]
        changeCount += 1
    }

    func plainText() -> String? {
        contentReads += 1
        return items.first?["public.utf8-plain-text"].map { String(decoding: $0, as: UTF8.self) }
    }
    func hasType(_ type: String) -> Bool { items.contains { $0[type] != nil } }
    func snapshot() -> [[String: Data]] {
        contentReads += 1
        return items
    }
    func restore(_ snapshot: [[String: Data]], marker: String) {
        items = snapshot
        if !marker.isEmpty, !items.isEmpty { items[0][marker] = Data() }
        changeCount += 1
    }
    func writePlainText(_ text: String, marker: String) {
        var item = ["public.utf8-plain-text": Data(text.utf8)]
        if !marker.isEmpty { item[marker] = Data() }
        items = [item]
        changeCount += 1
    }
}

/// Stands in for the daemon: redacts one IBAN, remembers it for detokenization.
private final class FakeBackend: GuardBackend {
    static let iban = "FR76 3000 6000 0112 3456 7890 189"
    var redactCalls = 0
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
    func detokenize(_ text: String, bundleId: String) async throws -> DetokenizeResult {
        let out = text.replacingOccurrences(of: "[IBAN_1]", with: Self.iban)
        return DetokenizeResult(text: out, replaced: out == text ? 0 : 1)
    }
    func reportOverride(eventId: String) async throws { overrides.append(eventId) }
}

@MainActor
final class ClipboardGuardTests: XCTestCase {
    private let chatgpt = "com.openai.codex"
    private var pb: FakePasteboard!
    private var backend: FakeBackend!
    private var guardian: ClipboardGuard!
    private var redactedEvents = 0

    override func setUp() async throws {
        pb = FakePasteboard()
        backend = FakeBackend()
        guardian = ClipboardGuard(pasteboard: pb, backend: backend)
        guardian.targets = [chatgpt]
        guardian.onRedacted = { [weak self] _, _ in self?.redactedEvents += 1 }
        redactedEvents = 0
    }

    private func text() -> String? {
        pb.items.first?["public.utf8-plain-text"].map { String(decoding: $0, as: UTF8.self) }
    }

    func testSwapsSensitiveTextWhenTheAIAppIsActivated() async {
        guardian.activated(bundleId: "com.apple.mail")
        pb.copy("Mon IBAN \(FakeBackend.iban)", rich: true)
        guardian.tick()
        await guardian.waitIdle()
        XCTAssertEqual(pb.contentReads, 0, "never reads while a non-protected app is frontmost")

        guardian.activated(bundleId: chatgpt)
        await guardian.waitIdle()
        XCTAssertEqual(text(), "Mon IBAN [IBAN_1]")
        XCTAssertTrue(pb.hasType(ClipboardGuard.marker))
        XCTAssertNil(pb.items.first?["public.rtf"], "rich representations would leak the value")
        XCTAssertEqual(redactedEvents, 1)

        // Our own write is not inspected again.
        guardian.tick()
        await guardian.waitIdle()
        XCTAssertEqual(backend.redactCalls, 1)
    }

    func testLeavingTheAppRestoresTheOriginal() async {
        pb.copy("Mon IBAN \(FakeBackend.iban)", rich: true)
        guardian.activated(bundleId: chatgpt)
        await guardian.waitIdle()
        guardian.activated(bundleId: "com.apple.Notes")
        await guardian.waitIdle()
        XCTAssertEqual(text(), "Mon IBAN \(FakeBackend.iban)")
        XCTAssertNotNil(pb.items.first?["public.rtf"], "the user gets back exactly what they copied")
        XCTAssertFalse(pb.hasType(ClipboardGuard.marker))
    }

    func testAnswerCopiedInsideTheAppIsDetokenizedOnLeaving() async {
        pb.copy("Mon IBAN \(FakeBackend.iban)")
        guardian.activated(bundleId: chatgpt)
        await guardian.waitIdle()
        pb.copy("Virement prêt vers [IBAN_1].") // the user copies the AI's answer
        guardian.tick()
        await guardian.waitIdle()
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
        XCTAssertEqual(redactedEvents, 0)
    }

    func testANewerCopyWinsOverAnInFlightRedaction() async {
        pb.copy("Mon IBAN \(FakeBackend.iban)")
        backend.onRedact = { [pb] in pb!.copy("autre chose") } // user copies again meanwhile
        guardian.activated(bundleId: chatgpt)
        await guardian.waitIdle()
        XCTAssertEqual(text(), "autre chose")
        XCTAssertEqual(redactedEvents, 0)
    }

    func testPasteOriginalPutsItBackAndReportsTheOverride() async {
        pb.copy("Mon IBAN \(FakeBackend.iban)")
        guardian.activated(bundleId: chatgpt)
        await guardian.waitIdle()
        guardian.pasteOriginal()
        await Task.yield()
        XCTAssertEqual(text(), "Mon IBAN \(FakeBackend.iban)")
        guardian.tick()
        await guardian.waitIdle()
        XCTAssertEqual(backend.redactCalls, 1, "the original the user chose is not re-redacted")
        try? await Task.sleep(nanoseconds: 50_000_000)
        XCTAssertEqual(backend.overrides, ["ev-1"])
    }

    func testOwnPopupTakingFocusIsNotLeavingTheApp() async {
        pb.copy("Mon IBAN \(FakeBackend.iban)")
        guardian.activated(bundleId: chatgpt)
        await guardian.waitIdle()
        guardian.activated(bundleId: Bundle.main.bundleIdentifier)
        await guardian.waitIdle()
        XCTAssertEqual(guardian.frontmost, chatgpt)
        XCTAssertEqual(text(), "Mon IBAN [IBAN_1]")
    }
}
