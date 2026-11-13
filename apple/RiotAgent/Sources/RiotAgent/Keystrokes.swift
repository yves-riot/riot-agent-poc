import Carbon.HIToolbox
import CoreGraphics

/// ⌘Z then ⌘V posted to the frontmost app, for "paste without redaction". Posting events needs
/// the Accessibility permission (granted by MDM with a PPPC profile, or once by the user).
final class SystemKeystrokes: KeystrokeSender {
    func undoThenPaste() -> Bool {
        guard CGPreflightPostEventAccess() else {
            CGRequestPostEventAccess() // the system prompt to Privacy & Security › Accessibility
            return false
        }
        guard let z = Self.keyCode(typing: "z"), let v = Self.keyCode(typing: "v") else { return false }
        press(z)
        press(v)
        return true
    }

    private func press(_ key: CGKeyCode) {
        let source = CGEventSource(stateID: .privateState) // not merged with keys physically held
        for down in [true, false] {
            let event = CGEvent(keyboardEventSource: source, virtualKey: key, keyDown: down)
            event?.flags = .maskCommand
            event?.post(tap: .cghidEventTap)
        }
    }

    /// The key that types `character` in the current layout: shortcuts follow the layout, and
    /// the QWERTY Z key is ⌘W (close) on AZERTY. Layouts without Latin letters fall back to the
    /// ASCII-capable layout, the one macOS uses for ⌘ shortcuts.
    static func keyCode(typing character: String) -> CGKeyCode? {
        let sources = [TISCopyCurrentKeyboardLayoutInputSource(), TISCopyCurrentASCIICapableKeyboardLayoutInputSource()]
        for source in sources {
            guard let source = source?.takeRetainedValue(),
                  let raw = TISGetInputSourceProperty(source, kTISPropertyUnicodeKeyLayoutData) else { continue }
            let data = Unmanaged<CFData>.fromOpaque(raw).takeUnretainedValue() as Data
            let code: CGKeyCode? = data.withUnsafeBytes { bytes in
                guard let layout = bytes.baseAddress?.assumingMemoryBound(to: UCKeyboardLayout.self) else { return nil }
                for code in UInt16(0)..<128 {
                    var deadKeys: UInt32 = 0
                    var chars = [UniChar](repeating: 0, count: 4)
                    var length = 0
                    let status = UCKeyTranslate(layout, code, UInt16(kUCKeyActionDown), 0, UInt32(LMGetKbdType()),
                                                OptionBits(kUCKeyTranslateNoDeadKeysBit), &deadKeys,
                                                chars.count, &length, &chars)
                    if status == noErr, String(utf16CodeUnits: chars, count: length) == character { return code }
                }
                return nil
            }
            if let code { return code }
        }
        return nil
    }
}
