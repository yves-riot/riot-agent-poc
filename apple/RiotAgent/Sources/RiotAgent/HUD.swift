import AppKit
import SwiftUI

/// The in-the-moment cards, the native counterpart of the extension's in-page guard popup
/// (PopupShell: 346 pt wide, top-right). Shown in a non-activating panel so the AI app keeps
/// focus: activating Riot would read, to the clipboard guard, as leaving the app.
@MainActor
final class HUDController: ObservableObject {
    enum Card: Equatable {
        case text(result: RedactTextResultBox, app: String)
        case textConfirm(result: RedactTextResultBox, app: String)
        /// After "paste without redaction", when the original could only go on the clipboard.
        case steppedAside
        case file(FileBlocked)
        case fileConfirm(FileBlocked)
        case fileGranted(app: String)
        /// A message redacted on the network: by the time the card shows, it has been sent.
        case message(TextRedacted)
        case messageConfirm(TextRedacted)
        case messageGranted(app: String)
    }

    @Published var card: Card?
    private var panel: NSPanel?
    private weak var model: AppModel?
    private var dismissWork: DispatchWorkItem?

    init(model: AppModel) { self.model = model }

    func showText(result: RedactTextResult, appName: String) {
        show(.text(result: RedactTextResultBox(result), app: appName), autoDismiss: model?.popupMode == "lite" ? 6 : nil)
    }

    func showFile(_ blocked: FileBlocked) {
        show(.file(blocked), autoDismiss: nil)
    }

    func showMessage(_ redacted: TextRedacted) {
        show(.message(redacted), autoDismiss: model?.popupMode == "lite" ? 6 : nil)
    }

    func dismiss() {
        dismissWork?.cancel()
        card = nil
        panel?.orderOut(nil)
    }

    func show(_ card: Card, autoDismiss: TimeInterval?) {
        self.card = card
        let panel = self.panel ?? makePanel()
        self.panel = panel
        // SwiftUI renders the new card on the next pass: size and place the panel after it.
        DispatchQueue.main.async { [weak self] in
            guard let self, self.card != nil else { return }
            self.position(panel)
            panel.orderFrontRegardless()
        }
        dismissWork?.cancel()
        if let autoDismiss {
            let work = DispatchWorkItem { [weak self] in self?.dismiss() }
            dismissWork = work
            DispatchQueue.main.asyncAfter(deadline: .now() + autoDismiss, execute: work)
        }
    }

    private func makePanel() -> NSPanel {
        let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 346, height: 10),
                            styleMask: [.nonactivatingPanel, .borderless],
                            backing: .buffered, defer: false)
        panel.isFloatingPanel = true
        panel.level = .statusBar
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .transient]
        panel.isOpaque = false
        panel.backgroundColor = .clear
        panel.hasShadow = true
        panel.hidesOnDeactivate = false
        let host = NSHostingView(rootView: HUDView(controller: self).environmentObject(model!))
        panel.contentView = host
        return panel
    }

    private func position(_ panel: NSPanel) {
        let screen = NSScreen.screens.first { NSMouseInRect(NSEvent.mouseLocation, $0.frame, false) } ?? NSScreen.main
        guard let frame = screen?.visibleFrame, let host = panel.contentView else { return }
        host.layoutSubtreeIfNeeded()
        var size = host.fittingSize
        size.width = 346
        size.height = max(size.height, 80)
        panel.setFrame(NSRect(x: frame.maxX - size.width - 16, y: frame.maxY - size.height - 16,
                              width: size.width, height: size.height), display: true)
        if ProcessInfo.processInfo.environment["RIOT_DEBUG"] != nil {
            NSLog("riot hud frame %@ on %@", NSStringFromRect(panel.frame), NSStringFromRect(frame))
        }
    }

    fileprivate func resize() {
        guard let panel else { return }
        DispatchQueue.main.async { self.position(panel) }
    }

    // MARK: actions

    func pasteOriginal() {
        // Pasted in place: the field shows it, nothing to add.
        if model?.clipboard.pasteOriginal() == .pasted {
            dismiss()
        } else {
            show(.steppedAside, autoDismiss: 8)
        }
    }

    /// The message already left, redacted. The grant covers the one the user sends next.
    func allowNextMessage(_ redacted: TextRedacted) {
        Task {
            if await model?.grantTextBypass(eventId: redacted.eventId) == true {
                show(.messageGranted(app: redacted.appName), autoDismiss: 8)
            } else {
                dismiss()
            }
        }
    }

    func sendFileAnyway(_ blocked: FileBlocked) {
        Task {
            if await model?.grantFileBypass(eventId: blocked.eventId) == true {
                show(.fileGranted(app: blocked.appName), autoDismiss: 8)
            } else {
                dismiss()
            }
        }
    }
}

/// `RedactTextResult` is a plain Decodable; the box gives the card Equatable identity.
struct RedactTextResultBox: Equatable {
    let result: RedactTextResult
    init(_ result: RedactTextResult) { self.result = result }
    static func == (a: Self, b: Self) -> Bool { a.result.eventId == b.result.eventId }
}

private struct HUDView: View {
    @ObservedObject var controller: HUDController
    @EnvironmentObject var model: AppModel
    private let l = L10n.shared

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            if let card = controller.card {
                content(card)
            }
        }
        .padding(20)
        .frame(width: 346, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 16).fill(Color(nsColor: .windowBackgroundColor)))
        .overlay(RoundedRectangle(cornerRadius: 16).strokeBorder(Color.primary.opacity(0.08)))
        .onChange(of: controller.card) { _, _ in controller.resize() }
    }

    private var bot: String { model.popup.botName }
    private var workspace: String { model.popup.company ?? "" }

    @ViewBuilder
    private func content(_ card: HUDController.Card) -> some View {
        switch card {
        case let .text(box, app) where model.popupMode == "lite":
            header(l.t("redactionGuard.lite.title", ["botName": bot]),
                   l.t("redactionGuard.lite.subtitleService", ["service": app]))
            HStack {
                Button(l.t("redactionGuard.lite.viewDetails")) {
                    controller.show(.text(result: box, app: app), autoDismiss: nil)
                    model.popupMode = "full"
                }
                Spacer()
                Button(l.t("redactionGuard.lite.close")) { controller.dismiss() }.keyboardShortcut(.cancelAction)
            }
        case let .text(box, app):
            header(l.t("redactionGuard.text.intercepted.title", ["botName": bot]),
                   l.t("redactionGuard.text.intercepted.subtitle"))
            Text(l.t("redactionGuard.text.intercepted.intro", ["service": app, "workspace": workspace]))
                .font(.callout).foregroundStyle(.secondary)
            findings(box.result.types)
            HStack {
                if box.result.allowBypass {
                    Button(l.t("redactionGuard.text.intercepted.pasteAnyway")) {
                        controller.show(.textConfirm(result: box, app: app), autoDismiss: nil)
                    }
                    .buttonStyle(.link)
                }
                Spacer()
                Button(l.t("redactionGuard.text.intercepted.dismiss")) { controller.dismiss() }
                    .keyboardShortcut(.defaultAction)
            }
        case let .textConfirm(box, app):
            header(l.t("redactionGuard.text.confirm.title"), nil)
            confirmBox(l.t("redactionGuard.text.confirm.boxTitle"),
                       l.t("redactionGuard.text.confirm.warning", ["service": app]))
            HStack {
                Button(l.t("redactionGuard.text.confirm.cancel")) {
                    controller.show(.text(result: box, app: app), autoDismiss: nil)
                }
                Spacer()
                Button(l.t("redactionGuard.text.confirm.submit")) { controller.pasteOriginal() }
                    .keyboardShortcut(.defaultAction)
            }
        case .steppedAside:
            // Without Accessibility (or after the user typed), the original is only on the
            // clipboard: the user swaps it in themselves.
            header(l.t("redactionGuard.steppedAside.title"), l.t("agent.text.pasteOriginalHint"))
            HStack { Spacer(); Button(l.t("redactionGuard.steppedAside.close")) { controller.dismiss() } }
        case let .file(blocked):
            header(l.t("redactionGuard.file.intercepted.title", count: 1, ["botName": bot]),
                   blocked.fileName)
            Text(l.t("redactionGuard.file.intercepted.intro", ["service": blocked.appName, "workspace": workspace]))
                .font(.callout).foregroundStyle(.secondary)
            if blocked.types.isEmpty {
                Text(l.t("redactionGuard.error.processing.body", count: 1)).font(.callout)
            } else {
                findings(blocked.types)
            }
            HStack {
                if blocked.allowBypass {
                    Button(l.t("redactionGuard.file.intercepted.sendOriginal")) {
                        controller.show(.fileConfirm(blocked), autoDismiss: nil)
                    }
                    .buttonStyle(.link)
                }
                Spacer()
                Button(l.t("redactionGuard.file.intercepted.dismiss")) { controller.dismiss() }
                    .keyboardShortcut(.defaultAction)
            }
        case let .fileConfirm(blocked):
            header(l.t("redactionGuard.file.confirm.title", count: 1), blocked.fileName)
            confirmBox(l.t("redactionGuard.file.confirm.boxTitle"),
                       l.t("redactionGuard.file.confirm.warning", ["service": blocked.appName]))
            HStack {
                Button(l.t("redactionGuard.file.confirm.cancel")) { controller.show(.file(blocked), autoDismiss: nil) }
                Spacer()
                Button(l.t("redactionGuard.file.confirm.submit")) { controller.sendFileAnyway(blocked) }
                    .keyboardShortcut(.defaultAction)
            }
        case let .fileGranted(app):
            header(l.t("agent.file.bypassGranted", ["app": app]), nil)
            HStack { Spacer(); Button(l.t("redactionGuard.steppedAside.close")) { controller.dismiss() } }
        case let .message(redacted) where model.popupMode == "lite":
            header(l.t("agent.message.title", ["botName": bot]),
                   l.t("redactionGuard.lite.subtitleService", ["service": redacted.appName]))
            HStack {
                Button(l.t("redactionGuard.lite.viewDetails")) {
                    controller.show(.message(redacted), autoDismiss: nil)
                    model.popupMode = "full"
                }
                Spacer()
                Button(l.t("redactionGuard.lite.close")) { controller.dismiss() }.keyboardShortcut(.cancelAction)
            }
        case let .message(redacted):
            header(l.t("agent.message.title", ["botName": bot]), l.t("agent.message.subtitle"))
            Text(l.t("agent.message.intro", ["service": redacted.appName, "workspace": workspace]))
                .font(.callout).foregroundStyle(.secondary)
            findings(redacted.types)
            HStack {
                if redacted.allowBypass {
                    Button(l.t("agent.message.allowNext")) { controller.show(.messageConfirm(redacted), autoDismiss: nil) }
                        .buttonStyle(.link)
                }
                Spacer()
                Button(l.t("redactionGuard.text.intercepted.dismiss")) { controller.dismiss() }
                    .keyboardShortcut(.defaultAction)
            }
        case let .messageConfirm(redacted):
            header(l.t("agent.message.allowNext"), nil)
            confirmBox(l.t("redactionGuard.text.confirm.boxTitle"),
                       l.t("agent.message.confirm.warning", ["service": redacted.appName]))
            HStack {
                Button(l.t("redactionGuard.text.confirm.cancel")) { controller.show(.message(redacted), autoDismiss: nil) }
                Spacer()
                Button(l.t("agent.message.confirm.submit")) { controller.allowNextMessage(redacted) }
                    .keyboardShortcut(.defaultAction)
            }
        case let .messageGranted(app):
            header(l.t("agent.message.bypassGranted", ["app": app]), nil)
            HStack { Spacer(); Button(l.t("redactionGuard.steppedAside.close")) { controller.dismiss() } }
        }
    }

    private func header(_ title: String, _ subtitle: String?) -> some View {
        HStack(alignment: .top, spacing: 12) {
            BotAvatar(url: model.popup.botIconUrl, size: 32)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.headline).fixedSize(horizontal: false, vertical: true)
                if let subtitle { Text(subtitle).font(.subheadline).foregroundStyle(.secondary) }
            }
        }
    }

    private func findings(_ types: [TypeCount]) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            ForEach(types.prefix(4), id: \.flag) { t in
                HStack {
                    Image(systemName: "eye.slash").foregroundStyle(.red)
                    Text(t.localizedLabel)
                    Spacer()
                    if t.count > 1 { Text("×\(t.count)").foregroundStyle(.secondary) }
                }
                .font(.callout)
            }
            if types.count > 4 {
                Text(l.t("redactionGuard.findings.more", count: types.count - 4, ["count": "\(types.count - 4)"]))
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 10).fill(Color.red.opacity(0.06)))
    }

    private func confirmBox(_ title: String, _ warning: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.callout.weight(.semibold))
            Text(warning).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 10).fill(Color.orange.opacity(0.08)))
    }
}

struct BotAvatar: View {
    let url: String?
    let size: CGFloat
    var body: some View {
        Group {
            if let url, let u = URL(string: url) {
                AsyncImage(url: u) { $0.resizable().scaledToFill() } placeholder: { fallback }
            } else {
                fallback
            }
        }
        .frame(width: size, height: size)
        .clipShape(Circle())
    }
    private var fallback: some View {
        ZStack {
            Circle().fill(Color.accentColor.opacity(0.15))
            Image(systemName: "shield.lefthalf.filled").foregroundStyle(Color.accentColor)
        }
    }
}
