import AppKit
import SwiftUI

/// The menu bar popup: the extension's toolbar popup (entrypoints/popup/App.vue) plus what only
/// the native agent knows (protected apps, clipboard permission, recent activity).
struct MenuPopup: View {
    @EnvironmentObject var model: AppModel
    private let l = L10n.shared

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            header
            if !model.connected {
                card(icon: "bolt.horizontal.circle", tint: .red,
                     title: l.t("agent.daemon.down.title"), body: l.t("agent.daemon.down.body"))
            } else {
                viewCard
            }
            if case .signedIn(_, let count) = model.popup.view {
                infoRow(icon: "checkmark.shield",
                        title: l.t("popup.redactions.title", count: count, ["count": "\(count)"]),
                        body: l.t("popup.redactions.body", ["botName": bot]))
            }
            infoRow(icon: "lock", title: l.t("privacy.title", ["botName": bot]), body: l.t("privacy.body"))
            pasteboardWarning
            if !model.popup.protectedApps.isEmpty { protectedApps }
            if !model.popup.recentEvents.isEmpty { recent }
            Divider()
            Toggle(l.t("popup.showFullPopup"), isOn: Binding(
                get: { model.popupMode == "full" },
                set: { model.popupMode = $0 ? "full" : "lite" }))
                .toggleStyle(.switch).font(.callout)
            footer
        }
        .padding(24)
        .frame(width: 360)
        .task { await model.refresh() }
    }

    private var bot: String { model.popup.botName }

    private var header: some View {
        HStack(spacing: 12) {
            BotAvatar(url: model.popup.botIconUrl, size: 40)
            VStack(alignment: .leading, spacing: 2) {
                Text(bot).font(.headline)
                Text(model.popup.company.map { l.t("popup.subtitle", ["company": $0]) } ?? l.t("popup.subtitleNoCompany"))
                    .font(.subheadline).foregroundStyle(.secondary)
            }
        }
    }

    @ViewBuilder
    private var viewCard: some View {
        switch model.popup.view {
        case .loading:
            HStack { ProgressView().controlSize(.small); Text(l.t("Loading…")).foregroundStyle(.secondary) }
        case .notConfigured:
            card(icon: "exclamationmark.triangle", tint: .orange,
                 title: l.t("agent.notConfigured.title"), body: l.t("agent.notConfigured.body"))
        case .standby:
            card(icon: "moon.zzz", tint: .gray,
                 title: l.t("popup.standby.title"), body: l.t("agent.standby.body", ["botName": bot]))
        case .signedIn(let name, _):
            card(icon: "circle.fill", tint: .green,
                 title: l.t("popup.signedIn.title"), body: l.t("popup.signedIn.body", ["name": name]))
        case .reconnect:
            card(icon: "person.crop.circle.badge.questionmark", tint: .orange,
                 title: l.t("agent.reconnect.title"), body: l.t("agent.reconnect.body"))
        case .error:
            card(icon: "xmark.octagon", tint: .red, title: l.t("popup.unexpectedError"), body: nil)
        }
    }

    @ViewBuilder
    private var pasteboardWarning: some View {
        if model.pasteboardAccess == "deny" || model.pasteboardAccess == "ask" {
            VStack(alignment: .leading, spacing: 6) {
                Label(l.t("agent.pasteboard.title"), systemImage: "doc.on.clipboard").font(.callout.weight(.semibold))
                Text(l.t(model.pasteboardAccess == "deny" ? "agent.pasteboard.denied" : "agent.pasteboard.ask", ["botName": bot]))
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                Button(l.t("agent.pasteboard.open")) {
                    NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_Pasteboard")!)
                }
                .buttonStyle(.link).font(.caption)
            }
            .padding(12)
            .background(RoundedRectangle(cornerRadius: 10).fill(Color.orange.opacity(0.08)))
        }
    }

    private var protectedApps: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(l.t("agent.protectedApps")).font(.caption.weight(.semibold)).foregroundStyle(.secondary)
            ForEach(model.popup.protectedApps) { app in
                HStack {
                    Image(systemName: app.installed ? "checkmark.circle.fill" : "circle.dashed")
                        .foregroundStyle(app.installed ? .green : .secondary)
                    Text(app.displayName)
                    if !app.installed { Text(l.t("agent.notInstalled")).foregroundStyle(.secondary) }
                }
                .font(.callout)
            }
        }
    }

    private var recent: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(l.t("agent.recent")).font(.caption.weight(.semibold)).foregroundStyle(.secondary)
            ForEach(model.popup.recentEvents.prefix(4)) { e in
                HStack(alignment: .firstTextBaseline) {
                    Text(l.t("agent.recent.\(e.kind)")).font(.callout)
                    Text("· \(e.appName)").font(.callout).foregroundStyle(.secondary)
                    Spacer()
                    Text(e.types.map(\.localizedLabel).prefix(2).joined(separator: ", "))
                        .font(.caption).foregroundStyle(.secondary).lineLimit(1)
                }
            }
        }
    }

    private var footer: some View {
        HStack {
            Spacer()
            Button(l.t("agent.quit")) { NSApp.terminate(nil) }.buttonStyle(.link)
        }
        .font(.caption)
    }

    private func card(icon: String, tint: Color, title: String, body: String?) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: icon).foregroundStyle(tint).font(icon == "circle.fill" ? .system(size: 8) : .body)
                .frame(width: 16).padding(.top, icon == "circle.fill" ? 5 : 0)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.callout.weight(.semibold))
                if let body { Text(body).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true) }
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 10).fill(Color.primary.opacity(0.04)))
    }

    private func infoRow(icon: String, title: String, body: String) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: icon).frame(width: 16).foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.callout.weight(.medium))
                Text(body).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}
