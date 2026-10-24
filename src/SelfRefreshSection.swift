import SwiftUI

/// Signature-refresh section shown in the Sign tab: shows how long the current
/// free-developer signature lasts and lets the user re-sign/reinstall on demand.
struct SelfRefreshSection: View {
    @ObservedObject private var refresh = SelfRefreshManager.shared
    @ObservedObject private var auth = AppleIDAuthService.shared

    var body: some View {
        Section(header: Text("Signature refresh")) {
            HStack {
                Image(systemName: refresh.needsRefresh ? "exclamationmark.triangle.fill" : "clock.fill")
                    .foregroundColor(refresh.needsRefresh ? .orange : .green)
                Text(refresh.status)
                    .font(.subheadline)
                Spacer()
                if let days = refresh.daysLeft {
                    Text("\(days)d")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                }
            }

            Toggle("Auto-refresh before expiry", isOn: $refresh.autoRefreshEnabled)

            Button {
                refresh.startRefresh { _ in }
            } label: {
                if refresh.isRefreshing {
                    HStack(spacing: 8) {
                        ProgressView()
                        Text("Refreshing…")
                    }
                    .frame(maxWidth: .infinity)
                } else {
                    Text("Refresh signature now")
                        .frame(maxWidth: .infinity)
                }
            }
            .buttonStyle(PressableBlueButtonStyle())
            .disabled(refresh.isRefreshing || !auth.isLoggedIn)

            if !auth.isLoggedIn {
                Text("Sign in with an Apple ID above to refresh the signature without a PC.")
                    .font(.caption2)
                    .foregroundColor(.secondary)
            } else {
                Text("Re-signs BuildBox with a freshly issued profile and asks iOS to reinstall it (one confirmation tap).")
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
        }
        .onAppear { refresh.evaluate() }
    }
}
