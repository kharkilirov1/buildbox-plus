import SwiftUI
import UIKit

/// Sign-in section for Apple-ID based signing. Renders in the Sign tab below
/// the certificate section: log in with a free Apple ID, then sign the
/// currently imported IPA with the account-issued development certificate.
struct AppleIDSection: View {
    @ObservedObject private var auth = AppleIDAuthService.shared

    let ipaURL: URL?
    var onSigned: (AppleIDAuthService.SignedResult) -> Void
    var onLog: (String) -> Void

    @State private var emailField = ""
    @State private var passwordField = ""
    @State private var remember = true
    @State private var showTwoFactor = false

    var body: some View {
        Section(header: Text("Apple ID")) {
            if auth.isLoggedIn {
                HStack(spacing: 8) {
                    Image(systemName: "checkmark.seal.fill")
                        .foregroundColor(.green)
                    Text(auth.email)
                        .font(.subheadline)
                    Spacer()
                    Button("Sign out") { auth.logout() }
                        .font(.caption)
                        .foregroundColor(.red)
                }

                Button {
                    guard let ipaURL else {
                        auth.setStatus("Import an IPA first")
                        return
                    }
                    onLog("Signing \(ipaURL.lastPathComponent) with Apple ID…")
                    auth.sign(ipaURL: ipaURL) { result in
                        switch result {
                        case .success(let signed):
                            onLog("Signed with Apple ID: \(signed.ipaURL.lastPathComponent)")
                            onSigned(signed)
                        case .failure(let error):
                            onLog("Apple ID signing failed: \(error.localizedDescription)")
                        }
                    }
                } label: {
                    if auth.isBusy {
                        HStack(spacing: 8) {
                            ProgressView()
                            Text("Signing… \(Int(auth.signProgress * 100))%")
                        }
                        .frame(maxWidth: .infinity)
                    } else {
                        Text("Sign IPA with Apple ID")
                            .frame(maxWidth: .infinity)
                    }
                }
                .buttonStyle(PressableBlueButtonStyle())
                .disabled(ipaURL == nil || auth.isBusy)

                if !auth.status.isEmpty {
                    Text(auth.status)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }

                if let expiration = EmbeddedProfile.expirationDate {
                    let days = Int(expiration.timeIntervalSinceNow / 86_400)
                    Text(days >= 0 ? "Current signature expires in \(days) day(s)" : "Signature expired — refresh it")
                        .font(.caption2)
                        .foregroundColor(days <= 2 ? .orange : .secondary)
                }
            } else {
                TextField("Apple ID (email)", text: $emailField)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(.emailAddress)
                SecureField("Apple ID password", text: $passwordField)
                Toggle("Remember in iOS Keychain", isOn: $remember)

                Button {
                    auth.login(email: emailField, password: passwordField, remember: remember)
                    passwordField = ""
                } label: {
                    if auth.isBusy {
                        HStack(spacing: 8) {
                            ProgressView()
                            Text("Signing in…")
                        }
                        .frame(maxWidth: .infinity)
                    } else {
                        Text("Sign in")
                            .frame(maxWidth: .infinity)
                    }
                }
                .buttonStyle(PressableBlueButtonStyle())
                .disabled(auth.isBusy || emailField.isEmpty || passwordField.isEmpty)

                if !auth.status.isEmpty {
                    Text(auth.status)
                        .font(.caption)
                        .foregroundColor(auth.status.localizedCaseInsensitiveContains("fail") ||
                                         auth.status.localizedCaseInsensitiveContains("error") ? .red : .secondary)
                }

                Text("Uses a free Apple ID: the certificate is valid for 7 days and counts toward Apple's 3-app limit. The password is stored only in the iOS Keychain and is used once to request a certificate.")
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
        }
        .onAppear {
            emailField = auth.savedEmail
            remember = auth.rememberPassword
            if remember, let saved = auth.loadSavedPassword() {
                passwordField = saved
            }
        }
        .onChange(of: auth.savedEmail) { newValue in
            if emailField.isEmpty { emailField = newValue }
        }

    }
}

