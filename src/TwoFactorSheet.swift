import SwiftUI

/// Two-factor prompt shown from the app root (so it also appears when an
/// automatic refresh triggers a sign-in from any tab).
struct TwoFactorSheet: View {
    let prompt: TwoFactorPrompt
    @ObservedObject private var auth = AppleIDAuthService.shared
    @State private var code = ""

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text(prompt.message)
                }
                Section(header: Text("Verification code")) {
                    TextField("6-digit code", text: $code)
                        .keyboardType(.numberPad)
                        .textContentType(.oneTimeCode)
                }
                Section {
                    Button("Submit code") {
                        let trimmed = code.trimmingCharacters(in: .whitespacesAndNewlines)
                        guard !trimmed.isEmpty else { return }
                        auth.submitTwoFactor(code: trimmed)
                    }
                    .disabled(code.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)

                    if prompt.unknown || prompt.sms {
                        Button("Send code to my devices") { auth.requestCodeOnDevices() }
                    }
                    ForEach(prompt.numbers) { number in
                        if number.id != prompt.selectedNumberId {
                            Button("Send SMS to \(number.display)") { auth.requestCodeBySMS(id: number.id) }
                        }
                    }
                    if !prompt.unknown {
                        Button("Resend code") { auth.resendCode() }
                    }
                }
                Section {
                    Button("Cancel", role: .cancel) { auth.cancelTwoFactor() }
                }
            }
            .navigationTitle("Two-Factor Authentication")
        }
        .interactiveDismissDisabled()
    }
}
