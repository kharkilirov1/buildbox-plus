import Foundation
import Combine
import Security
import UIKit

// MARK: - FFI value types

struct TrustedNumber: Decodable, Identifiable {
    let numberWithDialCode: String
    let lastTwoDigits: String
    let pushMode: String
    let id: UInt32

    var display: String { "\(numberWithDialCode) (···\(lastTwoDigits))" }
}

struct TwoFactorPrompt: Identifiable {
    let id = UUID()
    let message: String
    let numbers: [TrustedNumber]
    let selectedNumberId: UInt32?
    let sms: Bool
    let unknown: Bool
    let lastError: String?
}

private struct TwoFactorParamsJSON: Decodable {
    let lastError: String?
    let unknown: Bool
    let sms: Bool
    let numbers: [TrustedNumber]
    let selectedNumberId: UInt32?
}

enum AppleIDAuthError: LocalizedError {
    case notLoggedIn
    case missingEmbeddedProfile
    case ffi(String)
    case badResponse(String)

    var errorDescription: String? {
        switch self {
        case .notLoggedIn: return "Sign in with an Apple ID first"
        case .missingEmbeddedProfile:
            return "Cannot read this app's embedded provisioning profile — reinstall BuildBox with iLoader"
        case .ffi(let message): return message
        case .badResponse(let message): return message
        }
    }
}

// MARK: - C callbacks (must be non-capturing)

private func bbsTwoFactorTrampoline(_ ctx: UnsafeMutableRawPointer?,
                                    _ paramsJSON: UnsafePointer<CChar>?,
                                    _ outBuf: UnsafeMutablePointer<CChar>?,
                                    _ outCap: Int) -> Int {
    guard let ctx, let outBuf, outCap > 1 else { return -1 }
    let service = Unmanaged<AppleIDAuthService>.fromOpaque(ctx).takeUnretainedValue()
    let json = paramsJSON.map { String(cString: $0) } ?? "{}"
    return service.handleTwoFactor(paramsJSON: json, outBuf: outBuf, outCap: outCap)
}

private func bbsProgressTrampoline(_ ctx: UnsafeMutableRawPointer?, _ progress: Float) {
    guard let ctx else { return }
    let service = Unmanaged<AppleIDAuthService>.fromOpaque(ctx).takeUnretainedValue()
    service.updateProgress(Double(progress))
}

// MARK: - Service

final class AppleIDAuthService: NSObject, ObservableObject {
    static let shared = AppleIDAuthService()

    @Published private(set) var isLoggedIn = false
    @Published private(set) var email = ""
    @Published private(set) var isBusy = false
    @Published private(set) var status = ""
    @Published private(set) var signProgress: Double = 0
    @Published var twoFactorPrompt: TwoFactorPrompt?
    @Published private(set) var savedEmail: String = UserDefaults.standard.string(forKey: "appleIDEmail") ?? ""
    @Published private(set) var rememberPassword = UserDefaults.standard.object(forKey: "appleIDRemember") as? Bool ?? true

    private var handle: UInt64 = 0
    private var twoFactorSemaphore: DispatchSemaphore?
    private let twoFactorLock = NSLock()
    private var twoFactorResponse: [String: Any]?

    private static let keychainService = "com.mikevillarroel.buildbox.appleid"

    override init() {
        super.init()
        _ = bbs_init()
        if rememberPassword, !savedEmail.isEmpty,
           Keychain.load(service: Self.keychainService, account: savedEmail) != nil {
            email = savedEmail
        }
    }

    var storageDirectory: URL {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        return docs.appendingPathComponent("sideload-engine", isDirectory: true)
    }

    // MARK: Login

    func login(email rawEmail: String, password: String, remember: Bool, completion: ((Bool) -> Void)? = nil) {
        let email = rawEmail.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !email.isEmpty, !password.isEmpty else {
            status = "Enter Apple ID and password"
            completion?(false)
            return
        }
        isBusy = true
        status = "Signing in to \(email)…"
        twoFactorPrompt = nil

        let storage = storageDirectory
        let machine = Self.machineName
        let ctx = Unmanaged.passUnretained(self).toOpaque()

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            try? FileManager.default.createDirectory(at: storage, withIntermediateDirectories: true)
            var resultJSON: String?
            email.withCString { emailPtr in
                password.withCString { passwordPtr in
                    storage.path.withCString { storagePtr in
                        machine.withCString { machinePtr in
                            let raw = bbs_login(emailPtr, passwordPtr, storagePtr, machinePtr,
                                                bbsTwoFactorTrampoline, ctx)
                            if let raw {
                                resultJSON = String(cString: raw)
                                bbs_string_free(raw)
                            }
                        }
                    }
                }
            }
            DispatchQueue.main.async {
                self.finishLogin(resultJSON: resultJSON, email: email, password: password, remember: remember, completion: completion)
            }
        }
    }

    private func finishLogin(resultJSON: String?, email: String, password: String, remember: Bool, completion: ((Bool) -> Void)? = nil) {
        isBusy = false
        twoFactorPrompt = nil
        guard let resultJSON, let data = resultJSON.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            status = "Unexpected response from signing engine"
            completion?(false)
            return
        }
        if let ok = object["ok"] as? Bool, ok, let handleNumber = object["handle"] as? NSNumber {
            handle = handleNumber.uint64Value
            isLoggedIn = true
            self.email = email
            savedEmail = email
            UserDefaults.standard.set(email, forKey: "appleIDEmail")
            UserDefaults.standard.set(remember, forKey: "appleIDRemember")
            rememberPassword = remember
            if remember {
                Keychain.save(password, service: Self.keychainService, account: email)
            } else {
                Keychain.delete(service: Self.keychainService, account: email)
            }
            status = "Signed in as \(email)"
            completion?(true)
        } else {
            let message = object["error"] as? String ?? "Apple ID sign-in failed"
            status = message
            completion?(false)
        }
    }

    func setStatus(_ message: String) {
        status = message
    }

    func logout() {
        if handle != 0 { _ = bbs_logout(handle) }
        handle = 0
        isLoggedIn = false
        status = "Signed out"
        if !savedEmail.isEmpty { Keychain.delete(service: Self.keychainService, account: savedEmail) }
    }

    func loadSavedPassword() -> String? {
        guard !savedEmail.isEmpty else { return nil }
        return Keychain.load(service: Self.keychainService, account: savedEmail)
    }


    /// Whether an email + password for a previous sign-in are stored in the Keychain.
    var hasSavedCredentials: Bool {
        !savedEmail.isEmpty && Keychain.load(service: Self.keychainService, account: savedEmail) != nil
    }

    /// Sign in again without user input (used by the auto-refresh path). If Apple
    /// asks for a 2FA code the prompt sheet appears; the completion fires after
    /// the attempt finishes.
    func loginWithSavedCredentials(completion: @escaping (Bool) -> Void) {
        guard hasSavedCredentials, let password = loadSavedPassword() else {
            completion(false)
            return
        }
        login(email: savedEmail, password: password, remember: true, completion: completion)
    }
    // MARK: Two-factor authentication

    func handleTwoFactor(paramsJSON: String, outBuf: UnsafeMutablePointer<CChar>, outCap: Int) -> Int {
        guard let data = paramsJSON.data(using: .utf8),
              let params = try? JSONDecoder().decode(TwoFactorParamsJSON.self, from: data) else {
            return -1
        }
        let semaphore = DispatchSemaphore(value: 0)
        twoFactorLock.lock()
        twoFactorSemaphore = semaphore
        twoFactorResponse = nil
        twoFactorLock.unlock()

        let message: String
        if let lastError = params.lastError {
            message = lastError
        } else if params.sms {
            message = "Enter the verification code sent by SMS"
        } else if params.unknown {
            message = "Choose a verification method and enter the code"
        } else {
            message = "Enter the verification code sent to your devices"
        }

        let prompt = TwoFactorPrompt(message: message,
                                     numbers: params.numbers,
                                     selectedNumberId: params.selectedNumberId,
                                     sms: params.sms,
                                     unknown: params.unknown,
                                     lastError: params.lastError)
        DispatchQueue.main.async { [weak self] in
            self?.twoFactorPrompt = prompt
        }

        let deadline = DispatchTime.now() + 600
        if semaphore.wait(timeout: deadline) == .timedOut {
            DispatchQueue.main.async { [weak self] in
                self?.twoFactorPrompt = nil
                self?.status = "Two-factor code timed out"
            }
            return -1
        }
        twoFactorLock.lock()
        let response = twoFactorResponse
        twoFactorResponse = nil
        twoFactorSemaphore = nil
        twoFactorLock.unlock()
        guard let response,
              let json = try? JSONSerialization.data(withJSONObject: response),
              let jsonString = String(data: json, encoding: .utf8) else { return -1 }
        let bytes = Array(jsonString.utf8)
        let copyCount = min(bytes.count, outCap - 1)
        for index in 0..<copyCount { outBuf[index] = CChar(bitPattern: bytes[index]) }
        outBuf[copyCount] = 0
        return copyCount
    }

    func submitTwoFactor(code: String) {
        respond(["type": "code", "code": code])
    }

    func requestCodeOnDevices() {
        respond(["type": "sendToDevices"])
    }

    func requestCodeBySMS(id: UInt32) {
        respond(["type": "sendSms", "id": NSNumber(value: id)])
    }

    func resendCode() {
        respond(["type": "resend"])
    }

    func cancelTwoFactor() {
        twoFactorLock.lock()
        let semaphore = twoFactorSemaphore
        twoFactorResponse = nil
        twoFactorSemaphore = nil
        twoFactorLock.unlock()
        DispatchQueue.main.async { [weak self] in self?.twoFactorPrompt = nil }
        semaphore?.signal()
    }

    private func respond(_ response: [String: Any]) {
        twoFactorLock.lock()
        twoFactorResponse = response
        let semaphore = twoFactorSemaphore
        twoFactorLock.unlock()
        DispatchQueue.main.async { [weak self] in self?.twoFactorPrompt = nil }
        semaphore?.signal()
    }

    // MARK: Signing

    func updateProgress(_ value: Double) {
        DispatchQueue.main.async { [weak self] in self?.signProgress = value }
    }

    struct SignedResult {
        let ipaURL: URL
        let appName: String
        let bundleID: String
        let version: String
    }

    /// Ask the Rust engine for a development certificate + provisioning profile
    /// for the IPA's bundle id, then sign with the existing on-device zsign pipeline.
    func sign(ipaURL: URL, completion: @escaping (Result<SignedResult, Error>) -> Void) {
        guard isLoggedIn, handle != 0 else {
            completion(.failure(AppleIDAuthError.notLoggedIn)); return
        }
        guard let identity = EmbeddedProfile.identity else {
            completion(.failure(AppleIDAuthError.missingEmbeddedProfile)); return
        }
        let meta = IPASigner.shared.readMetadata(ipaURL: ipaURL)
        let bundleID = meta.bundleID ?? ""
        let appName = meta.appName ?? "App"
        let version = meta.version ?? "1.0.0"
        guard !bundleID.isEmpty else {
            completion(.failure(AppleIDAuthError.badResponse("Could not read the bundle id from the IPA"))); return
        }

        isBusy = true
        signProgress = 0.05
        setStatus("Requesting certificate…")

        let storage = storageDirectory.appendingPathComponent("identity-\(UUID().uuidString)", isDirectory: true)
        let handleCopy = handle
        let udid = identity.udid
        let deviceName = UIDevice.current.name
        let password = "buildbox-\(UUID().uuidString.prefix(8))"

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            let json = Self.exportIdentity(handle: handleCopy,
                                           bundleID: bundleID,
                                           appName: appName,
                                           udid: udid,
                                           deviceName: deviceName,
                                           outDir: storage.path,
                                           password: password)
            DispatchQueue.main.async {
                guard let json, let data = json.data(using: .utf8),
                      let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                    self.finishSign(.failure(AppleIDAuthError.badResponse("Unexpected response from signing engine")), completion: completion)
                    return
                }
                guard (object["ok"] as? Bool) == true,
                      let p12Path = object["p12_path"] as? String,
                      let provisionPath = object["provision_path"] as? String,
                      let pwd = object["password"] as? String else {
                    let message = object["error"] as? String ?? "Certificate request failed"
                    self.finishSign(.failure(AppleIDAuthError.ffi(message)), completion: completion)
                    return
                }
                self.signProgress = 0.35
                IPASigner.shared.sign(ipaURL: ipaURL,
                                      p12URL: URL(fileURLWithPath: p12Path),
                                      p12Password: pwd,
                                      provisionURL: URL(fileURLWithPath: provisionPath),
                                      appName: appName, bundleID: bundleID, version: version,
                                      progress: { message in
                                          DispatchQueue.main.async {
                                              self.setStatus(message)
                                              self.signProgress = min(self.signProgress + 0.05, 0.9)
                                          }
                                      },
                                      completion: { result in
                                          switch result {
                                          case .success(let signedURL):
                                              let signedMeta = IPASigner.shared.readMetadata(ipaURL: signedURL)
                                              self.finishSign(.success(SignedResult(ipaURL: signedURL,
                                                                                    appName: signedMeta.appName ?? appName,
                                                                                    bundleID: signedMeta.bundleID ?? bundleID,
                                                                                    version: signedMeta.version ?? version)),
                                                              completion: completion)
                                          case .failure(let error):
                                              self.finishSign(.failure(error), completion: completion)
                                          }
                                      })
            }
        }
    }

    private func finishSign(_ result: Result<SignedResult, Error>, completion: @escaping (Result<SignedResult, Error>) -> Void) {
        isBusy = false
        signProgress = 0
        if case .success = result { setStatus("") }
        completion(result)
    }

    private static func exportIdentity(handle: UInt64, bundleID: String, appName: String,
                                       udid: String, deviceName: String,
                                       outDir: String, password: String) -> String? {
        var resultJSON: String?
        bundleID.withCString { bundlePtr in
            appName.withCString { appPtr in
                udid.withCString { udidPtr in
                    deviceName.withCString { namePtr in
                        outDir.withCString { outPtr in
                            password.withCString { pwdPtr in
                                let raw = bbs_export_identity(handle, bundlePtr, appPtr, udidPtr, namePtr, outPtr, pwdPtr)
                                if let raw {
                                    resultJSON = String(cString: raw)
                                    bbs_string_free(raw)
                                }
                            }
                        }
                    }
                }
            }
        }
        return resultJSON
    }
    static var machineName: String {
        let name = UIDevice.current.name
        return "BuildBox — \(name)"
    }
}

// MARK: - Embedded provisioning profile

enum EmbeddedProfile {
    struct Identity {
        let udid: String
        let expiration: Date?
    }

    static var identity: Identity? {
        guard let url = Bundle.main.url(forResource: "embedded", withExtension: "mobileprovision"),
              let data = try? Data(contentsOf: url) else { return nil }
        guard let plistData = extractPlist(from: data),
              let plist = try? PropertyListSerialization.propertyList(from: plistData,
                                                                     options: [], format: nil),
              let dict = plist as? [String: Any] else { return nil }
        let devices = dict["ProvisionedDevices"] as? [String] ?? []
        guard let udid = devices.first else { return nil }
        let expiry = dict["ExpirationDate"] as? Date
        return Identity(udid: udid, expiration: expiry)
    }

    static var expirationDate: Date? { identity?.expiration }

    static func extractPlist(from data: Data) -> Data? {
        guard let startRange = data.range(of: Data("<?xml".utf8)),
              let endRange = data.range(of: Data("</plist>".utf8), options: [], in: startRange.upperBound..<data.endIndex) else {
            return nil
        }
        return data.subdata(in: startRange.lowerBound..<endRange.upperBound)
    }
}

// MARK: - Keychain

enum Keychain {
    static func save(_ value: String, service: String, account: String) {
        guard let data = value.data(using: .utf8) else { return }
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrService as String: service,
                                    kSecAttrAccount as String: account]
        SecItemDelete(query as CFDictionary)
        var add = query
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
        SecItemAdd(add as CFDictionary, nil)
    }

    static func load(service: String, account: String) -> String? {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrService as String: service,
                                    kSecAttrAccount as String: account,
                                    kSecReturnData as String: true,
                                    kSecMatchLimit as String: kSecMatchLimitOne]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    static func delete(service: String, account: String) {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrService as String: service,
                                    kSecAttrAccount as String: account]
        SecItemDelete(query as CFDictionary)
    }
}




