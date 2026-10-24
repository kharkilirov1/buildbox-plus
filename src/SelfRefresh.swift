import Foundation
import UIKit
import BackgroundTasks
import UserNotifications

/// Keeps BuildBox's own free-developer signature alive.
///
/// A free Apple ID certificate/profile expires after 7 days. On launch (and in a
/// `BGAppRefreshTask`) this manager checks the embedded provisioning profile; when
/// fewer than two days remain it signs a fresh copy of the installed app with a new
/// account-issued profile and asks iOS to reinstall it through the local installer.
final class SelfRefreshManager: ObservableObject {
    static let shared = SelfRefreshManager()
    static let backgroundTaskIdentifier = "com.mikevillarroel.buildbox.refresh"
    private static let autoRefreshKey = "selfRefreshAuto"

    @Published private(set) var status = ""
    @Published private(set) var isRefreshing = false
    @Published private(set) var daysLeft: Int?
    @Published private(set) var needsRefresh = false
    @Published var autoRefreshEnabled: Bool {
        didSet { UserDefaults.standard.set(autoRefreshEnabled, forKey: Self.autoRefreshKey) }
    }

    private init() {
        autoRefreshEnabled = UserDefaults.standard.object(forKey: Self.autoRefreshKey) as? Bool ?? true
    }

    var signatureExpiry: Date? { EmbeddedProfile.expirationDate }

    func evaluate() {
        guard let expiry = signatureExpiry else {
            status = "No provisioning profile embedded — reinstall BuildBox with iLoader first"
            needsRefresh = false
            daysLeft = nil
            return
        }
        let remaining = expiry.timeIntervalSinceNow
        daysLeft = max(0, Int(remaining / 86_400))
        needsRefresh = remaining < 2 * 86_400
        if remaining <= 0 {
            status = "Signature expired"
        } else if needsRefresh {
            status = "Signature expires in \(daysLeft ?? 0) day(s)"
        } else {
            status = "Signature valid for \(daysLeft ?? 0) more day(s)"
        }
        if needsRefresh {
            scheduleExpiryNotification(expiry: expiry)
        }
    }

    // MARK: Background scheduling

    func registerBackgroundTask() {
        BGTaskScheduler.shared.register(forTaskWithIdentifier: Self.backgroundTaskIdentifier,
                                        using: nil) { task in
            guard let refreshTask = task as? BGAppRefreshTask else {
                task.setTaskCompleted(success: false)
                return
            }
            Self.shared.handleBackgroundRefresh(task: refreshTask)
        }
    }

    func scheduleBackgroundRefresh() {
        guard autoRefreshEnabled else { return }
        let request = BGAppRefreshTaskRequest(identifier: Self.backgroundTaskIdentifier)
        request.earliestBeginDate = Date(timeIntervalSinceNow: 6 * 3600)
        try? BGTaskScheduler.shared.submit(request)
    }

    private func handleBackgroundRefresh(task: BGAppRefreshTask) {
        evaluate()
        guard needsRefresh, AppleIDAuthService.shared.isLoggedIn else {
            task.setTaskCompleted(success: false)
            scheduleBackgroundRefresh()
            return
        }
        scheduleExpiryNotification(expiry: signatureExpiry ?? Date())
        startRefresh { _ in task.setTaskCompleted(success: true) }
    }

    // MARK: Refresh

    /// Called when the app becomes active: starts a refresh automatically when the
    /// signature is about to expire, an Apple ID is linked and auto-refresh is on.
    func autoRefreshIfNeeded() {
        evaluate()
        scheduleBackgroundRefresh()
        guard needsRefresh, autoRefreshEnabled,
              AppleIDAuthService.shared.isLoggedIn, !isRefreshing else { return }
        startRefresh { _ in }
    }

    func startRefresh(completion: @escaping (Result<Void, Error>) -> Void) {
        guard !isRefreshing else {
            completion(.failure(NSError(domain: "BuildBox", code: 2,
                                        userInfo: [NSLocalizedDescriptionKey: "Refresh already running"])))
            return
        }
        guard AppleIDAuthService.shared.isLoggedIn else {
            completion(.failure(NSError(domain: "BuildBox", code: 1,
                                        userInfo: [NSLocalizedDescriptionKey: "Sign in with an Apple ID first"])))
            return
        }
        isRefreshing = true
        status = "Preparing refresh…"

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            do {
                let ipa = try self.exportInstalledIPA()
                DispatchQueue.main.async {
                    self.status = "Signing with Apple ID…"
                    AppleIDAuthService.shared.sign(ipaURL: ipa) { result in
                        switch result {
                        case .success(let signed):
                            self.install(signed, completion: completion)
                        case .failure(let error):
                            self.isRefreshing = false
                            self.status = "Refresh failed: \(error.localizedDescription)"
                            completion(.failure(error))
                        }
                    }
                }
            } catch {
                DispatchQueue.main.async {
                    self.isRefreshing = false
                    self.status = "Refresh failed: \(error.localizedDescription)"
                    completion(.failure(error))
                }
            }
        }
    }

    /// Packages the currently installed .app so it can be re-signed with a fresh profile.
    private func exportInstalledIPA() throws -> URL {
        let fm = FileManager.default
        let work = fm.temporaryDirectory.appendingPathComponent("self-refresh-\(UUID().uuidString)", isDirectory: true)
        let payload = work.appendingPathComponent("Payload", isDirectory: true)
        try fm.createDirectory(at: payload, withIntermediateDirectories: true)

        let bundle = Bundle.main.bundleURL
        let dest = payload.appendingPathComponent(bundle.lastPathComponent, isDirectory: true)
        try fm.copyItem(at: bundle, to: dest)

        let output = fm.temporaryDirectory.appendingPathComponent("self-refresh-\(Int(Date().timeIntervalSince1970)).ipa")
        try? fm.removeItem(at: output)
        try IPASigner.shared.zip(sourceDir: work, to: output)
        try? fm.removeItem(at: work)
        return output
    }

    private func install(_ signed: AppleIDAuthService.SignedResult,
                         completion: @escaping (Result<Void, Error>) -> Void) {
        status = "Requesting install…"
        LocalInstaller.install(ipaURL: signed.ipaURL,
                               bundleID: signed.bundleID,
                               appName: signed.appName,
                               version: signed.version,
                               progress: { message in
                                   DispatchQueue.main.async { self.status = message }
                               },
                               completion: { result in
                                   DispatchQueue.main.async {
                                       self.isRefreshing = false
                                       switch result {
                                       case .success:
                                           self.status = "Install requested — confirm it in iOS"
                                           completion(.success(()))
                                       case .failure(let error):
                                           self.status = "Install failed: \(error.localizedDescription)"
                                           completion(.failure(error))
                                       }
                                   }
                               })
    }

    // MARK: Notifications

    private func scheduleExpiryNotification(expiry: Date) {
        let center = UNUserNotificationCenter.current()
        center.requestAuthorization(options: [.alert, .sound]) { _, _ in }
        center.removePendingNotificationRequests(withIdentifiers: ["buildbox.signature.expiry"])
        guard let days = daysLeft else { return }
        let content = UNMutableNotificationContent()
        content.title = "BuildBox signature expires soon"
        content.body = days <= 0 ? "Your signature expires today. Open BuildBox and refresh it."
                                 : "Your signature expires in \(days) day(s). Open BuildBox and refresh it."
        content.sound = .default
        let trigger = UNTimeIntervalNotificationTrigger(timeInterval: 5, repeats: false)
        let request = UNNotificationRequest(identifier: "buildbox.signature.expiry",
                                            content: content, trigger: trigger)
        center.add(request, withCompletionHandler: nil)
    }
}
