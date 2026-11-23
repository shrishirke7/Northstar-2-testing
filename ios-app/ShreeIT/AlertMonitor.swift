import Foundation
import UserNotifications
import WebKit

final class AlertMonitor: NSObject, URLSessionDelegate {
    static let shared = AlertMonitor()
    private var timer: Timer?
    private var isForeground = false
    private var lastHistoryRev = ""
    private var lastTicketRev = ""
    private var lastNotifRev = ""
    private var lastAlertId = ""
    private var session: URLSession!

    private override init() {
        super.init()
        let cfg = URLSessionConfiguration.default
        cfg.timeoutIntervalForRequest = 6
        cfg.timeoutIntervalForResource = 10
        session = URLSession(configuration: cfg, delegate: self, delegateQueue: nil)
    }

    func setForeground(_ fg: Bool) {
        isForeground = fg
        if fg {
            startPolling()
        } else {
            pollOnce()
        }
    }

    func startPolling() {
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            self.timer?.invalidate()
            self.timer = Timer.scheduledTimer(withTimeInterval: 10.0, repeats: true) { [weak self] _ in
                self?.pollOnce()
            }
        }
    }

    func showLocalAlert(title: String, body: String, targetView: String, targetId: String) {
        let content = UNMutableNotificationContent()
        content.title = title.isEmpty ? "Shree IT Alert" : title
        content.body = body.isEmpty ? "New IT update received" : body
        content.sound = .default
        content.userInfo = [
            "targetView": targetView.isEmpty ? "notifications" : targetView,
            "targetId": targetId
        ]
        let req = UNNotificationRequest(
            identifier: "shree-\(Int(Date().timeIntervalSince1970 * 1000))-\(UUID().uuidString.prefix(6))",
            content: content,
            trigger: nil
        )
        UNUserNotificationCenter.current().add(req, withCompletionHandler: nil)
    }

    func pollOnce(completion: (() -> Void)? = nil) {
        guard CertPinStore.isBgAlertsEnabled() else {
            completion?()
            return
        }
        let baseUrl = CertPinStore.getServerUrl()
        guard let origin = CertPinStore.buildOrigin(from: baseUrl) else {
            completion?()
            return
        }

        readCookieHeader(for: origin) { [weak self] cookieHeader in
            guard let self = self else { completion?(); return }
            self.fetchJson(urlString: "\(origin)/api/live-pulse", cookie: cookieHeader) { obj in
                guard let obj = obj else { completion?(); return }
                let histRev = obj["historyRev"] as? String ?? ""
                let tickRev = obj["ticketRev"] as? String ?? ""
                let notifRev = obj["notificationsRev"] as? String ?? ""

                let changed = (!self.lastHistoryRev.isEmpty && histRev != self.lastHistoryRev)
                    || (!self.lastTicketRev.isEmpty && tickRev != self.lastTicketRev)
                    || (!self.lastNotifRev.isEmpty && notifRev != self.lastNotifRev)

                if !histRev.isEmpty { self.lastHistoryRev = histRev }
                if !tickRev.isEmpty { self.lastTicketRev = tickRev }
                if !notifRev.isEmpty { self.lastNotifRev = notifRev }

                if changed && !self.isForeground {
                    self.checkLatestNotification(origin: origin, cookie: cookieHeader, completion: completion)
                } else {
                    completion?()
                }
            }
        }
    }

    private func readCookieHeader(for origin: String, completion: @escaping (String?) -> Void) {
        DispatchQueue.main.async {
            WKWebsiteDataStore.default().httpCookieStore.getAllCookies { cookies in
                guard let host = URL(string: origin)?.host?.lowercased() else {
                    completion(nil)
                    return
                }
                let matched = cookies.filter { cookie in
                    let dom = cookie.domain.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
                    return host == dom || host.hasSuffix("." + dom)
                }
                if matched.isEmpty {
                    completion(nil)
                    return
                }
                let header = matched.map { "\($0.name)=\($0.value)" }.joined(separator: "; ")
                completion(header)
            }
        }
    }

    private func fetchJson(urlString: String, cookie: String?, completion: @escaping ([String: Any]?) -> Void) {
        guard let url = URL(string: urlString) else { completion(nil); return }
        var req = URLRequest(url: url)
        req.httpMethod = "GET"
        req.setValue("NorthstarIT", forHTTPHeaderField: "X-Requested-With")
        if let cookie = cookie, !cookie.isEmpty {
            req.setValue(cookie, forHTTPHeaderField: "Cookie")
        }
        session.dataTask(with: req) { data, response, _ in
            guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode),
                  let data = data,
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                completion(nil)
                return
            }
            completion(json)
        }.resume()
    }

    private func checkLatestNotification(origin: String, cookie: String?, completion: (() -> Void)?) {
        fetchJson(urlString: "\(origin)/api/notifications/history", cookie: cookie) { [weak self] obj in
            guard let self = self, let obj = obj else { completion?(); return }
            let events = obj["events"] as? [[String: Any]] ?? []
            guard let latest = events.first else { completion?(); return }
            let id = latest["id"] as? String ?? ""
            guard !id.isEmpty, id != self.lastAlertId else { completion?(); return }
            self.lastAlertId = id

            if (obj["silentMode"] as? Bool) == true { completion?(); return }
            if (latest["read"] as? Bool) == true { completion?(); return }

            let title = latest["title"] as? String ?? "Shree IT Alert"
            let body = latest["body"] as? String ?? "New IT update received"
            let kind = (latest["kind"] as? String ?? "").trimmingCharacters(in: .whitespaces).lowercased()
            let devType = (latest["deviceType"] as? String ?? "").trimmingCharacters(in: .whitespaces).lowercased()
            let devSub = (latest["deviceSubtype"] as? String ?? "").trimmingCharacters(in: .whitespaces).lowercased()
            let targetView = latest["targetView"] as? String ?? "notifications"
            let targetId = latest["targetId"] as? String ?? ""

            self.fetchJson(urlString: "\(origin)/api/notifications/sounds", cookie: cookie) { sObj in
                if let soundAlerts = sObj?["soundAlerts"] as? [String: Any] {
                    let evMap = soundAlerts["events"] as? [String: Any]
                    let evKey = (kind == "material_request" || kind == "helpdesk_message") ? "ticket" : kind
                    if let evRule = evMap?[evKey] as? [String: Any], (evRule["enabled"] as? Bool) == false {
                        completion?()
                        return
                    }
                    let devRules = soundAlerts["deviceRules"] as? [String: Any] ?? [:]
                    if kind == "visitor", let vr = devRules["visitor pass"] as? [String: Any], (vr["silent"] as? Bool) == true {
                        completion?()
                        return
                    }
                    if kind == "gatepass" {
                        let gr = (devRules["material entry"] as? [String: Any]) ?? (devRules["material gate entry"] as? [String: Any])
                        if (gr?["silent"] as? Bool) == true {
                            completion?()
                            return
                        }
                    }
                    let isDevEv = !devType.isEmpty || !devSub.isEmpty || kind == "online" || kind == "offline" || kind == "critical"
                    var anyMatched = false
                    let hay = "\(devSub) \(devType) \(title) \(body)".lowercased()
                    for (rk, rawRule) in devRules {
                        let kn = rk.trimmingCharacters(in: .whitespaces).lowercased()
                        guard !kn.isEmpty, let rule = rawRule as? [String: Any] else { continue }
                        let regex = try? NSRegularExpression(pattern: "(?:^|[^a-z0-9])\(NSRegularExpression.escapedPattern(for: kn))(?:$|[^a-z0-9])")
                        let range = NSRange(hay.startIndex..., in: hay)
                        let hit = (kn == devSub) || (kn == devType) || (regex?.firstMatch(in: hay, range: range) != nil)
                        if hit {
                            anyMatched = true
                            if (rule["silent"] as? Bool) == true {
                                completion?()
                                return
                            }
                        }
                    }
                    if isDevEv && !anyMatched && (soundAlerts["defaultNewTypeSilent"] as? Bool) == true {
                        completion?()
                        return
                    }
                }
                self.showLocalAlert(title: title, body: body, targetView: targetView, targetId: targetId)
                completion?()
            }
        }
    }

    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
           let trust = challenge.protectionSpace.serverTrust {
            let host = challenge.protectionSpace.host
            let fp = CertPinStore.sha256Fingerprint(trust: trust)
            if CertPinStore.isCertPinned(host: host, fingerprint: fp) {
                completionHandler(.useCredential, URLCredential(trust: trust))
                return
            }
        }
        completionHandler(.performDefaultHandling, nil)
    }
}
