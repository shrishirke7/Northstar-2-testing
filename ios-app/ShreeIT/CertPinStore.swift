import Foundation
import CryptoKit
import Security

enum CertPinStore {
    private static let serverUrlKey = "shree_ios_server_url"
    private static let bgAlertsKey = "shree_ios_bg_alerts"
    private static let pinsKey = "shree_ios_pinned_certs"

    static func getServerUrl() -> String {
        return (UserDefaults.standard.string(forKey: serverUrlKey) ?? "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    static func saveServerUrl(_ url: String) {
        UserDefaults.standard.set(url.trimmingCharacters(in: .whitespacesAndNewlines), forKey: serverUrlKey)
    }

    static func isBgAlertsEnabled() -> Bool {
        if UserDefaults.standard.object(forKey: bgAlertsKey) == nil {
            return true
        }
        return UserDefaults.standard.bool(forKey: bgAlertsKey)
    }

    static func setBgAlertsEnabled(_ enabled: Bool) {
        UserDefaults.standard.set(enabled, forKey: bgAlertsKey)
    }

    static func sha256Fingerprint(trust: SecTrust) -> String {
        let count = SecTrustGetCertificateCount(trust)
        guard count > 0, let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate], let leaf = chain.first else {
            return ""
        }
        let data = SecCertificateCopyData(leaf) as Data
        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02X", $0) }.joined(separator: ":")
    }

    static func isCertPinned(host: String, fingerprint: String) -> Bool {
        guard !host.isEmpty, !fingerprint.isEmpty else { return false }
        let dict = UserDefaults.standard.dictionary(forKey: pinsKey) as? [String: String] ?? [:]
        return dict[host.lowercased()]?.caseInsensitiveCompare(fingerprint) == .orderedSame
    }

    static func savePinnedCert(host: String, fingerprint: String) {
        guard !host.isEmpty, !fingerprint.isEmpty else { return }
        var dict = UserDefaults.standard.dictionary(forKey: pinsKey) as? [String: String] ?? [:]
        dict[host.lowercased()] = fingerprint
        UserDefaults.standard.set(dict, forKey: pinsKey)
    }

    static func buildOrigin(from rawUrl: String) -> String? {
        guard let url = URL(string: rawUrl), let scheme = url.scheme, let host = url.host else {
            return nil
        }
        if let port = url.port {
            return "\(scheme)://\(host):\(port)"
        }
        return "\(scheme)://\(host)"
    }
}
