import UIKit

final class ServerSetupViewController: UIViewController, URLSessionDelegate {
    private let cardView = UIView()
    private let titleLabel = UILabel()
    private let subLabel = UILabel()
    private let urlField = UITextField()
    private let bgAlertsSwitch = UISwitch()
    private let testBtn = UIButton(type: .system)
    private let saveBtn = UIButton(type: .system)
    private let statusLabel = UILabel()
    private var testSession: URLSession!
    private var discoveredHost = ""
    private var discoveredFp = ""

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = UIColor(red: 0.96, green: 0.97, blue: 0.96, alpha: 1)
        title = "Server Setup"

        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 6
        testSession = URLSession(configuration: cfg, delegate: self, delegateQueue: nil)

        setupUI()
        let saved = CertPinStore.getServerUrl()
        urlField.text = saved.isEmpty ? "https://swarnshilp.local:8849" : saved
        bgAlertsSwitch.isOn = CertPinStore.isBgAlertsEnabled()
    }

    private func setupUI() {
        cardView.backgroundColor = .white
        cardView.layer.cornerRadius = 18
        cardView.layer.borderWidth = 1
        cardView.layer.borderColor = UIColor(white: 0.90, alpha: 1).cgColor
        cardView.layer.shadowColor = UIColor.black.cgColor
        cardView.layer.shadowOpacity = 0.08
        cardView.layer.shadowRadius = 18
        cardView.layer.shadowOffset = CGSize(width: 0, height: 6)
        cardView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(cardView)

        titleLabel.text = "Shree · Swarnshilp IT"
        titleLabel.font = .systemFont(ofSize: 22, weight: .heavy)
        titleLabel.textColor = UIColor(red: 0.08, green: 0.48, blue: 0.33, alpha: 1)

        subLabel.text = "Connect your iPhone or iPad to the Swarnshilp Ubuntu server (supports private self-signed LAN HTTPS automatically)."
        subLabel.font = .systemFont(ofSize: 13)
        subLabel.textColor = UIColor(white: 0.42, alpha: 1)
        subLabel.numberOfLines = 0

        urlField.placeholder = "https://192.168.1.10:8849 or http://swarnshilp.local:8848"
        urlField.borderStyle = .roundedRect
        urlField.autocapitalizationType = .none
        urlField.autocorrectionType = .no
        urlField.keyboardType = .URL
        urlField.returnKeyType = .done

        let bgRow = UIStackView()
        bgRow.axis = .horizontal
        bgRow.alignment = .center
        bgRow.spacing = 12
        let bgLbl = UILabel()
        bgLbl.text = "Enable Alert Notifications"
        bgLbl.font = .systemFont(ofSize: 14, weight: .semibold)
        bgLbl.textColor = UIColor(white: 0.16, alpha: 1)
        bgRow.addArrangedSubview(bgLbl)
        bgRow.addArrangedSubview(bgAlertsSwitch)

        testBtn.setTitle("Test Connection & SSL", for: .normal)
        testBtn.backgroundColor = UIColor(red: 0.93, green: 0.97, blue: 0.95, alpha: 1)
        testBtn.setTitleColor(UIColor(red: 0.08, green: 0.48, blue: 0.33, alpha: 1), for: .normal)
        testBtn.titleLabel?.font = .systemFont(ofSize: 14, weight: .bold)
        testBtn.layer.cornerRadius = 11
        testBtn.heightAnchor.constraint(equalToConstant: 44).isActive = true
        testBtn.addTarget(self, action: #selector(testPressed), for: .touchUpInside)

        saveBtn.setTitle("Connect & Open App →", for: .normal)
        saveBtn.backgroundColor = UIColor(red: 0.08, green: 0.48, blue: 0.33, alpha: 1)
        saveBtn.setTitleColor(.white, for: .normal)
        saveBtn.titleLabel?.font = .systemFont(ofSize: 15, weight: .bold)
        saveBtn.layer.cornerRadius = 11
        saveBtn.heightAnchor.constraint(equalToConstant: 48).isActive = true
        saveBtn.addTarget(self, action: #selector(savePressed), for: .touchUpInside)

        statusLabel.font = .systemFont(ofSize: 12)
        statusLabel.textColor = UIColor(white: 0.38, alpha: 1)
        statusLabel.numberOfLines = 0

        let stack = UIStackView(arrangedSubviews: [titleLabel, subLabel, urlField, bgRow, testBtn, saveBtn, statusLabel])
        stack.axis = .vertical
        stack.spacing = 14
        stack.translatesAutoresizingMaskIntoConstraints = false
        cardView.addSubview(stack)

        NSLayoutConstraint.activate([
            cardView.centerYAnchor.constraint(equalTo: view.safeAreaLayoutGuide.centerYAnchor),
            cardView.centerXAnchor.constraint(equalTo: view.safeAreaLayoutGuide.centerXAnchor),
            cardView.leadingAnchor.constraint(greaterThanOrEqualTo: view.safeAreaLayoutGuide.leadingAnchor, constant: 18),
            cardView.trailingAnchor.constraint(lessThanOrEqualTo: view.safeAreaLayoutGuide.trailingAnchor, constant: -18),
            cardView.widthAnchor.constraint(lessThanOrEqualToConstant: 480),
            cardView.widthAnchor.constraint(equalToConstant: 480).withPriority(.defaultHigh),

            stack.topAnchor.constraint(equalTo: cardView.topAnchor, constant: 24),
            stack.leadingAnchor.constraint(equalTo: cardView.leadingAnchor, constant: 22),
            stack.trailingAnchor.constraint(equalTo: cardView.trailingAnchor, constant: -22),
            stack.bottomAnchor.constraint(equalTo: cardView.bottomAnchor, constant: -24)
        ])
    }

    private func normalizedUrl() -> String? {
        var raw = (urlField.text ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        if raw.isEmpty { return nil }
        if !raw.lowercased().hasPrefix("http://") && !raw.lowercased().hasPrefix("https://") {
            raw = "https://" + raw
        }
        while raw.hasSuffix("/") { raw.removeLast() }
        return URL(string: raw)?.host != nil ? raw : nil
    }

    @objc private func testPressed() {
        guard let urlStr = normalizedUrl(), let url = URL(string: urlStr + "/api/public/portal-options") else {
            statusLabel.text = "Enter a valid server URL, e.g. https://192.168.1.10:8849"
            statusLabel.textColor = .systemRed
            return
        }
        discoveredHost = ""
        discoveredFp = ""
        statusLabel.text = "Checking server & SSL certificate..."
        statusLabel.textColor = .darkGray

        testSession.dataTask(with: url) { [weak self] _, response, error in
            DispatchQueue.main.async {
                guard let self = self else { return }
                if let err = error {
                    self.statusLabel.text = "Connection error: \(err.localizedDescription)"
                    self.statusLabel.textColor = .systemRed
                    return
                }
                let code = (response as? HTTPURLResponse)?.statusCode ?? 0
                if !self.discoveredFp.isEmpty {
                    self.statusLabel.text = "Reachable (HTTP \(code)). Self-signed cert PIN saved for \(self.discoveredHost)."
                } else {
                    self.statusLabel.text = "Server reachable cleanly (HTTP \(code))."
                }
                self.statusLabel.textColor = UIColor(red: 0.08, green: 0.48, blue: 0.33, alpha: 1)
            }
        }.resume()
    }

    @objc private func savePressed() {
        guard let urlStr = normalizedUrl() else {
            statusLabel.text = "Enter a valid server URL."
            statusLabel.textColor = .systemRed
            return
        }
        CertPinStore.saveServerUrl(urlStr)
        CertPinStore.setBgAlertsEnabled(bgAlertsSwitch.isOn)
        if !discoveredHost.isEmpty && !discoveredFp.isEmpty {
            CertPinStore.savePinnedCert(host: discoveredHost, fingerprint: discoveredFp)
        }
        if let nav = navigationController, nav.viewControllers.first !== self {
            nav.popViewController(animated: true)
            NotificationCenter.default.post(name: Notification.Name("ShreeServerUrlUpdated"), object: nil)
        } else if let window = view.window {
            window.rootViewController = MainViewController()
            UIView.transition(with: window, duration: 0.25, options: .transitionCrossDissolve, animations: nil)
        }
    }

    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
           let trust = challenge.protectionSpace.serverTrust {
            let fp = CertPinStore.sha256Fingerprint(trust: trust)
            let host = challenge.protectionSpace.host
            if !fp.isEmpty {
                discoveredHost = host
                discoveredFp = fp
                CertPinStore.savePinnedCert(host: host, fingerprint: fp)
            }
            completionHandler(.useCredential, URLCredential(trust: trust))
            return
        }
        completionHandler(.performDefaultHandling, nil)
    }
}

private extension NSLayoutConstraint {
    func withPriority(_ p: UILayoutPriority) -> NSLayoutConstraint {
        self.priority = p
        return self
    }
}
