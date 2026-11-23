import UIKit
import WebKit
import AVFoundation
import UniformTypeIdentifiers

final class MainViewController: UIViewController,
                                WKNavigationDelegate,
                                WKUIDelegate,
                                WKScriptMessageHandler,
                                WKDownloadDelegate,
                                UIImagePickerControllerDelegate,
                                UINavigationControllerDelegate {

    private var webView: WKWebView!
    private var secureField: UITextField?
    private var secureHostView: UIView?
    private var progressView = UIProgressView(progressViewStyle: .bar)
    private var errorOverlay = UIView()
    private var errorDetailLabel = UILabel()
    private var configuredHost = ""

    private var pendingCamCallbackId = ""
    private var pendingAudioRecorder: AVAudioRecorder?
    private var pendingAudioUrl: URL?
    private var pendingVoiceCallbackId = ""
    private var downloadTempUrl: URL?

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = UIColor(red: 0.96, green: 0.97, blue: 0.96, alpha: 1)

        NotificationCenter.default.addObserver(self, selector: #selector(handleDeepLink(_:)), name: Notification.Name("ShreeDeepLinkNotification"), object: nil)
        NotificationCenter.default.addObserver(self, selector: #selector(handleServerUpdate), name: Notification.Name("ShreeServerUrlUpdated"), object: nil)
        NotificationCenter.default.addObserver(self, selector: #selector(screenCaptureChanged), name: UIScreen.capturedDidChangeNotification, object: nil)
        NotificationCenter.default.addObserver(self, selector: #selector(userTookScreenshot), name: UIApplication.userDidTakeScreenshotNotification, object: nil)

        setupWebView()
        setupProgressAndErrorUI()
        loadConfiguredServer()
    }

    private func setupWebView() {
        let userContent = WKUserContentController()
        userContent.add(self, name: "shreeBridge")

        let bridgeScript = """
        (function(){
          if(window.ShreeIOS) return;
          const post = (action, payload) => {
            try{ window.webkit.messageHandlers.shreeBridge.postMessage(Object.assign({action: action}, payload || {})); }catch(_){}
          };
          window.ShreeIOS = {
            notify: (title, body, targetView, targetId) => post('notify', {title: String(title||''), body: String(body||''), targetView: String(targetView||''), targetId: String(targetId||'')}),
            openServerSettings: () => post('openServerSettings'),
            getAppVersion: () => '1.0.7',
            setSecureScreen: (secure) => post('setSecureScreen', {secure: !!secure}),
            hasCameraSupport: () => true,
            hasNativeCamera: () => true,
            hasNativeVoiceRecorder: () => true,
            captureCameraPhoto: (facing, callbackId) => post('captureCameraPhoto', {facing: String(facing||'environment'), callbackId: String(callbackId||'')}),
            captureVoicePcm: (durationMs, callbackId) => post('captureVoicePcm', {durationMs: Number(durationMs||2400), callbackId: String(callbackId||'')})
          };
        })();
        """
        userContent.addUserScript(WKUserScript(source: bridgeScript, injectionTime: .atDocumentStart, forMainFrameOnly: false))

        let config = WKWebViewConfiguration()
        config.userContentController = userContent
        config.allowsInlineMediaPlayback = true
        config.mediaTypesRequiringUserActionForPlayback = []
        config.websiteDataStore = .default()

        let wv = WKWebView(frame: .zero, configuration: config)
        wv.navigationDelegate = self
        wv.uiDelegate = self
        wv.allowsBackForwardNavigationGestures = true
        wv.scrollView.contentInsetAdjustmentBehavior = .automatic
        wv.translatesAutoresizingMaskIntoConstraints = false
        self.webView = wv

        // Host WebView inside a secure-capable container for Apple screenshot/recording protection
        let tf = UITextField()
        tf.isSecureTextEntry = false
        tf.isUserInteractionEnabled = false
        tf.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(tf)
        NSLayoutConstraint.activate([
            tf.topAnchor.constraint(equalTo: view.topAnchor),
            tf.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            tf.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            tf.bottomAnchor.constraint(equalTo: view.bottomAnchor)
        ])
        self.secureField = tf

        let container = tf.subviews.first ?? view!
        self.secureHostView = container
        if container !== view {
            container.isUserInteractionEnabled = true
            container.addSubview(wv)
        } else {
            view.addSubview(wv)
        }

        NSLayoutConstraint.activate([
            wv.topAnchor.constraint(equalTo: container.topAnchor),
            wv.leadingAnchor.constraint(equalTo: container.leadingAnchor),
            wv.trailingAnchor.constraint(equalTo: container.trailingAnchor),
            wv.bottomAnchor.constraint(equalTo: container.bottomAnchor)
        ])

        wv.addObserver(self, forKeyPath: #keyPath(WKWebView.estimatedProgress), options: .new, context: nil)
    }

    private func setupProgressAndErrorUI() {
        progressView.progressTintColor = UIColor(red: 0.08, green: 0.48, blue: 0.33, alpha: 1)
        progressView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(progressView)
        NSLayoutConstraint.activate([
            progressView.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            progressView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            progressView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            progressView.heightAnchor.constraint(equalToConstant: 2.5)
        ])

        errorOverlay.backgroundColor = view.backgroundColor
        errorOverlay.isHidden = true
        errorOverlay.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(errorOverlay)

        let title = UILabel()
        title.text = "Unable to connect to Shree Server"
        title.font = .systemFont(ofSize: 19, weight: .bold)
        title.textAlignment = .center

        errorDetailLabel.font = .systemFont(ofSize: 13)
        errorDetailLabel.textColor = .secondaryLabel
        errorDetailLabel.numberOfLines = 0
        errorDetailLabel.textAlignment = .center

        let retryBtn = UIButton(type: .system)
        retryBtn.setTitle("Retry Connection", for: .normal)
        retryBtn.backgroundColor = UIColor(red: 0.08, green: 0.48, blue: 0.33, alpha: 1)
        retryBtn.setTitleColor(.white, for: .normal)
        retryBtn.layer.cornerRadius = 10
        retryBtn.heightAnchor.constraint(equalToConstant: 44).isActive = true
        retryBtn.addTarget(self, action: #selector(retryLoad), for: .touchUpInside)

        let setupBtn = UIButton(type: .system)
        setupBtn.setTitle("Change Server URL", for: .normal)
        setupBtn.heightAnchor.constraint(equalToConstant: 40).isActive = true
        setupBtn.addTarget(self, action: #selector(openServerSettings), for: .touchUpInside)

        let stack = UIStackView(arrangedSubviews: [title, errorDetailLabel, retryBtn, setupBtn])
        stack.axis = .vertical
        stack.spacing = 12
        stack.translatesAutoresizingMaskIntoConstraints = false
        errorOverlay.addSubview(stack)

        NSLayoutConstraint.activate([
            errorOverlay.topAnchor.constraint(equalTo: view.topAnchor),
            errorOverlay.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            errorOverlay.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            errorOverlay.bottomAnchor.constraint(equalTo: view.bottomAnchor),

            stack.centerYAnchor.constraint(equalTo: errorOverlay.centerYAnchor),
            stack.leadingAnchor.constraint(equalTo: errorOverlay.safeAreaLayoutGuide.leadingAnchor, constant: 28),
            stack.trailingAnchor.constraint(equalTo: errorOverlay.safeAreaLayoutGuide.trailingAnchor, constant: -28)
        ])
    }

    private func loadConfiguredServer() {
        let raw = CertPinStore.getServerUrl()
        guard let url = URL(string: raw) else {
            openServerSettings()
            return
        }
        configuredHost = url.host ?? ""
        errorOverlay.isHidden = true
        webView.load(URLRequest(url: url))
    }

    @objc private func retryLoad() {
        loadConfiguredServer()
    }

    @objc private func openServerSettings() {
        let vc = ServerSetupViewController()
        let nav = UINavigationController(rootViewController: vc)
        nav.modalPresentationStyle = .formSheet
        present(nav, animated: true)
    }

    @objc private func handleServerUpdate() {
        loadConfiguredServer()
    }

    @objc private func screenCaptureChanged() {
        guard secureField?.isSecureTextEntry == true, UIScreen.main.isCaptured else { return }
        webView.evaluateJavaScript("if(window.nsVaultModule&&nsVaultModule.engagePrivacyVeil){nsVaultModule.engagePrivacyVeil('iOS screen recording or mirroring blocked by Vault Privacy Shield','ios_capture');}else if(document.getElementById('nsVaultPrivacyVeil')){document.getElementById('nsVaultPrivacyVeil').classList.add('active');document.body.classList.add('ns-vault-shielded');}", completionHandler: nil)
    }

    @objc private func userTookScreenshot() {
        guard secureField?.isSecureTextEntry == true else { return }
        webView.evaluateJavaScript("if(window.nsVaultModule&&nsVaultModule.engagePrivacyVeil){nsVaultModule.engagePrivacyVeil('iOS screenshot attempt blocked by Vault Privacy Shield','ios_screenshot');}else if(document.getElementById('nsVaultPrivacyVeil')){document.getElementById('nsVaultPrivacyVeil').classList.add('active');document.body.classList.add('ns-vault-shielded');}", completionHandler: nil)
    }

    @objc private func handleDeepLink(_ note: Notification) {
        let targetView = note.userInfo?["targetView"] as? String ?? ""
        let targetId = note.userInfo?["targetId"] as? String ?? ""
        guard !targetView.isEmpty else { return }
        let js = """
        if(\(jsonLiteral(targetView)) === 'messages' && typeof window.openHelpdeskMessages==='function'){
          setTimeout(function(){window.openHelpdeskMessages({threadId:\(jsonLiteral(targetId))});}, 250);
        } else {
          if(typeof window.go==='function'){window.go(\(jsonLiteral(targetView)));}
          if(\(jsonLiteral(targetId)) && typeof window.jumpToTicketInQueue==='function'){
            setTimeout(function(){window.jumpToTicketInQueue(\(jsonLiteral(targetId)));}, 300);
          }
        }
        """
        webView.evaluateJavaScript(js, completionHandler: nil)
    }

    override func observeValue(forKeyPath keyPath: String?, of object: Any?, change: [NSKeyValueChangeKey: Any]?, context: UnsafeMutableRawPointer?) {
        if keyPath == #keyPath(WKWebView.estimatedProgress) {
            let p = Float(webView.estimatedProgress)
            progressView.isHidden = p >= 1.0
            progressView.setProgress(p, animated: true)
        }
    }

    // MARK: - JS Bridge
    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        guard message.name == "shreeBridge", let dict = message.body as? [String: Any],
              let action = dict["action"] as? String else { return }

        switch action {
        case "notify":
            AlertMonitor.shared.showLocalAlert(
                title: dict["title"] as? String ?? "Shree IT Alert",
                body: dict["body"] as? String ?? "",
                targetView: dict["targetView"] as? String ?? "notifications",
                targetId: dict["targetId"] as? String ?? ""
            )
        case "openServerSettings":
            openServerSettings()
        case "setSecureScreen":
            let sec = (dict["secure"] as? Bool) ?? false
            secureField?.isSecureTextEntry = sec
            if sec && UIScreen.main.isCaptured {
                screenCaptureChanged()
            }
        case "captureCameraPhoto":
            let facing = dict["facing"] as? String ?? "environment"
            let cbId = dict["callbackId"] as? String ?? ""
            startNativeCamera(facing: facing, callbackId: cbId)
        case "captureVoicePcm":
            let ms = dict["durationMs"] as? Int ?? 2400
            let cbId = dict["callbackId"] as? String ?? ""
            startVoiceCapture(durationMs: ms, callbackId: cbId)
        default:
            break
        }
    }

    // MARK: - Native Camera
    private func startNativeCamera(facing: String, callbackId: String) {
        pendingCamCallbackId = callbackId
        let status = AVCaptureDevice.authorizationStatus(for: .video)
        if status == .notDetermined {
            AVCaptureDevice.requestAccess(for: .video) { [weak self] granted in
                DispatchQueue.main.async {
                    if granted { self?.presentPicker(facing: facing) }
                }
            }
            return
        }
        presentPicker(facing: facing)
    }

    private func presentPicker(facing: String) {
        let picker = UIImagePickerController()
        picker.delegate = self
        if UIImagePickerController.isSourceTypeAvailable(.camera) {
            picker.sourceType = .camera
            picker.cameraDevice = (facing == "user" && UIImagePickerController.isCameraDeviceAvailable(.front)) ? .front : .rear
        } else {
            picker.sourceType = .photoLibrary
        }
        if UIDevice.current.userInterfaceIdiom == .pad {
            picker.modalPresentationStyle = .formSheet
        }
        present(picker, animated: true)
    }

    func imagePickerControllerDidCancel(_ picker: UIImagePickerController) {
        picker.dismiss(animated: true)
        pendingCamCallbackId = ""
    }

    func imagePickerController(_ picker: UIImagePickerController, didFinishPickingMediaWithInfo info: [UIImagePickerController.InfoKey: Any]) {
        picker.dismiss(animated: true)
        let cbId = pendingCamCallbackId
        pendingCamCallbackId = ""
        guard !cbId.isEmpty, let img = (info[.originalImage] as? UIImage)?.normalizedUp() else { return }

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let maxSide: CGFloat = 1400
            let scale = min(1.0, maxSide / max(img.size.width, img.size.height))
            let targetSize = CGSize(width: round(img.size.width * scale), height: round(img.size.height * scale))
            let renderer = UIGraphicsImageRenderer(size: targetSize)
            let resized = renderer.image { _ in img.draw(in: CGRect(origin: .zero, size: targetSize)) }
            guard let jpeg = resized.jpegData(compressionQuality: 0.85) else { return }
            let dataUrl = "data:image/jpeg;base64," + jpeg.base64EncodedString()
            DispatchQueue.main.async {
                let js = "if(typeof window.__shreeReceiveNativePhoto==='function'){window.__shreeReceiveNativePhoto(\(self?.jsonLiteral(cbId) ?? "''"),\(self?.jsonLiteral(dataUrl) ?? "''"));}"
                self?.webView.evaluateJavaScript(js, completionHandler: nil)
            }
        }
    }

    // MARK: - Native Voice Lock PCM Capture
    private func startVoiceCapture(durationMs: Int, callbackId: String) {
        pendingVoiceCallbackId = callbackId
        AVAudioSession.sharedInstance().requestRecordPermission { [weak self] granted in
            DispatchQueue.main.async {
                guard let self = self, granted else {
                    self?.deliverVoicePcm(callbackId: callbackId, b64: "")
                    return
                }
                self.recordPcm(durationMs: durationMs, callbackId: callbackId)
            }
        }
    }

    private func recordPcm(durationMs: Int, callbackId: String) {
        do {
            let session = AVAudioSession.sharedInstance()
            try session.setCategory(.playAndRecord, mode: .measurement, options: [.defaultToSpeaker])
            try session.setActive(true)

            let tmpUrl = FileManager.default.temporaryDirectory.appendingPathComponent("voice_\(UUID().uuidString).wav")
            let settings: [String: Any] = [
                AVFormatIDKey: Int(kAudioFormatLinearPCM),
                AVSampleRateKey: 16000.0,
                AVNumberOfChannelsKey: 1,
                AVLinearPCMBitDepthKey: 16,
                AVLinearPCMIsBigEndianKey: false,
                AVLinearPCMIsFloatKey: false
            ]
            let recorder = try AVAudioRecorder(url: tmpUrl, settings: settings)
            pendingAudioRecorder = recorder
            pendingAudioUrl = tmpUrl
            recorder.record()

            let sec = Double(max(1000, min(8000, durationMs))) / 1000.0
            DispatchQueue.main.asyncAfter(deadline: .now() + sec) { [weak self] in
                guard let self = self else { return }
                self.pendingAudioRecorder?.stop()
                self.pendingAudioRecorder = nil
                guard let url = self.pendingAudioUrl, let data = try? Data(contentsOf: url), data.count > 44 else {
                    self.deliverVoicePcm(callbackId: callbackId, b64: "")
                    return
                }
                try? FileManager.default.removeItem(at: url)
                let pcmData = data.subdata(in: 44..<data.count)
                self.deliverVoicePcm(callbackId: callbackId, b64: pcmData.base64EncodedString())
            }
        } catch {
            deliverVoicePcm(callbackId: callbackId, b64: "")
        }
    }

    private func deliverVoicePcm(callbackId: String, b64: String) {
        let js = "if(typeof window.__shreeReceiveVoicePcm==='function'){window.__shreeReceiveVoicePcm(\(jsonLiteral(callbackId)),\(jsonLiteral(b64)),16000);}"
        DispatchQueue.main.async { [weak self] in
            self?.webView.evaluateJavaScript(js, completionHandler: nil)
        }
    }

    // MARK: - SSL Trust & Downloads
    func webView(_ webView: WKWebView, didReceive challenge: URLAuthenticationChallenge,
                 completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
           let trust = challenge.protectionSpace.serverTrust {
            let host = challenge.protectionSpace.host
            let fp = CertPinStore.sha256Fingerprint(trust: trust)
            if !fp.isEmpty && CertPinStore.isCertPinned(host: host, fingerprint: fp) {
                completionHandler(.useCredential, URLCredential(trust: trust))
                return
            }
            DispatchQueue.main.async { [weak self] in
                guard let self = self else {
                    completionHandler(.cancelAuthenticationChallenge, nil)
                    return
                }
                let alert = UIAlertController(
                    title: "Trust Office Server?",
                    message: "Host: \(host)\nSHA-256: \(fp.isEmpty ? "(unavailable)" : fp)\n\nTrust & pin this certificate for your local Swarnshilp server?",
                    preferredStyle: .alert
                )
                alert.addAction(UIAlertAction(title: "Trust & Connect", style: .default) { _ in
                    if !fp.isEmpty { CertPinStore.savePinnedCert(host: host, fingerprint: fp) }
                    completionHandler(.useCredential, URLCredential(trust: trust))
                })
                alert.addAction(UIAlertAction(title: "Cancel", style: .cancel) { _ in
                    completionHandler(.cancelAuthenticationChallenge, nil)
                })
                self.present(alert, animated: true)
            }
            return
        }
        completionHandler(.performDefaultHandling, nil)
    }

    func webView(_ webView: WKWebView, decidePolicyFor navigationResponse: WKNavigationResponse,
                 decisionHandler: @escaping (WKNavigationResponsePolicy) -> Void) {
        if let http = navigationResponse.response as? HTTPURLResponse {
            let disp = (http.allHeaderFields["Content-Disposition"] as? String ?? "").lowercased()
            if disp.contains("attachment") {
                decisionHandler(.download)
                return
            }
        }
        decisionHandler(.allow)
    }

    func webView(_ webView: WKWebView, navigationResponse: WKNavigationResponse, didBecome download: WKDownload) {
        download.delegate = self
    }

    func download(_ download: WKDownload, decideDestinationUsing response: URLResponse, suggestedFilename: String,
                  completionHandler: @escaping (URL?) -> Void) {
        let dest = FileManager.default.temporaryDirectory.appendingPathComponent(suggestedFilename)
        try? FileManager.default.removeItem(at: dest)
        downloadTempUrl = dest
        completionHandler(dest)
    }

    func downloadDidFinish(_ download: WKDownload) {
        guard let url = downloadTempUrl else { return }
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            let vc = UIActivityViewController(activityItems: [url], applicationActivities: nil)
            if let pop = vc.popoverPresentationController {
                pop.sourceView = self.view
                pop.sourceRect = CGRect(x: self.view.bounds.midX, y: self.view.bounds.midY, width: 1, height: 1)
            }
            self.present(vc, animated: true)
        }
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        errorDetailLabel.text = "Server: \(CertPinStore.getServerUrl())\nError: \(error.localizedDescription)"
        errorOverlay.isHidden = false
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        errorOverlay.isHidden = true
    }

    private func jsonLiteral(_ value: String) -> String {
        if let data = try? JSONSerialization.data(withJSONObject: [value]),
           let str = String(data: data, encoding: .utf8), str.count >= 2 {
            return String(str.dropFirst().dropLast())
        }
        return "\"\""
    }
}

private extension UIImage {
    func normalizedUp() -> UIImage {
        if imageOrientation == .up { return self }
        let renderer = UIGraphicsImageRenderer(size: size)
        return renderer.image { _ in draw(in: CGRect(origin: .zero, size: size)) }
    }
}
