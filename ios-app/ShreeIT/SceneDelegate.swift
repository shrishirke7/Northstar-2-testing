import UIKit

class SceneDelegate: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?

    func scene(_ scene: UIScene,
               willConnectTo session: UISceneSession,
               options connectionOptions: UIScene.ConnectionOptions) {
        guard let windowScene = scene as? UIWindowScene else { return }
        let window = UIWindow(windowScene: windowScene)

        let url = CertPinStore.getServerUrl()
        let rootVC: UIViewController = url.isEmpty
            ? UINavigationController(rootViewController: ServerSetupViewController())
            : MainViewController()

        window.rootViewController = rootVC
        window.makeKeyAndVisible()
        self.window = window
    }

    func sceneDidBecomeActive(_ scene: UIScene) {
        AlertMonitor.shared.setForeground(true)
    }

    func sceneWillResignActive(_ scene: UIScene) {
        AlertMonitor.shared.setForeground(false)
        AppDelegate.scheduleBackgroundRefresh()
    }

    func sceneDidEnterBackground(_ scene: UIScene) {
        AlertMonitor.shared.setForeground(false)
        AppDelegate.scheduleBackgroundRefresh()
    }
}
