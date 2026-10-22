import Cocoa
import FlutterMacOS

final class MenuBarController {
  private var statusItem: NSStatusItem?
  private weak var appDelegate: AppDelegate?

  init(appDelegate: AppDelegate) {
    self.appDelegate = appDelegate
    statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    statusItem?.button?.title = "CP"
    let menu = NSMenu()
    let showItem = NSMenuItem(title: "显示 CredPivot", action: #selector(AppDelegate.showMainWindow), keyEquivalent: "")
    showItem.target = appDelegate
    let lockItem = NSMenuItem(title: "锁定 Vault", action: #selector(AppDelegate.lockFromMenu), keyEquivalent: "")
    lockItem.target = appDelegate
    let quitItem = NSMenuItem(title: "退出 CredPivot", action: #selector(AppDelegate.quitApp), keyEquivalent: "q")
    quitItem.target = appDelegate
    menu.addItem(showItem)
    menu.addItem(lockItem)
    menu.addItem(.separator())
    menu.addItem(quitItem)
    statusItem?.menu = menu
  }
}
