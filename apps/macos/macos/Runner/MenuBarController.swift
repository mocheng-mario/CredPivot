import Cocoa
import FlutterMacOS

final class MenuBarController {
  private var statusItem: NSStatusItem?
  private weak var appDelegate: AppDelegate?

  init(appDelegate: AppDelegate) {
    self.appDelegate = appDelegate
    statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    if let image = NSImage(named: "CredPivotStatusColor") {
      // 彩色资源必须保留原始颜色，模板模式会将其渲染成单色。
      image.isTemplate = false
      image.size = NSSize(width: 18, height: 18)
      statusItem?.button?.image = image
      statusItem?.button?.toolTip = "CredPivot"
      statusItem?.button?.setAccessibilityLabel("CredPivot")
    } else {
      statusItem?.button?.title = "CP"
    }
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
