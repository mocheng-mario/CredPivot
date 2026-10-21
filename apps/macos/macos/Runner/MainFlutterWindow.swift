import Cocoa
import FlutterMacOS

class MainFlutterWindow: NSWindow {
  override func awakeFromNib() {
    let flutterViewController = FlutterViewController()
    let windowFrame = frame
    self.contentViewController = flutterViewController
    setFrame(windowFrame, display: true)

    RegisterGeneratedPlugins(registry: flutterViewController)

    super.awakeFromNib()
    // 以最初 800×600 的内容区域为基准，最小宽高分别为 80% 和 70%。
    contentMinSize = NSSize(width: 640, height: 420)
    // 使用系统窗口自动保存，后台浏览器验证不会重置用户调整过的尺寸。
    if !setFrameUsingName("CredPivotMainWindow") {
      setContentSize(NSSize(width: 1200, height: 720))
      if let visibleFrame = screen?.visibleFrame ?? NSScreen.main?.visibleFrame {
        var fittingFrame = frame
        fittingFrame.size.width = min(fittingFrame.width, visibleFrame.width)
        fittingFrame.size.height = min(fittingFrame.height, visibleFrame.height)
        setFrame(fittingFrame, display: false)
      }
      center()
    }
    // 旧的窗口记录可能小于新下限，恢复时一并修正。
    let contentSize = contentRect(forFrameRect: frame).size
    if contentSize.width < contentMinSize.width || contentSize.height < contentMinSize.height {
      setContentSize(NSSize(width: max(contentSize.width, contentMinSize.width),
                            height: max(contentSize.height, contentMinSize.height)))
    }
    setFrameAutosaveName("CredPivotMainWindow")
    if AppDelegate.launchedForBrowser {
      orderOut(nil)
    }
  }

  override func close() {
    orderOut(nil)
    NSApp.setActivationPolicy(.accessory)
  }
}
