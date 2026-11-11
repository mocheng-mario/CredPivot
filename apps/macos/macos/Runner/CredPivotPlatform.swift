import Cocoa
import Vision
import Darwin
import notify
import CryptoKit
import FlutterMacOS
import UniformTypeIdentifiers
import LocalAuthentication
import Security
import ServiceManagement

// MARK: - WebDAV 密文传输。认证信息不写入 settings.json、保险库或诊断日志。

private struct WebDAVFailure: Error {
  let key: String
  let retryAfter: Int?
  let stage: String?
  let status: Int?
  let statuses: [Int]?
  init(_ key: String, retryAfter: Int? = nil, stage: String? = nil, status: Int? = nil, statuses: [Int]? = nil) {
    self.key = key; self.retryAfter = retryAfter; self.stage = stage; self.status = status; self.statuses = statuses
  }
}

private enum WebDAVProviderPolicy: Equatable {
  case standard, nutstore

  init(_ config: [String: Any]) {
    // 未确认有差异的提供方继续按标准探测，不仅凭渠道名称假定服务端能力。
    self = config["provider"] as? String == "nutstore" ? .nutstore : .standard
  }

  func rejectsMoveOverwrite(_ status: Int) -> Bool {
    // 兼容坚果云以 409 拒绝覆盖的实现；还必须实测源、目标未变及并发只有一个赢家。
    status == 412 || (self == .nutstore && status == 409)
  }
}

private final class WebDAVTransfer: NSObject, URLSessionDataDelegate {
  struct Reply { let data: Data; let response: HTTPURLResponse }
  private var buffer = Data()
  private var response: HTTPURLResponse?
  private var continuation: CheckedContinuation<Reply, Error>?
  private var failure: Error?
  private let limit: Int
  private var session: URLSession?
  private let sessionLock = NSLock()
  private var cancelled = false
  init(limit: Int) { self.limit = limit }

  func run(_ request: URLRequest) async throws -> Reply {
    let configuration = URLSessionConfiguration.ephemeral
    configuration.urlCache = nil
    configuration.urlCredentialStorage = nil
    configuration.httpCookieStorage = nil
    configuration.httpShouldSetCookies = false
    configuration.timeoutIntervalForRequest = 45
    configuration.timeoutIntervalForResource = 120
    return try await withTaskCancellationHandler(operation: {
      try await withCheckedThrowingContinuation { continuation in
        self.continuation = continuation
        let session = URLSession(configuration: configuration, delegate: self, delegateQueue: nil)
        let task = session.dataTask(with: request)
        self.sessionLock.lock()
        self.session = session
        let cancelled = self.cancelled
        self.sessionLock.unlock()
        task.resume()
        if cancelled { session.invalidateAndCancel() }
      }
    }, onCancel: { self.cancel() })
  }
  func cancel() {
    sessionLock.lock(); cancelled = true; let session = self.session; sessionLock.unlock()
    session?.invalidateAndCancel()
  }
  func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                  newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
    // 不把应用密码转发给重定向目标，也不允许 HTTPS 降级。
    completionHandler(nil)
  }
  func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
                  completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
    guard let response = response as? HTTPURLResponse,
          response.expectedContentLength <= Int64(limit) else {
      failure = WebDAVFailure("sync.errors.responseTooLarge")
      completionHandler(.cancel)
      return
    }
    self.response = response
    completionHandler(.allow)
  }
  func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
    guard data.count <= limit - buffer.count else {
      failure = WebDAVFailure("sync.errors.responseTooLarge")
      dataTask.cancel()
      return
    }
    buffer.append(data)
  }
  func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
    let continuation = self.continuation
    self.continuation = nil
    if let error = failure ?? error { continuation?.resume(throwing: error) }
    else if let response = response { continuation?.resume(returning: Reply(data: buffer, response: response)) }
    else { continuation?.resume(throwing: WebDAVFailure("sync.errors.network")) }
    session.finishTasksAndInvalidate()
    sessionLock.lock(); self.session = nil; sessionLock.unlock()
  }
}

private final class WebDAVCollection: NSObject, XMLParserDelegate {
  var collection = false
  private let expected: URL
  private var href = ""
  private var inHref = false
  private var responseCollection = false
  private var inProperties = false
  private var inResourceType = false
  private var inStatus = false
  private var isCollection = false
  private var status = ""
  init(expected: URL) { self.expected = expected }
  func parser(_ parser: XMLParser, didStartElement elementName: String, namespaceURI: String?,
              qualifiedName qName: String?, attributes attributeDict: [String: String] = [:]) {
    guard namespaceURI == "DAV:" else { return }
    if elementName == "response" { href = ""; responseCollection = false }
    if elementName == "href" { inHref = true }
    if elementName == "propstat" { inProperties = true; isCollection = false; status = "" }
    if elementName == "resourcetype", inProperties { inResourceType = true }
    if elementName == "collection", inResourceType { isCollection = true }
    if elementName == "status", inProperties { inStatus = true }
  }
  func parser(_ parser: XMLParser, foundCharacters string: String) {
    if inStatus { status += string }
    if inHref { href += string }
  }
  func parser(_ parser: XMLParser, didEndElement elementName: String, namespaceURI: String?, qualifiedName qName: String?) {
    guard namespaceURI == "DAV:" else { return }
    if elementName == "href" { inHref = false }
    if elementName == "status" { inStatus = false }
    if elementName == "resourcetype" { inResourceType = false }
    if elementName == "propstat" {
      // 失败的 propstat 中出现 collection 不能证明目录存在。
      if isCollection, status.split(whereSeparator: { $0.isWhitespace }).dropFirst().first == "200" { responseCollection = true }
      inProperties = false
    }
    if elementName == "response", responseCollection,
       let observed = URL(string:href.trimmingCharacters(in:.whitespacesAndNewlines),relativeTo:expected)?.absoluteURL,
       observed.scheme?.lowercased() == expected.scheme?.lowercased(), observed.host?.lowercased() == expected.host?.lowercased(),
       (observed.port ?? 443) == (expected.port ?? 443), observed.query == nil, observed.fragment == nil,
       (observed.path == expected.path || observed.path + "/" == expected.path || observed.path == expected.path + "/") {
      collection = true
    }
  }
}

// 只接收 DAV 成功属性；缺少属性或无法辨认的目录项不能作为删除依据。
private final class WebDAVListing: NSObject, XMLParserDelegate {
  struct Entry {
    let href: String
    let properties: [String: String]
    let collection: Bool
  }
  var entries: [Entry] = []
  var valid = true
  private var href = "", field = "", text = "", status = ""
  private var properties: [String: String] = [:], pending: [String: String] = [:]
  private var inResponse = false, inProperties = false, isCollection = false, pendingCollection = false
  private var multistatus = false
  func parser(_ parser: XMLParser, didStartElement name: String, namespaceURI: String?,
              qualifiedName qName: String?, attributes: [String: String] = [:]) {
    guard namespaceURI == "DAV:" else { return }
    if name == "multistatus" { multistatus = true }
    if name == "response" {
      if inResponse { valid = false }
      inResponse = true; href = ""; properties = [:]; isCollection = false
    }
    if name == "propstat" { inProperties = true; pending = [:]; pendingCollection = false; status = "" }
    if name == "collection", inProperties { pendingCollection = true }
    if ["href", "status", "getetag", "getlastmodified", "resourcetype"].contains(name) {
      field = name; text = ""
    }
    if name == "error" || name == "number-of-matches-within-limits" { valid = false }
  }
  func parser(_ parser: XMLParser, foundCharacters string: String) { text += string }
  func parser(_ parser: XMLParser, didEndElement name: String, namespaceURI: String?, qualifiedName qName: String?) {
    guard namespaceURI == "DAV:" else { return }
    if name == field {
      let value = text.trimmingCharacters(in:.whitespacesAndNewlines)
      if name == "href" { href = value }
      else if name == "status" {
        if inProperties { status = value }
        else if value.split(whereSeparator: { $0.isWhitespace }).dropFirst().first != "200" { valid = false }
      } else if inProperties { pending[name] = value }
      field = ""; text = ""
    }
    if name == "propstat" {
      if status.split(whereSeparator: { $0.isWhitespace }).dropFirst().first == "200" {
        properties.merge(pending) { _, new in new }; isCollection = isCollection || pendingCollection
      }
      inProperties = false
    }
    if name == "response" {
      if href.isEmpty || properties["resourcetype"] == nil { valid = false }
      entries.append(Entry(href:href,properties:properties,collection:isCollection)); inResponse = false
    }
  }
  func parserDidEndDocument(_ parser: XMLParser) { valid = valid && multistatus && !inResponse }
}

@MainActor private final class CredPivotWebDAV {
  static let shared = CredPivotWebDAV()
  private let service = "io.credpivot.webdav"
  private var busy = false
  private var transfers: [UUID: WebDAVTransfer] = [:]
  private var generation = 0
  private var cancellationKey = "sync.errors.locked"
  private var rateLimits: [String: Date] = [:]
  private let maxSnapshot = 64 * 1024 * 1024
  // 能力只缓存于当前解锁会话，切换服务器或重新启动后必须重新探测。
  private var writeCapabilities: (location: String, policy: WebDAVProviderPolicy, createOnly: Bool, initialCreation: String)?
  private var cleanupLocation = ""
  private var cleanupDue = Date.distantPast
  private var cleanupReferences: [String: HistoryReference] = [:]
  private var cleanupDeleteVerified = false
  private var cleanupRequests = 0
  // 仅记录本机生成的随机临时路径；不是用户配置，也不保存认证信息或文件内容。
  private let probeJournalKey = "credpivot.webdav.pendingProbes"
  private let testDirectoryRoot = ".credpivot-tests"
  private func testDirectoryPath(_ path: String) -> Bool {
    let container = testDirectoryRoot + "/"
    guard path.hasPrefix(container) else { return false }
    let name = String(path.dropFirst(container.count))
    let prefix = ".credpivot-test-"
    return name.hasPrefix(prefix) && UUID(uuidString:String(name.dropFirst(prefix.count))) != nil
  }
  private func probePath(_ path: String) -> Bool {
    let prefix = ".credpivot-probe-"
    return testDirectoryPath(path) || (path.hasPrefix(prefix) && UUID(uuidString:String(path.dropFirst(prefix.count))) != nil)
  }
  private func recordProbe(_ config: [String: Any], path: String, pending: Bool) {
    guard probePath(path), let location = config["location"] as? String else { return }
    var journal = UserDefaults.standard.dictionary(forKey:probeJournalKey) as? [String:[String:Double]] ?? [:]
    var paths = journal[location] ?? [:]
    if pending {
      if paths[path] == nil { paths[path] = Date().timeIntervalSince1970 }
      // 限制本机重试账本大小；测试目录中的未知内容始终保留，不递归清理。
      while paths.count > 256, let oldest = paths.min(by: { $0.value < $1.value })?.key { paths.removeValue(forKey:oldest) }
    } else { paths.removeValue(forKey:path) }
    if paths.isEmpty { journal.removeValue(forKey:location) } else { journal[location] = paths }
    UserDefaults.standard.set(journal,forKey:probeJournalKey)
  }
  private func retryProbeCleanup(_ config: [String: Any], testDirectoriesOnly: Bool = false) async {
    guard let location = config["location"] as? String,
          let journal = UserDefaults.standard.dictionary(forKey:probeJournalKey) as? [String:[String:Double]] else { return }
    // 只清理本机精确记账的路径，并留出网络迟到窗口；其他设备的临时文件仍遵循 7 天规则。
    let paths = (journal[location] ?? [:]).filter {
      probePath($0.key) && (!testDirectoriesOnly || testDirectoryPath($0.key)) && $0.value < Date().timeIntervalSince1970 - 600
    }
      .sorted { $0.value < $1.value }.prefix(8)
    for (path, _) in paths {
      do {
        if testDirectoryPath(path) {
          if try await cleanupTestDirectory(config,path) { recordProbe(config,path:path,pending:false) }
          continue
        }
        let removed = try await request(config,path,method:"DELETE",limit:1024)
        guard [200,204,404].contains(removed.response.statusCode) else { break }
        let missing = try await request(config,path,limit:1024)
        guard missing.response.statusCode == 404 else { break }
      } catch { break } // 锁定、取消及限流不能为了清理而绕过。
    }
  }

  func cancel(reason: String = "sync.errors.locked") {
    // 所有入口均在主线程；代理回调只操作单个传输对象的数据缓冲区。
    generation += 1
    cancellationKey = reason
    for transfer in transfers.values { transfer.cancel() }
    cleanupReferences.removeAll(); cleanupLocation = ""; cleanupDeleteVerified = false
    writeCapabilities = nil
  }
  private func unlocked() -> Bool {
    LocalVaultUnlock.request(["type":"status"])?["unlocked"] as? Bool == true
  }
  private func transferAllowed(_ config: [String: Any]) -> Bool {
    if config["_bootstrap_read_only"] as? Bool == true {
      guard let status = LocalVaultUnlock.request(["type":"status"]) else { return false }
      return status["vault_exists"] as? Bool == false && status["unlocked"] as? Bool != true
    }
    return unlocked()
  }
  private func authorize() throws {
    guard LocalVaultUnlock.request(["type":"sync_control_authorize"]) != nil else { throw WebDAVFailure("sync.errors.authentication") }
  }
  private func settings() -> [String: Any]? { AppPreferences.settings()["webdav"] as? [String: Any] }
  private func keyQuery(_ account: String) -> [String: Any] {
    [kSecClass as String:kSecClassGenericPassword, kSecAttrService as String:service,
     kSecAttrAccount as String:account, kSecUseDataProtectionKeychain as String:false]
  }
  func forgetPasswords() throws {
    let query: [String:Any] = [kSecClass as String:kSecClassGenericPassword,
      kSecAttrService as String:service,kSecUseDataProtectionKeychain as String:false]
    let status = SecItemDelete(query as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else { throw WebDAVFailure("sync.errors.keychain") }
  }
  private func password(_ location: String) throws -> String {
    var query = keyQuery(location)
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    let context = LAContext(); context.interactionNotAllowed = true
    query[kSecUseAuthenticationContext as String] = context
    var item: CFTypeRef?
    guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
          let data = item as? Data, let value = String(data: data, encoding: .utf8), !value.isEmpty else {
      throw WebDAVFailure("sync.errors.passwordMissing")
    }
    return value
  }
  private func savePassword(_ value: String, location: String) throws {
    let query = keyQuery(location)
    let update = [kSecValueData as String:Data(value.utf8)]
    let status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
    if status == errSecSuccess { return }
    guard status == errSecItemNotFound else { throw WebDAVFailure("sync.errors.keychain") }
    var add = query
    add[kSecValueData as String] = Data(value.utf8)
    add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    guard SecItemAdd(add as CFDictionary, nil) == errSecSuccess else { throw WebDAVFailure("sync.errors.keychain") }
  }
  private func hash(_ data: Data) -> String { SHA256.hash(data: data).map { String(format:"%02x", $0) }.joined() }
  private func normalized(_ args: [String: Any]) throws -> [String: Any] {
    let input = args["server_url"] as? String ?? ""
    guard input.rangeOfCharacter(from:.controlCharacters) == nil,
          var parts = URLComponents(string: input.trimmingCharacters(in:.whitespacesAndNewlines)),
          parts.scheme?.lowercased() == "https", let host = parts.host, !host.isEmpty,
          parts.user == nil, parts.password == nil, parts.query == nil, parts.fragment == nil,
          !parts.path.contains("\\"), !parts.path.split(separator:"/").contains(where: { $0 == "." || $0 == ".." }) else {
      throw WebDAVFailure("sync.errors.address")
    }
    if let rawPort = args["port"] as? String, !rawPort.isEmpty {
      guard let port = Int(rawPort), (1...65535).contains(port) else { throw WebDAVFailure("sync.errors.port") }
      if let existing = parts.port, existing != port { throw WebDAVFailure("sync.errors.portConflict") }
      parts.port = port
    }
    if let port = parts.port, !(1...65535).contains(port) { throw WebDAVFailure("sync.errors.port") }
    let username = (args["username"] as? String ?? "").trimmingCharacters(in:.whitespacesAndNewlines)
    guard !username.isEmpty, username.utf8.count <= 1024, !username.contains(":"),
          username.rangeOfCharacter(from:.controlCharacters) == nil else { throw WebDAVFailure("sync.errors.username") }
    guard let interval = args["interval_seconds"] as? Int, (60...3600).contains(interval) else {
      throw WebDAVFailure("sync.errors.interval")
    }
    let dailyHistoryCount: Int
    if let value = args["daily_history_count"] {
      guard let count = value as? Int, (3...99).contains(count) else { throw WebDAVFailure("sync.errors.dailyHistoryCount") }
      dailyHistoryCount = count
    } else { dailyHistoryCount = 5 }
    parts.scheme = "https"; parts.host = host.lowercased()
    if !parts.percentEncodedPath.hasSuffix("/") { parts.percentEncodedPath += "/" }
    guard let server = parts.url?.absoluteString, server.utf8.count <= 4096 else { throw WebDAVFailure("sync.errors.address") }
    let directory = args["directory"] as? String ?? ""
    let segments = directory.split(separator:"/", omittingEmptySubsequences:true)
    guard directory.utf8.count <= 2048, !directory.contains("\\"),
          directory.rangeOfCharacter(from:.controlCharacters) == nil,
          !segments.contains(where: { $0 == "." || $0 == ".." }) else { throw WebDAVFailure("sync.errors.directoryPath") }
    let relative = segments.joined(separator:"/")
    if !relative.isEmpty {
      // 只编码新目录，保留服务器入口中已经存在的百分号编码（例如账号路径）。
      var suffix = URLComponents(); suffix.path = relative + "/"
      parts.percentEncodedPath += suffix.percentEncodedPath
    }
    guard let root = parts.url?.absoluteString, root.utf8.count <= 4096 else { throw WebDAVFailure("sync.errors.address") }
    let rawProvider = args["provider"] as? String ?? ""
    let provider = rawProvider.isEmpty ? "custom" : rawProvider
    guard ["custom","nutstore","nextcloud","owncloud"].contains(provider) else { throw WebDAVFailure("sync.errors.configuration") }
    let identity = try JSONSerialization.data(withJSONObject:[root,username], options:[.sortedKeys])
    return ["root":root,"username":username,"location":hash(identity),
            "provider":provider,"server_url":server,"directory":relative,
            "automatic":args["automatic"] as? Bool ?? true,"interval_seconds":interval,
            "daily_history_count":dailyHistoryCount]
  }
  private func saveSettings(_ value: Any) throws {
    guard let payload = LocalVaultUnlock.request(["type":"app_settings_get"]),
          (payload["warning"] as? String ?? "").isEmpty,
          var current = payload["settings"] as? [String:Any] else { throw WebDAVFailure("sync.errors.settingsRead") }
    current["webdav"] = value
    let body = try JSONSerialization.data(withJSONObject:["type":"app_settings_set","settings":current])
    guard let json = String(data:body,encoding:.utf8),
          let response = credpivotAgentRequestJsonString(json).data(using:.utf8),
          let result = try JSONSerialization.jsonObject(with:response) as? [String:Any] else { throw WebDAVFailure("sync.errors.settingsWrite") }
    guard result["type"] as? String == "ok" else {
      switch result["code"] as? String {
      case "auth_required": throw WebDAVFailure("sync.errors.authentication")
      case "locked": throw WebDAVFailure("sync.errors.locked")
      case "bad_settings": throw WebDAVFailure("sync.errors.settingsInvalid")
      default: throw WebDAVFailure("sync.errors.settingsWrite")
      }
    }
  }
  @discardableResult private func authorizePublish(_ config: [String: Any]) throws -> Bool {
    guard let head = config["_publish_head"] as? [String: Any] else { return false }
    let body = try JSONSerialization.data(withJSONObject:["type":"sync_publish_authorize","location":config["location"] ?? "","head":head])
    guard let text = String(data:body,encoding:.utf8),
          let data = credpivotAgentRequestJsonString(text).data(using:.utf8),
          let response = try JSONSerialization.jsonObject(with:data) as? [String:Any] else { throw WebDAVFailure("sync.errors.operation") }
    if response["type"] as? String == "ok" {
      return (response["payload"] as? [String: Any])?["preserve_previous"] as? Bool ?? false
    }
    if response["code"] as? String == "locked" { throw WebDAVFailure("sync.errors.locked") }
    let key = response["message"] as? String ?? ""
    guard ["sync.errors.localControlChanged","sync.errors.localChanged"].contains(key) else { throw WebDAVFailure("sync.errors.operation") }
    throw WebDAVFailure(key)
  }
  private func request(_ config: [String: Any], _ path: String, method: String = "GET", data: Data? = nil,
                       headers: [String: String] = [:], limit: Int = 64 * 1024 * 1024,
                       listingPage: URL? = nil) async throws -> WebDAVTransfer.Reply {
    guard transferAllowed(config) else { throw WebDAVFailure("sync.errors.locked") }
    if config["_bootstrap_read_only"] as? Bool == true, method != "GET" { throw WebDAVFailure("sync.errors.operation") }
    guard config["_transfer_generation"] as? Int == generation else { throw WebDAVFailure(cancellationKey) }
    try authorizePublish(config)
    guard let root = config["root"] as? String, let base = URL(string:root),
          let location = config["location"] as? String, let username = config["username"] as? String else {
      throw WebDAVFailure("sync.errors.configuration")
    }
    rateLimits = rateLimits.filter { $0.value > Date() }
    if let until = rateLimits[location] {
      throw WebDAVFailure("sync.errors.rateLimited", retryAfter:max(1,Int(ceil(until.timeIntervalSinceNow))), status:429)
    }
    guard !path.split(separator:"/").contains(where: { $0 == "." || $0 == ".." }),
          !path.contains(":"), !path.hasPrefix("/"), !path.contains("\\"),
          let url = path.isEmpty ? base : URL(string:path, relativeTo:base)?.absoluteURL,
          url.scheme == base.scheme, url.host == base.host, url.port == base.port,
          (url.path == base.path || url.path.hasPrefix(base.path.hasSuffix("/") ? base.path : base.path + "/")),
          url.query == nil, url.fragment == nil else {
      throw WebDAVFailure("sync.errors.requestPath")
    }
    var target = url
    if let page = listingPage {
      // 分页链接只能改变当前集合的查询参数，绝不向其他目录或主机转发认证信息。
      guard method == "PROPFIND", headers["Depth"] == "1", page.scheme?.lowercased() == url.scheme?.lowercased(),
            page.host?.lowercased() == url.host?.lowercased(), (page.port ?? 443) == (url.port ?? 443), page.path == url.path,
            page.user == nil, page.password == nil, page.fragment == nil,
            page.absoluteString.utf8.count <= 8192 else { throw WebDAVFailure("sync.cleanup.incomplete") }
      target = page
    }
    var request = URLRequest(url:target, cachePolicy:.reloadIgnoringLocalCacheData, timeoutInterval:45)
    if method == "PUT" { recordProbe(config,path:path,pending:true) }
    request.httpMethod = method; request.httpBody = data
    let secret: String
    if let draft = config["_password"] as? String { secret = draft }
    else { secret = try password(location) }
    request.setValue("Basic " + Data("\(username):\(secret)".utf8).base64EncodedString(), forHTTPHeaderField:"Authorization")
    request.setValue("CredPivot/1", forHTTPHeaderField:"User-Agent")
    request.setValue("application/octet-stream", forHTTPHeaderField:"Content-Type")
    for (key,value) in headers { request.setValue(value, forHTTPHeaderField:key) }
    let id = UUID(), currentGeneration = generation
    let transfer = WebDAVTransfer(limit:limit); transfers[id] = transfer
    defer { transfers.removeValue(forKey:id) }
    let reply: WebDAVTransfer.Reply
    do { reply = try await transfer.run(request) }
    catch {
      // 主动取消产生的 URLSession 错误也要保留取消原因，不能误判为可重试的断网。
      guard transferAllowed(config) else { throw WebDAVFailure("sync.errors.locked") }
      guard currentGeneration == generation else { throw WebDAVFailure(cancellationKey) }
      throw error
    }
    guard transferAllowed(config) else { throw WebDAVFailure("sync.errors.locked") }
    guard currentGeneration == generation else { throw WebDAVFailure(cancellationKey) }
    try authorizePublish(config)
    if (method == "GET" || method == "DELETE") && reply.response.statusCode == 404 { recordProbe(config,path:path,pending:false) }
    switch reply.response.statusCode {
    case 401: throw WebDAVFailure("sync.errors.unauthorized", status:401)
    case 403: throw WebDAVFailure("sync.errors.forbidden", status:403)
    case 429:
      let raw = reply.response.value(forHTTPHeaderField:"Retry-After") ?? ""
      var seconds = Int(raw) ?? 120
      if Int(raw) == nil {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier:"en_US_POSIX"); formatter.timeZone = TimeZone(secondsFromGMT:0)
        formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss zzz"
        if let date = formatter.date(from:raw) { seconds = Int(max(0,date.timeIntervalSinceNow)) }
      }
      let delay = max(60,min(86400,seconds))
      // 清理、手动操作和自动同步共享同一连接的退避，锁定/取消不能绕过服务端限流。
      let until = max(rateLimits[location] ?? .distantPast, Date().addingTimeInterval(TimeInterval(delay)))
      rateLimits[location] = until
      throw WebDAVFailure("sync.errors.rateLimited", retryAfter:max(1,Int(ceil(until.timeIntervalSinceNow))), status:429)
    case 500...599: throw WebDAVFailure("sync.errors.server", status:reply.response.statusCode)
    case 300...303, 305...399: throw WebDAVFailure("sync.errors.redirect", status:reply.response.statusCode)
    default: return reply
    }
  }
  private func validatedETag(_ value: String?) throws -> String {
    guard let value = value, !value.isEmpty else { throw WebDAVFailure("sync.errors.etagMissing") }
    guard !value.uppercased().hasPrefix("W/") else { throw WebDAVFailure("sync.errors.etagWeak") }
    let quoted = value.hasPrefix("\"") && value.hasSuffix("\"") && value.count >= 2
    let opaque = quoted ? String(value.dropFirst().dropLast()) : value
    guard value.utf8.count <= 1024, opaque.utf8.allSatisfy({ $0 == 0x21 || (0x23...0x7E).contains($0) }) else {
      throw WebDAVFailure("sync.errors.etagFormat")
    }
    // 部分 DAV 服务返回不带引号的版本号。原样回传；能否保护更新由写入探测确认。
    return value
  }
  private func etag(_ reply: WebDAVTransfer.Reply) throws -> String {
    try validatedETag(reply.response.value(forHTTPHeaderField:"ETag"))
  }
  private func directory(_ config: [String: Any], _ path: String, create: Bool = true) async throws {
    let reply = try await request(config,path,method:"PROPFIND",
      data:Data("<?xml version=\"1.0\"?><d:propfind xmlns:d=\"DAV:\"><d:prop><d:resourcetype/></d:prop></d:propfind>".utf8),
      headers:["Depth":"0","Content-Type":"application/xml"],limit:256 * 1024)
    if reply.response.statusCode == 404, create {
      let created = try await request(config,path,method:"MKCOL",limit:256 * 1024)
      if created.response.statusCode == 201 { return }
      // 另一台设备可能刚创建了同一目录，重新读取确认，而非把 405 当作成功。
      if created.response.statusCode == 405 { try await directory(config,path,create:false); return }
      throw WebDAVFailure("sync.errors.directory")
    }
    guard let target = reply.response.url else { throw WebDAVFailure("sync.errors.directory") }
    let parser = XMLParser(data:reply.data), delegate = WebDAVCollection(expected:target)
    parser.shouldProcessNamespaces = true; parser.shouldResolveExternalEntities = false; parser.delegate = delegate
    guard reply.response.statusCode == 207, parser.parse(), delegate.collection else { throw WebDAVFailure("sync.errors.directory") }
  }
  private func moveWithoutOverwrite(_ config: [String: Any], source: String, destination: String) async throws -> WebDAVTransfer.Reply {
    guard let root = config["root"] as? String, let base = URL(string:root),
          let target = URL(string:destination,relativeTo:base)?.absoluteURL,
          target.scheme == base.scheme, target.host == base.host, target.port == base.port,
          target.path.hasPrefix(base.path), target.query == nil, target.fragment == nil,
          !destination.contains("/"), !destination.contains(":"), !destination.contains("\\") else {
      throw WebDAVFailure("sync.errors.requestPath")
    }
    return try await request(config,source,method:"MOVE",headers:["Destination":target.absoluteString,"Overwrite":"F"],limit:256 * 1024)
  }
  private func testCleanupRequest(_ config: [String: Any], _ path: String, phase: UInt32, method: String = "PROPFIND",
                                  data: Data? = nil, headers: [String: String] = [:], limit: Int = 256 * 1024) async throws -> WebDAVTransfer.Reply {
    let gate = path == "initial-gate/"
    do {
      let reply = try await request(config,path,method:method,data:data,headers:headers,limit:limit)
      CredPivotRustFFI.logWebDAVCleanup(phase,status:reply.response.statusCode,gate:gate)
      return reply
    } catch {
      CredPivotRustFFI.logWebDAVCleanup(phase,status:(error as? WebDAVFailure)?.status ?? 0,reason:4,gate:gate)
      throw error
    }
  }
  private func rejectTestCleanup(_ phase: UInt32, reason: UInt32, status: Int = 0, gate: Bool = false) -> Bool {
    CredPivotRustFFI.logWebDAVCleanup(phase,status:status,reason:reason,gate:gate)
    return false
  }
  /// 只用于本次随机测试目录；集合 DELETE 有递归语义，删除前必须验证确实为空。
  private func removeEmptyTestCollection(_ config: [String: Any], _ path: String) async throws -> Bool {
    let gate = path == "initial-gate/"
    guard let name = config["_test_directory"] as? String, testDirectoryPath(name),
          path.isEmpty || gate,
          let root = URL(string:config["root"] as? String ?? ""), root.lastPathComponent == (name as NSString).lastPathComponent,
          let target = path.isEmpty ? root : URL(string:path,relativeTo:root)?.absoluteURL else { return rejectTestCleanup(9,reason:6,gate:gate) }
    let reply = try await testCleanupRequest(config,path,phase:9,
      data:Data("<?xml version=\"1.0\"?><d:propfind xmlns:d=\"DAV:\"><d:prop><d:resourcetype/></d:prop></d:propfind>".utf8),
      headers:["Depth":"1","Content-Type":"application/xml"])
    if reply.response.statusCode == 404 { return true }
    guard reply.response.statusCode == 207 else { return rejectTestCleanup(9,reason:1,status:reply.response.statusCode,gate:gate) }
    guard !(reply.response.value(forHTTPHeaderField:"Link") ?? "").lowercased().contains("next") else { return rejectTestCleanup(9,reason:7,gate:gate) }
    let parser = XMLParser(data:reply.data), listing = WebDAVListing()
    parser.shouldProcessNamespaces = true; parser.shouldResolveExternalEntities = false; parser.delegate = listing
    guard parser.parse() else { return rejectTestCleanup(9,reason:2,gate:gate) }
    guard listing.valid else { return rejectTestCleanup(9,reason:12,gate:gate) }
    guard listing.entries.count == 1 else { return rejectTestCleanup(9,reason:listing.entries.isEmpty ? 11 : 9,gate:gate) }
    guard let entry = listing.entries.first, entry.collection,
          let observed = URL(string:entry.href,relativeTo:target)?.absoluteURL,
          observed.scheme == target.scheme, observed.host == target.host, (observed.port ?? 443) == (target.port ?? 443),
          observed.query == nil, observed.fragment == nil, observed.user == nil, observed.password == nil,
          observed.path == target.path || observed.path + "/" == target.path || observed.path == target.path + "/" else { return rejectTestCleanup(9,reason:3,gate:gate) }
    let deleted = try await testCleanupRequest(config,path,phase:10,method:"DELETE",limit:1024)
    guard [200,204,404].contains(deleted.response.statusCode) else { return rejectTestCleanup(10,reason:1,status:deleted.response.statusCode,gate:gate) }
    let missing = try await testCleanupRequest(config,path,phase:11,headers:["Depth":"0"])
    guard missing.response.statusCode == 404 else { return rejectTestCleanup(11,reason:1,status:missing.response.statusCode,gate:gate) }
    return true
  }

  private func cleanupTestDirectory(_ config: [String: Any], _ name: String) async throws -> Bool {
    guard testDirectoryPath(name), let root = URL(string:config["root"] as? String ?? ""),
          let target = URL(string:name + "/",relativeTo:root)?.absoluteURL else { return rejectTestCleanup(6,reason:6) }
    var scratch = config
    scratch["root"] = target.absoluteString; scratch["_test_directory"] = name
    let reply = try await testCleanupRequest(scratch,"",phase:6,
      data:Data("<?xml version=\"1.0\"?><d:propfind xmlns:d=\"DAV:\"><d:prop><d:resourcetype/></d:prop></d:propfind>".utf8),
      headers:["Depth":"1","Content-Type":"application/xml"])
    if reply.response.statusCode == 404 { return true }
    guard reply.response.statusCode == 207 else { return rejectTestCleanup(6,reason:1,status:reply.response.statusCode) }
    guard !(reply.response.value(forHTTPHeaderField:"Link") ?? "").lowercased().contains("next") else { return rejectTestCleanup(6,reason:7) }
    let parser = XMLParser(data:reply.data), listing = WebDAVListing()
    parser.shouldProcessNamespaces = true; parser.shouldResolveExternalEntities = false; parser.delegate = listing
    guard parser.parse() else { return rejectTestCleanup(6,reason:2) }
    guard listing.valid else { return rejectTestCleanup(6,reason:12) }
    let allowed = ["probe","move-a","move-b","move-target-a","move-target-b"]
    var files = Set<String>(), foundRoot = false, foundGate = false
    for entry in listing.entries {
      guard let url = URL(string:entry.href,relativeTo:target)?.absoluteURL,
            url.scheme == target.scheme, url.host == target.host, (url.port ?? 443) == (target.port ?? 443),
            url.query == nil, url.fragment == nil, url.user == nil, url.password == nil else { return rejectTestCleanup(7,reason:3) }
      if url.path == target.path || url.path + "/" == target.path || url.path == target.path + "/" {
        guard entry.collection, !foundRoot else { return rejectTestCleanup(7,reason:10) }; foundRoot = true
      } else if let file = allowed.first(where: { target.appendingPathComponent($0).path == url.path }) {
        guard !entry.collection, files.insert(file).inserted else { return rejectTestCleanup(7,reason:10) }
      } else if url.path == target.appendingPathComponent("initial-gate").path || url.path == target.appendingPathComponent("initial-gate").path + "/" {
        guard entry.collection, !foundGate else { return rejectTestCleanup(7,reason:10,gate:true) }; foundGate = true
      } else { return rejectTestCleanup(7,reason:8) } // 有未知内容就保留，不递归删除整个目录。
    }
    guard foundRoot else { return rejectTestCleanup(7,reason:11) }
    for file in files {
      let deleted = try await testCleanupRequest(scratch,file,phase:8,method:"DELETE",limit:1024)
      guard [200,204,404].contains(deleted.response.statusCode) else { return rejectTestCleanup(8,reason:1,status:deleted.response.statusCode) }
    }
    if foundGate {
      guard try await removeEmptyTestCollection(scratch,"initial-gate/") else { return false }
    }
    return try await removeEmptyTestCollection(scratch,"")
  }

  private func probe(_ config: [String: Any], onCheck: (([String: Any]) -> Void)? = nil) async throws {
    let policy = WebDAVProviderPolicy(config)
    func checked(_ key: String, _ statuses: [Int] = [], passed: Bool = true, skipped: Bool = false) {
      onCheck?(["key":key,"passed":passed,"statuses":statuses,"skipped":skipped])
    }
    writeCapabilities = nil
    guard let server = config["server_url"] as? String, !server.isEmpty,
          let root = config["root"] as? String else { throw WebDAVFailure("sync.errors.configuration") }
    var parent = config
    parent["root"] = server
    // 服务器入口必须存在；仅逐级创建用户指定的相对目录，不猜测 /dav 等服务路径。
    try await directory(parent,"",create:false)
    guard let target = URL(string:root), let base = URL(string:server),
          target.path.hasPrefix(base.path) else { throw WebDAVFailure("sync.errors.directoryPath") }
    var prefix = ""
    for segment in target.path.dropFirst(base.path.count).split(separator:"/") {
      var component = CharacterSet.urlPathAllowed
      component.remove(charactersIn:"/%?#:")
      guard let encoded = String(segment).addingPercentEncoding(withAllowedCharacters:component) else { throw WebDAVFailure("sync.errors.directoryPath") }
      prefix += encoded + "/"
      try await directory(parent,prefix)
    }
    checked("directory")
    try await directory(config,testDirectoryRoot + "/")
    let testDirectory = testDirectoryRoot + "/.credpivot-test-" + UUID().uuidString.lowercased()
    let prior = try await request(config,testDirectory + "/",method:"PROPFIND",headers:["Depth":"0"],limit:256 * 1024)
    guard prior.response.statusCode == 404 else { throw WebDAVFailure("sync.errors.probeDirectory", stage:"testDirectory", status:prior.response.statusCode) }
    let made = try await request(config,testDirectory + "/",method:"MKCOL",limit:1024)
    guard made.response.statusCode == 201 else { throw WebDAVFailure("sync.errors.probeDirectory", stage:"testDirectory", status:made.response.statusCode) }
    recordProbe(config,path:testDirectory,pending:true)
    let original = config
    var scratch = config
    guard let root = URL(string:config["root"] as? String ?? ""),
          let target = URL(string:testDirectory + "/",relativeTo:root)?.absoluteURL else { throw WebDAVFailure("sync.errors.configuration") }
    scratch["root"] = target.absoluteString; scratch["_test_directory"] = testDirectory
    var outerStage = "testDirectory"
    do {
      let config = scratch
      try await directory(config,"",create:false)
      checked("testDirectory")
      let path = "probe"
      let first = Data(("credpivot-probe-one-" + UUID().uuidString).utf8)
      let second = Data(("credpivot-probe-two-" + UUID().uuidString).utf8)
      var stage = "create"
      var createOnly = false
      do {
        let create = try await request(config,path,method:"PUT",data:first,limit:1024)
        guard [200,201,204].contains(create.response.statusCode) else {
          throw WebDAVFailure("sync.errors.probeCreate", status:create.response.statusCode)
        }
        let created = try await request(config,path,limit:1024)
        guard created.response.statusCode == 200, created.data == first else { throw WebDAVFailure("sync.errors.probeReadback", status:created.response.statusCode) }
        checked("readWrite",[create.response.statusCode,created.response.statusCode])
        stage = "createCondition"
        if policy == .nutstore {
          // 此渠道不依赖 If-None-Match 或重复 MKCOL 互斥；首次入口直接验证禁止覆盖的 MOVE。
          checked("nutstoreCreateSkipped",passed:false,skipped:true)
        } else {
          do {
            let duplicate = try await request(config,path,method:"PUT",data:second,headers:["If-None-Match":"*"],limit:1024)
            let observed = try await request(config,path,limit:1024)
            createOnly = duplicate.response.statusCode == 412
            let ignored = [200,201,204].contains(duplicate.response.statusCode)
            let unsupported = [400,405,501].contains(duplicate.response.statusCode)
            guard observed.response.statusCode == 200,
                  (createOnly && observed.data == first) || (ignored && observed.data == second) || (unsupported && observed.data == first) else {
              throw WebDAVFailure("sync.errors.probeCreateCondition", status:duplicate.response.statusCode)
            }
            checked("createCondition",[duplicate.response.statusCode],passed:createOnly)
          } catch let error as WebDAVFailure where error.status == 501 {
            // 明确拒绝此条件头的服务仍可用 MKCOL 保护首次发布，更新保护另行验证。
            createOnly = false
            checked("createCondition",[501],passed:false)
          }
        }
        // If-None-Match 可能被忽略并写入第二份内容；重置随机探针后再独立检查 If-Match。
        stage = "readback"
        let reset = try await request(config,path,method:"PUT",data:first,limit:1024)
        let old = try await request(config,path,limit:1024)
        guard [200,201,204].contains(reset.response.statusCode), old.response.statusCode == 200, old.data == first else {
          throw WebDAVFailure("sync.errors.probeReadback", status:old.response.statusCode)
        }
        let tag = try etag(old)
        checked("readback",[old.response.statusCode])
        stage = "matchWrong"
        let invalid = "credpivot-invalid-" + UUID().uuidString
        let wrongTag = tag.hasPrefix("\"") ? "\"\(invalid)\"" : invalid
        let wrong = try await request(config,path,method:"PUT",data:second,headers:["If-Match":wrongTag],limit:1024)
        let unchanged = try await request(config,path,limit:1024)
        guard wrong.response.statusCode == 412, unchanged.response.statusCode == 200,
              unchanged.data == first, try etag(unchanged) == tag else {
          throw WebDAVFailure("sync.errors.probeMatchWrong", status:wrong.response.statusCode)
        }
        checked("matchWrong",[wrong.response.statusCode])
        stage = "matchUpdate"
        let update = try await request(config,path,method:"PUT",data:second,headers:["If-Match":tag],limit:1024)
        guard [200,201,204].contains(update.response.statusCode) else {
          throw WebDAVFailure("sync.errors.probeMatchUpdate", status:update.response.statusCode)
        }
        let updated = try await request(config,path,limit:1024)
        guard updated.response.statusCode == 200, updated.data == second, try etag(updated) != tag else {
          throw WebDAVFailure("sync.errors.probeReadback", status:updated.response.statusCode)
        }
        checked("matchUpdate",[update.response.statusCode])
        stage = "matchStale"
        let stale = try await request(config,path,method:"PUT",data:first,headers:["If-Match":tag],limit:1024)
        let final = try await request(config,path,limit:1024)
        guard stale.response.statusCode == 412, final.response.statusCode == 200,
              final.data == second, try etag(final) == etag(updated) else {
          throw WebDAVFailure("sync.errors.probeMatchStale", status:stale.response.statusCode)
        }
        checked("matchStale",[stale.response.statusCode])
        stage = "matchConcurrent"
        let concurrentTag = try etag(final), third = Data(("credpivot-probe-three-" + UUID().uuidString).utf8)
        async let one = request(config,path,method:"PUT",data:first,headers:["If-Match":concurrentTag],limit:1024)
        async let two = request(config,path,method:"PUT",data:third,headers:["If-Match":concurrentTag],limit:1024)
        let (a,b) = try await (one,two)
        let aWon = [200,201,204].contains(a.response.statusCode), bWon = [200,201,204].contains(b.response.statusCode)
        let concurrent = try await request(config,path,limit:1024)
        guard aWon != bWon, (aWon ? b.response.statusCode : a.response.statusCode) == 412,
              concurrent.response.statusCode == 200, concurrent.data == (aWon ? first : third) else {
          throw WebDAVFailure("sync.errors.probeMatchConcurrent", statuses:[a.response.statusCode,b.response.statusCode])
        }
        checked("matchConcurrent",[a.response.statusCode,b.response.statusCode])
        stage = "cleanup"
        let deleted = try await testCleanupRequest(config,path,phase:8,method:"DELETE",limit:1024)
        guard [200,204,404].contains(deleted.response.statusCode) else { throw WebDAVFailure("sync.errors.probeCleanup") }
        let removed = try await testCleanupRequest(config,path,phase:12,method:"GET",limit:1024)
        guard removed.response.statusCode == 404 else { throw WebDAVFailure("sync.errors.probeCleanup", status:removed.response.statusCode) }
      } catch {
        _ = try? await request(config,path,method:"DELETE",limit:1024)
        if let failure = error as? WebDAVFailure {
          throw WebDAVFailure(failure.key, retryAfter:failure.retryAfter, stage:stage, status:failure.status, statuses:failure.statuses)
        }
        throw WebDAVFailure("sync.errors.network", stage:stage)
      }
      var initialCreation = createOnly ? "conditional" : "directory"
      if !createOnly {
        var exclusive = false
        if policy == .nutstore {
          checked("nutstoreGateSkipped",passed:false,skipped:true)
        } else {
          // 仅需在首次创建共享入口时互斥。随机目录用于确认 MKCOL 确实只允许一个创建者。
          let gate = "initial-gate/"
          var statuses: [Int] = []
          do {
            async let one = request(config,gate,method:"MKCOL",limit:1024)
            async let two = request(config,gate,method:"MKCOL",limit:1024)
            let (a,b) = try await (one,two)
            statuses = [a.response.statusCode,b.response.statusCode]
            exclusive = statuses == [201,405] || statuses == [405,201]
            guard try await removeEmptyTestCollection(config,gate) else { throw WebDAVFailure("sync.errors.probeCleanup") }
          } catch {
            _ = try? await removeEmptyTestCollection(config,gate)
            if let failure = error as? WebDAVFailure {
              throw WebDAVFailure(failure.key, retryAfter:failure.retryAfter, stage:"initialGate", status:failure.status, statuses:failure.statuses)
            }
            throw WebDAVFailure("sync.errors.network", stage:"initialGate")
          }
          checked("initialGate",statuses,passed:exclusive)
        }
        if !exclusive {
          // 某些服务的 MKCOL 是幂等创建，并不互斥。只能在禁止覆盖的 MOVE 也通过实测后接入。
          do { try await probeInitialMove(config,onCheck:onCheck) }
          catch let failure as WebDAVFailure {
            throw WebDAVFailure(failure.key, retryAfter:failure.retryAfter, stage:failure.stage ?? "initialMove", status:failure.status, statuses:failure.statuses)
          }
          catch { throw WebDAVFailure("sync.errors.network", stage:"initialMove") }
          initialCreation = "move"
        }
      }
      outerStage = "cleanup"
      guard try await cleanupTestDirectory(original,testDirectory) else { throw WebDAVFailure("sync.errors.probeCleanup", stage:"cleanup") }
      recordProbe(original,path:testDirectory,pending:false)
      checked("cleanup")
      writeCapabilities = (location:config["location"] as? String ?? "", policy:policy, createOnly:createOnly, initialCreation:initialCreation)
    } catch {
      if (try? await cleanupTestDirectory(original,testDirectory)) == true { recordProbe(original,path:testDirectory,pending:false) }
      if let failure = error as? WebDAVFailure {
        throw WebDAVFailure(failure.key, retryAfter:failure.retryAfter, stage:failure.stage ?? outerStage, status:failure.status, statuses:failure.statuses)
      }
      throw WebDAVFailure("sync.errors.network", stage:outerStage)
    }
  }
  private func probeInitialMove(_ config: [String: Any], onCheck: (([String: Any]) -> Void)?) async throws {
    // 固定文件名只用于本次随机测试目录，不触碰 head.json 或已有同步数据。
    guard let name = config["_test_directory"] as? String, testDirectoryPath(name) else { throw WebDAVFailure("sync.errors.probeDirectory") }
    let paths = ["move-a","move-b","move-target-a","move-target-b"]
    let first = Data(("credpivot-move-one-" + UUID().uuidString).utf8)
    let second = Data(("credpivot-move-two-" + UUID().uuidString).utf8)
    let policy = WebDAVProviderPolicy(config)
    var stage = "initialMoveCreate"
    do {
      try await uploadUnique(config,path:paths[0],data:first,limit:1024,createOnly:false)
      try await uploadUnique(config,path:paths[1],data:second,limit:1024,createOnly:false)
      let created = try await moveWithoutOverwrite(config,source:paths[0],destination:paths[2])
      let original = try await request(config,paths[2],limit:1024)
      let missing = try await request(config,paths[0],limit:1024)
      guard created.response.statusCode == 201, original.response.statusCode == 200,
            original.data == first, missing.response.statusCode == 404 else {
        throw WebDAVFailure("sync.errors.probeInitialMoveCreate", status:created.response.statusCode)
      }
      onCheck?(["key":"initialMoveCreate","passed":true,"statuses":[created.response.statusCode]])
      stage = "initialMove"
      let rejected = try await moveWithoutOverwrite(config,source:paths[1],destination:paths[2])
      let unchanged = try await request(config,paths[2],limit:1024)
      let retained = try await request(config,paths[1],limit:1024)
      guard policy.rejectsMoveOverwrite(rejected.response.statusCode), unchanged.response.statusCode == 200, unchanged.data == first,
            retained.response.statusCode == 200, retained.data == second else {
        throw WebDAVFailure("sync.errors.probeInitialMove", status:rejected.response.statusCode)
      }
      onCheck?(["key":"initialMove","passed":true,"statuses":[rejected.response.statusCode]])
      stage = "initialMoveConcurrent"
      try await uploadUnique(config,path:paths[0],data:first,limit:1024,createOnly:false)
      async let one = moveWithoutOverwrite(config,source:paths[0],destination:paths[3])
      async let two = moveWithoutOverwrite(config,source:paths[1],destination:paths[3])
      let (a,b) = try await (one,two)
      let aWon = a.response.statusCode == 201, bWon = b.response.statusCode == 201
      let visible = try await request(config,paths[3],limit:1024)
      let loser = try await request(config,aWon ? paths[1] : paths[0],limit:1024)
      let winner = try await request(config,aWon ? paths[0] : paths[1],limit:1024)
      guard aWon != bWon, policy.rejectsMoveOverwrite(aWon ? b.response.statusCode : a.response.statusCode),
            visible.response.statusCode == 200, visible.data == (aWon ? first : second),
            loser.response.statusCode == 200, loser.data == (aWon ? second : first), winner.response.statusCode == 404 else {
        throw WebDAVFailure("sync.errors.probeInitialMove", stage:"initialMoveConcurrent", statuses:[a.response.statusCode,b.response.statusCode])
      }
      onCheck?(["key":"initialMoveConcurrent","passed":true,"statuses":[a.response.statusCode,b.response.statusCode]])
      stage = "cleanup"
      for path in paths {
        let deleted = try await testCleanupRequest(config,path,phase:8,method:"DELETE",limit:1024)
        guard [200,204,404].contains(deleted.response.statusCode) else { throw WebDAVFailure("sync.errors.probeCleanup", stage:"cleanup", status:deleted.response.statusCode) }
        let removed = try await testCleanupRequest(config,path,phase:12,method:"GET",limit:1024)
        guard removed.response.statusCode == 404 else { throw WebDAVFailure("sync.errors.probeCleanup", stage:"cleanup", status:removed.response.statusCode) }
      }
    } catch {
      for path in paths { _ = try? await request(config,path,method:"DELETE",limit:1024) }
      if let failure = error as? WebDAVFailure {
        throw WebDAVFailure(failure.key, retryAfter:failure.retryAfter, stage:failure.stage ?? stage, status:failure.status, statuses:failure.statuses)
      }
      throw WebDAVFailure("sync.errors.network", stage:stage)
    }
  }
  private func validSnapshot(_ head: [String: Any]) throws -> String {
    guard head["format"] as? String == "credpivot-sync", let version = head["version"] as? Int, [1, 2].contains(version),
          let path = head["snapshot"] as? String,
          path.range(of:"^snapshots/credpivot_[A-Za-z0-9_-]+\\.ovb$", options:.regularExpression) != nil,
          path.count <= 180 else { throw WebDAVFailure("sync.errors.format") }
    return path
  }
  private func read(_ config: [String: Any], knownETag: String?) async throws -> [String: Any] {
    for attempt in 0..<3 {
      let headers = attempt == 0 ? knownETag.map { ["If-None-Match":$0] } ?? [:] : [:]
      let reply = try await request(config,"head.json",headers:headers,limit:64 * 1024)
      if reply.response.statusCode == 304 { return ["not_modified":true,"location":config["location"] ?? ""] }
      if reply.response.statusCode == 404 { return ["empty":true,"location":config["location"] ?? ""] }
      guard reply.response.statusCode == 200,
            let head = try JSONSerialization.jsonObject(with:reply.data) as? [String: Any] else { throw WebDAVFailure("sync.errors.format") }
      let tag: String?
      if config["_bootstrap_read_only"] as? Bool == true { tag = try? etag(reply) }
      else { tag = try etag(reply) }
      let path = try validSnapshot(head)
      let snapshot = try await request(config,path,limit:maxSnapshot)
      // 刚读到的旧入口可能已被另一台设备替换并清理；重新读取入口，不能继续使用旧缓存。
      if snapshot.response.statusCode == 404, attempt < 2 { continue }
      guard snapshot.response.statusCode == 200, let expected = head["sha256"] as? String,
            hash(snapshot.data) == expected else { throw WebDAVFailure("sync.errors.integrity") }
      var value: [String: Any] = ["head":head,"remote_ovb":snapshot.data.base64EncodedString(),"location":config["location"] ?? ""]
      if let tag = tag { value["etag"] = tag }
      if config["_bootstrap_read_only"] as? Bool == true, let modified = reply.response.value(forHTTPHeaderField:"Last-Modified") { value["modified"] = modified }
      return value
    }
    throw WebDAVFailure("sync.errors.remoteChanged")
  }
  private func uploadUnique(_ config: [String: Any], path: String, data: Data, limit: Int, createOnly: Bool) async throws {
    // 快照和历史入口都有 UUID，永不更新已有内容。兼容模式先检查重试遗留文件，再上传并逐字校验。
    if !createOnly {
      let existing = try await request(config,path,limit:limit)
      if existing.response.statusCode == 200 {
        guard existing.data == data else { throw WebDAVFailure("sync.errors.integrity") }
        return
      }
      guard existing.response.statusCode == 404 else { throw WebDAVFailure("sync.errors.upload", status:existing.response.statusCode) }
    }
    let uploaded = try await request(config,path,method:"PUT",data:data,
      headers:createOnly ? ["If-None-Match":"*"] : [:],limit:256 * 1024)
    guard [200,201,204].contains(uploaded.response.statusCode) || (createOnly && uploaded.response.statusCode == 412) else {
      throw WebDAVFailure("sync.errors.upload", status:uploaded.response.statusCode)
    }
    let verified = try await request(config,path,limit:limit)
    guard verified.response.statusCode == 200, verified.data == data else { throw WebDAVFailure("sync.errors.integrity") }
  }
  private func publishHead(_ config: [String: Any], head: [String: Any], condition: [String: String]) async throws -> String {
    let gate = ".credpivot-initializing/"
    let data = try JSONSerialization.data(withJSONObject:head, options:[.sortedKeys])
    if condition.isEmpty, writeCapabilities?.initialCreation == "move" {
      // 以随机文件准备入口，再原子移动到不存在的 head.json。迟到请求也不能覆盖别端已发布的入口。
      // 沿用探针命名，使失败遗留的入口临时文件也能按既有的 7 天规则清理。
      let staged = ".credpivot-probe-" + UUID().uuidString.lowercased()
      do {
        try await uploadUnique(config,path:staged,data:data,limit:64 * 1024,createOnly:false)
        let moved = try await moveWithoutOverwrite(config,source:staged,destination:"head.json")
        if WebDAVProviderPolicy(config).rejectsMoveOverwrite(moved.response.statusCode) {
          // 409 也可能表示目录等错误，只有读到已有入口才归类为并发冲突。
          let current = try await request(config,"head.json",limit:64 * 1024)
          if current.response.statusCode == 200 { throw WebDAVFailure("sync.errors.remoteChanged") }
          throw WebDAVFailure("sync.errors.probeInitialMoveCreate", stage:"initialMoveCreate", status:moved.response.statusCode)
        }
        guard moved.response.statusCode == 201 else { throw WebDAVFailure("sync.errors.upload", status:moved.response.statusCode) }
        let visible = try await request(config,"head.json",limit:64 * 1024)
        guard visible.response.statusCode == 200,
              let observed = try JSONSerialization.jsonObject(with:visible.data) as? [String: Any],
              NSDictionary(dictionary:observed).isEqual(to:head) else { throw WebDAVFailure("sync.errors.remoteChanged") }
        return try etag(visible)
      } catch {
        _ = try? await request(config,staged,method:"DELETE",limit:1024)
        throw error
      }
    }
    var ownsGate = false, writeStarted = false
    do {
      if condition.isEmpty {
        let acquired = try await request(config,gate,method:"MKCOL",limit:1024)
        guard acquired.response.statusCode == 201 else {
          throw WebDAVFailure("sync.errors.initializationBusy", status:acquired.response.statusCode)
        }
        ownsGate = true
        // 读取必须在取得独占目录后重做，防止两端同时看到空入口后互相覆盖。
        let current = try await request(config,"head.json",limit:64 * 1024)
        guard current.response.statusCode == 404 else { throw WebDAVFailure("sync.errors.remoteChanged") }
      }
      writeStarted = true
      let committed = try await request(config,"head.json",method:"PUT",data:data,
        headers:condition.merging(["Content-Type":"application/json"]) { _, new in new },limit:256 * 1024)
      if committed.response.statusCode == 412 { throw WebDAVFailure("sync.errors.remoteChanged") }
      guard [200,201,204].contains(committed.response.statusCode) else {
        throw WebDAVFailure("sync.errors.upload", status:committed.response.statusCode)
      }
      let visible = try await request(config,"head.json",limit:64 * 1024)
      guard visible.response.statusCode == 200, let observed = try JSONSerialization.jsonObject(with:visible.data) as? [String: Any],
            NSDictionary(dictionary:observed).isEqual(to:head) else { throw WebDAVFailure("sync.errors.remoteChanged") }
      let tag = try etag(visible)
      if ownsGate { _ = try? await request(config,gate,method:"DELETE",limit:1024) }
      return tag
    } catch {
      // 写入一旦发出，超时不代表服务端已停止。保留初始化目录，避免另一端接管后被迟到写入覆盖。
      // 已有 head.json 的正常同步不受此目录影响；无入口时需人工确认没有初始化任务后移除此空目录。
      if ownsGate && !writeStarted { _ = try? await request(config,gate,method:"DELETE",limit:1024) }
      throw error
    }
  }
  private func publish(_ config: [String: Any], args: [String: Any]) async throws -> [String: Any] {
    guard let head = args["head"] as? [String: Any], let text = args["ovb"] as? String,
          text.utf8.count <= (maxSnapshot * 4 / 3 + 8), let archive = Data(base64Encoded:text),
          let expected = head["sha256"] as? String, hash(archive) == expected,
          args["location"] as? String == config["location"] as? String else { throw WebDAVFailure("sync.errors.integrity") }
    let path = try validSnapshot(head)
    var publishing = config
    publishing["_publish_head"] = head
    let preservePrevious = try authorizePublish(publishing)
    let policy = WebDAVProviderPolicy(config)
    if writeCapabilities?.location != config["location"] as? String || writeCapabilities?.policy != policy { try await probe(config) }
    guard let capabilities = writeCapabilities, capabilities.location == config["location"] as? String, capabilities.policy == policy else {
      throw WebDAVFailure("sync.errors.conditionalWrite")
    }
    try await directory(publishing,"snapshots/")
    try await directory(publishing,"backups/")
    try await uploadUnique(publishing,path:path,data:archive,limit:maxSnapshot,createOnly:capabilities.createOnly)
    let prior = try await request(publishing,"head.json",limit:64 * 1024)
    var condition: [String: String]
    var backup: String?
    if let tag = args["etag"] as? String {
      guard prior.response.statusCode == 200, try etag(prior) == tag else { throw WebDAVFailure("sync.errors.remoteChanged") }
      // 旧快照本身保持原名；保存入口副本便于找回任意一次发布前的版本。
      let old = try JSONSerialization.jsonObject(with:prior.data) as? [String: Any] ?? [:]
      guard let expectedHead = args["expected_head"] as? [String:Any],
            NSDictionary(dictionary:old).isEqual(to:expectedHead),
            old["revision"] as? String == head["parent"] as? String else { throw WebDAVFailure("sync.errors.remoteChanged") }
      backup = try validSnapshot(old)
      let backupPath = "backups/head_\(Int64(Date().timeIntervalSince1970 * 1000))_\(UUID().uuidString).json"
      var history: [String: Any] = ["format":"credpivot-history","version":1,"head":old,
                                    "important":preservePrevious,"retired":false]
      // 日期属于被归档的版本，不是本次创建历史入口的时间；各设备统一按 UTC 分桶。
      if let published = httpDate(prior.response.value(forHTTPHeaderField:"Last-Modified")) {
        history["published_at_ms"] = published.timeIntervalSince1970 * 1000
      }
      let historyData = try JSONSerialization.data(withJSONObject:history,options:[.sortedKeys])
      try await uploadUnique(publishing,path:backupPath,data:historyData,limit:64 * 1024,createOnly:capabilities.createOnly)
      condition = ["If-Match":tag]
    } else {
      guard prior.response.statusCode == 404 else { throw WebDAVFailure("sync.errors.remoteChanged") }
      condition = capabilities.createOnly ? ["If-None-Match":"*"] : [:]
    }
    let tag = try await publishHead(publishing,head:head,condition:condition)
    return ["published":true,"etag":tag,"remote_backup_path":backup ?? ""]
  }
  private struct CleanupEntry {
    let path: String
    let etag: String
    let modified: Date
  }
  private struct HistoryReference {
    let etag: String
    let snapshot: String
    let head: [String: Any]
    let published: Date?
    let important: Bool
    let retired: Bool
  }
  private func historyReference(_ data: Data, tag: String) throws -> HistoryReference {
    guard let object = try JSONSerialization.jsonObject(with:data) as? [String: Any] else {
      throw WebDAVFailure("sync.cleanup.incomplete")
    }
    var head = object
    var published: Date? = nil
    var important = false, retired = false
    if object["format"] as? String == "credpivot-history" {
      guard object["version"] as? Int == 1, let storedHead = object["head"] as? [String: Any],
            let storedImportant = object["important"] as? Bool,
            let storedRetired = object["retired"] as? Bool else { throw WebDAVFailure("sync.cleanup.incomplete") }
      head = storedHead; important = storedImportant; retired = storedRetired
      if let value = object["published_at_ms"] {
        guard let milliseconds = value as? Double, milliseconds.isFinite,
              milliseconds > 0, milliseconds <= 253402300799000 else { throw WebDAVFailure("sync.cleanup.incomplete") }
        published = Date(timeIntervalSince1970:milliseconds / 1000)
      }
    }
    // 兼容此前直接保存 head.json 的历史入口。
    return HistoryReference(etag:tag,snapshot:try validSnapshot(head),head:head,
                            published:published,important:important,retired:retired)
  }
  private func httpDate(_ value: String?) -> Date? {
    guard let value = value else { return nil }
    let formatter = DateFormatter()
    formatter.locale = Locale(identifier:"en_US_POSIX"); formatter.timeZone = TimeZone(secondsFromGMT:0)
    formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss zzz"
    return formatter.date(from:value)
  }
  private func cleanupRequest(_ config: [String: Any], _ path: String, method: String = "GET", data: Data? = nil,
                              headers: [String: String] = [:], limit: Int = 64 * 1024,
                              page: URL? = nil) async throws -> WebDAVTransfer.Reply {
    guard cleanupRequests > 0 else { throw WebDAVFailure("sync.cleanup.deferred") }
    cleanupRequests -= 1
    return try await request(config,path,method:method,data:data,headers:headers,limit:limit,listingPage:page)
  }
  private func cleanupListing(_ config: [String: Any], _ path: String) async throws -> [WebDAVListing.Entry] {
    let body = Data("<?xml version=\"1.0\"?><d:propfind xmlns:d=\"DAV:\"><d:prop><d:resourcetype/><d:getetag/><d:getlastmodified/></d:prop></d:propfind>".utf8)
    var page: URL? = nil, visited = Set<String>(), entries: [String: WebDAVListing.Entry] = [:]
    var foundDirectory = false
    while true {
      let reply = try await cleanupRequest(config,path,method:"PROPFIND",data:body,
        headers:["Depth":"1","Content-Type":"application/xml"],limit:8 * 1024 * 1024,page:page)
      guard reply.response.statusCode == 207, let url = reply.response.url,
            visited.insert(url.absoluteString).inserted, visited.count <= 64 else { throw WebDAVFailure("sync.cleanup.incomplete") }
      let parser = XMLParser(data:reply.data), listing = WebDAVListing()
      parser.shouldProcessNamespaces = true; parser.shouldResolveExternalEntities = false; parser.delegate = listing
      guard parser.parse(), listing.valid, !listing.entries.isEmpty else { throw WebDAVFailure("sync.cleanup.incomplete") }
      for entry in listing.entries {
        guard let target = URL(string:entry.href,relativeTo:url)?.absoluteURL,
              target.scheme?.lowercased() == url.scheme?.lowercased(), target.host?.lowercased() == url.host?.lowercased(),
              (target.port ?? 443) == (url.port ?? 443),
              target.user == nil, target.password == nil, target.query == nil, target.fragment == nil else {
          throw WebDAVFailure("sync.cleanup.incomplete")
        }
        if target.path.trimmingCharacters(in:CharacterSet(charactersIn:"/")) == url.path.trimmingCharacters(in:CharacterSet(charactersIn:"/")) {
          guard entry.collection else { throw WebDAVFailure("sync.cleanup.incomplete") }
          foundDirectory = true; continue
        }
        let directoryPath = url.path.hasSuffix("/") ? url.path : url.path + "/"
        guard target.path.hasPrefix(directoryPath) else { throw WebDAVFailure("sync.cleanup.incomplete") }
        var name = String(target.path.dropFirst(directoryPath.count))
        if entry.collection, name.hasSuffix("/") { name.removeLast() }
        guard !name.isEmpty, !name.contains("/"), entries[name] == nil else { throw WebDAVFailure("sync.cleanup.incomplete") }
        entries[name] = entry
      }
      guard entries.count <= 10000 else { throw WebDAVFailure("sync.cleanup.incomplete") }
      guard let link = reply.response.value(forHTTPHeaderField:"Link"), !link.isEmpty else {
        // 坚果云单页上限 750 项；达到上限却没有游标时，不能推断列表完整。
        if config["provider"] as? String == "nutstore", listing.entries.count >= 750 {
          throw WebDAVFailure("sync.cleanup.incomplete")
        }
        break
      }
      let pattern = "<([^>]+)>\\s*;\\s*rel=\"next\""
      let expression = try NSRegularExpression(pattern:pattern,options:.caseInsensitive)
      let matches = expression.matches(in:link,range:NSRange(link.startIndex...,in:link))
      if matches.isEmpty {
        if link.lowercased().contains("next") { throw WebDAVFailure("sync.cleanup.incomplete") }
        break
      }
      guard matches.count == 1, let range = Range(matches[0].range(at:1),in:link),
            let next = URL(string:String(link[range]),relativeTo:url)?.absoluteURL else { throw WebDAVFailure("sync.cleanup.incomplete") }
      page = next
    }
    guard foundDirectory else { throw WebDAVFailure("sync.cleanup.incomplete") }
    // 名字仅用于限定本应用拥有的文件；实际删除仍依赖服务器修改时间及已验证的条件删除能力。
    return entries.map { name, entry in WebDAVListing.Entry(href:name,properties:entry.properties,collection:entry.collection) }
  }
  private func cleanupEntry(_ entry: WebDAVListing.Entry, directory: String) -> CleanupEntry? {
    guard !entry.collection,
          let modified = httpDate(entry.properties["getlastmodified"]),
          let tag = try? validatedETag(entry.properties["getetag"]) else { return nil }
    if directory.isEmpty {
      let prefix = ".credpivot-probe-"
      guard entry.href.hasPrefix(prefix), UUID(uuidString:String(entry.href.dropFirst(prefix.count))) != nil else { return nil }
      return CleanupEntry(path:entry.href,etag:tag,modified:modified)
    }
    let suffix = directory == "backups/" ? ".json" : ".ovb"
    guard entry.href.hasSuffix(suffix) else { return nil }
    let parts = entry.href.dropLast(suffix.count).split(separator:"_",omittingEmptySubsequences:false)
    guard parts.count == 3, parts[0] == (directory == "backups/" ? "head" : "credpivot"),
          UUID(uuidString:String(parts[2])) != nil else { return nil }
    let created: Date?
    if let milliseconds = Int64(parts[1]), milliseconds > 0 {
      created = Date(timeIntervalSince1970:Double(milliseconds) / 1000)
    } else {
      let formatter = DateFormatter()
      formatter.locale = Locale(identifier:"en_US_POSIX"); formatter.timeZone = TimeZone(secondsFromGMT:0)
      formatter.dateFormat = "yyyyMMdd'T'HHmmss'Z'"; formatter.isLenient = false
      created = formatter.date(from:String(parts[1]))
    }
    guard let created = created else { return nil }
    // 设备时钟偏移或文件被重新写入时，宁可延迟清理，也不缩短保留期。
    return CleanupEntry(path:directory + entry.href,etag:tag,modified:max(created,modified))
  }
  private func cleanupCurrent(_ config: [String: Any], head: [String: Any], tag: String) async throws -> WebDAVTransfer.Reply {
    let reply = try await cleanupRequest(config,"head.json",headers:["If-Match":tag])
    guard reply.response.statusCode == 200, try etag(reply) == tag,
          let observed = try JSONSerialization.jsonObject(with:reply.data) as? [String: Any],
          NSDictionary(dictionary:observed).isEqual(to:head) else { throw WebDAVFailure("sync.cleanup.changed") }
    return reply
  }
  private func verifyCleanupDelete(_ config: [String: Any]) async throws {
    if cleanupDeleteVerified { return }
    let path = "snapshots/credpivot_\(Int64(Date().timeIntervalSince1970 * 1000))_\(UUID().uuidString).ovb"
    let body = Data("credpivot-cleanup-probe".utf8)
    let created = try await cleanupRequest(config,path,method:"PUT",data:body)
    guard [200,201,204].contains(created.response.statusCode) else { throw WebDAVFailure("sync.cleanup.deleteUnsupported") }
    do {
      let original = try await cleanupRequest(config,path), tag = try etag(original)
      guard original.response.statusCode == 200, original.data == body else { throw WebDAVFailure("sync.cleanup.deleteUnsupported") }
      let invalid = "credpivot-invalid-" + UUID().uuidString
      let wrongTag = tag.hasPrefix("\"") ? "\"\(invalid)\"" : invalid
      // 淘汰标记需要条件更新；不能只检查 DELETE，否则服务器忽略 If-Match 时会覆盖别端标记。
      let changedBody = Data("credpivot-cleanup-changed".utf8)
      let wrongUpdate = try await cleanupRequest(config,path,method:"PUT",data:changedBody,headers:["If-Match":wrongTag])
      let afterUpdate = try await cleanupRequest(config,path)
      guard wrongUpdate.response.statusCode == 412, afterUpdate.response.statusCode == 200,
            afterUpdate.data == body, try etag(afterUpdate) == tag else { throw WebDAVFailure("sync.cleanup.deleteUnsupported") }
      let wrong = try await cleanupRequest(config,path,method:"DELETE",headers:["If-Match":wrongTag])
      let unchanged = try await cleanupRequest(config,path)
      guard wrong.response.statusCode == 412, unchanged.response.statusCode == 200,
            unchanged.data == body, try etag(unchanged) == tag else { throw WebDAVFailure("sync.cleanup.deleteUnsupported") }
      let removed = try await cleanupRequest(config,path,method:"DELETE",headers:["If-Match":tag])
      let missing = try await cleanupRequest(config,path)
      guard [200,204].contains(removed.response.statusCode), missing.response.statusCode == 404 else { throw WebDAVFailure("sync.cleanup.deleteUnsupported") }
      cleanupDeleteVerified = true
    } catch {
      // 仅补偿本次创建的随机探测文件，不触碰任何历史文件。
      _ = try? await request(config,path,method:"DELETE",limit:1024)
      throw error
    }
  }
  private func removeCleanupEntry(_ config: [String: Any], entry: CleanupEntry,
                                  head: [String: Any], tag: String) async throws {
    guard cleanupRequests >= 2 else { throw WebDAVFailure("sync.cleanup.deferred") }
    _ = try await cleanupCurrent(config,head:head,tag:tag)
    let removed = try await cleanupRequest(config,entry.path,method:"DELETE",headers:["If-Match":entry.etag])
    guard [200,204,404].contains(removed.response.statusCode) else { throw WebDAVFailure("sync.cleanup.changed") }
  }
  private func cleanup(_ config: [String: Any], args: [String: Any]) async throws -> [String: Any] {
    guard let location = config["location"] as? String, args["location"] as? String == location,
          let head = args["head"] as? [String: Any], let tag = args["etag"] as? String,
          let status = LocalVaultUnlock.request(["type":"sync_status"]),
          status["connected"] as? Bool == true, status["location"] as? String == location,
          status["pending_upload"] as? Bool == false else { throw WebDAVFailure("sync.cleanup.changed") }
    if cleanupLocation != location {
      cleanupLocation = location; cleanupDue = .distantPast; cleanupReferences.removeAll(); cleanupDeleteVerified = false
    }
    if Date() < cleanupDue { return ["throttled":true] }
    let dailyHistoryCount = config["daily_history_count"] as? Int ?? 5
    guard (3...99).contains(dailyHistoryCount) else { throw WebDAVFailure("sync.errors.dailyHistoryCount") }
    // 限制额外请求量，引用缓存由每轮完整列表中的 ETag 校验，不缓存密文或凭据。
    cleanupRequests = 64; cleanupDue = Date().addingTimeInterval(15 * 60)
    do {
      let currentSnapshot = try validSnapshot(head)
      let current = try await cleanupCurrent(config,head:head,tag:tag)
      guard let serverTime = httpDate(current.response.value(forHTTPHeaderField:"Date")) else { throw WebDAVFailure("sync.cleanup.incomplete") }
      let now = min(serverTime,Date()), historyCutoff = now.addingTimeInterval(-30 * 86400)
      let orphanCutoff = now.addingTimeInterval(-7 * 86400), readCutoff = now.addingTimeInterval(-10 * 60)
      let backupListing = try await cleanupListing(config,"backups/")
      let snapshotListing = try await cleanupListing(config,"snapshots/")
      let rootListing = try await cleanupListing(config,"")
      let backups = backupListing.compactMap { cleanupEntry($0,directory:"backups/") }.sorted { $0.modified < $1.modified }
      let snapshots = snapshotListing.compactMap { cleanupEntry($0,directory:"snapshots/") }
      let snapshotsByPath = Dictionary(uniqueKeysWithValues:snapshots.map { ($0.path,$0) })
      // 无法辨认的入口也可能引用有效快照，此时不猜测、不删除。
      guard backups.count == backupListing.count else { throw WebDAVFailure("sync.cleanup.incomplete") }
      let listed = Set(backups.map { $0.path })
      cleanupReferences = cleanupReferences.filter { listed.contains($0.key) }
      for entry in backups {
        if cleanupReferences[entry.path]?.etag != entry.etag {
          let reply = try await cleanupRequest(config,entry.path,headers:["If-Match":entry.etag])
          guard reply.response.statusCode == 200, try etag(reply) == entry.etag else { throw WebDAVFailure("sync.cleanup.incomplete") }
          cleanupReferences[entry.path] = try historyReference(reply.data,tag:entry.etag)
        }
      }
      let references = cleanupReferences
      let listedSnapshots = Set(snapshotListing.map { "snapshots/" + $0.href })
      for reference in references.values {
        // 列表中存在但缺少可靠版本号/时间的快照，不能当成已删除，否则会丢失后续清理凭据。
        if listedSnapshots.contains(reference.snapshot), snapshotsByPath[reference.snapshot] == nil {
          throw WebDAVFailure("sync.cleanup.incomplete")
        }
      }
      func versionDate(_ entry: CleanupEntry) -> Date {
        guard let reference = references[entry.path] else { return entry.modified }
        return reference.published ?? snapshotsByPath[reference.snapshot]?.modified ?? entry.modified
      }
      let active = backups.filter { references[$0.path]?.retired == false }
      let ranked = active.sorted {
        let first = versionDate($0), second = versionDate($1)
        if first != second { return first > second }
        if $0.modified != $1.modified { return $0.modified > $1.modified }
        return $0.path < $1.path
      }
      // 一次版本可能因重试留下多个入口；先去重，并优先保留有重要操作标记的入口。
      var canonical: [String: CleanupEntry] = [:]
      for entry in ranked {
        guard let reference = references[entry.path] else { throw WebDAVFailure("sync.cleanup.incomplete") }
        if let previous = canonical[reference.snapshot] {
          if reference.important && references[previous.path]?.important != true { canonical[reference.snapshot] = entry }
        } else { canonical[reference.snapshot] = entry }
      }
      let eligible = ranked.filter { entry in
        guard let reference = references[entry.path] else { return false }
        return canonical[reference.snapshot]?.path == entry.path
          && reference.snapshot != currentSnapshot && versionDate(entry) >= historyCutoff
      }
      var retained = Set<String>(), recent = 0
      var days: [Date: Int] = [:]
      var calendar = Calendar(identifier:.gregorian)
      calendar.timeZone = TimeZone(secondsFromGMT:0)!
      for entry in eligible {
        guard let reference = references[entry.path] else { throw WebDAVFailure("sync.cleanup.incomplete") }
        // 时钟异常的未来版本先保留，也不占用正常的五个近期恢复位置。
        if versionDate(entry) > now { retained.insert(entry.path); continue }
        if recent < 5 { retained.insert(entry.path); recent += 1 }
        let day = calendar.startOfDay(for:versionDate(entry)), count = days[day] ?? 0
        if (days[day] != nil || days.count < 30), count < dailyHistoryCount {
          retained.insert(entry.path); days[day] = count + 1
        }
        if reference.important { retained.insert(entry.path) }
      }
      // 当前版本可因失败发布已存在历史副本，其中的重要操作标记仍应保留。
      for entry in active {
        if let reference = references[entry.path], reference.snapshot == currentSnapshot,
           reference.important, canonical[reference.snapshot]?.path == entry.path,
           versionDate(entry) >= historyCutoff { retained.insert(entry.path) }
      }
      let retiring = active.filter { !retained.contains($0.path) && $0.modified < readCutoff }
      let retired = backups.filter { references[$0.path]?.retired == true && $0.modified < readCutoff }
      // 原历史入口是持久清理凭据：淘汰后仍保留一个短暂读取窗口，重启或网络失败均可续做。
      var protected: Set<String> = [currentSnapshot]
      for entry in active {
        if let reference = references[entry.path] { protected.insert(reference.snapshot) }
      }
      let managed = Set(references.values.map { $0.snapshot })
      // 只有从未归档的失败上传才走 7 天规则；正常淘汰的历史由 retired 标记单独处理。
      let unused = snapshots.filter { $0.modified < orphanCutoff && $0.path != currentSnapshot && !managed.contains($0.path) }
        .sorted { $0.modified < $1.modified }
      let abandonedProbes = rootListing.compactMap { cleanupEntry($0,directory:"") }
        .filter { $0.modified < orphanCutoff }.sorted { $0.modified < $1.modified }
      guard !retiring.isEmpty || !retired.isEmpty || !unused.isEmpty || !abandonedProbes.isEmpty else { return ["completed":true] }
      try await verifyCleanupDelete(config)
      var removedHeads = 0, removedSnapshots = Set<String>(), removedProbes = 0, marked = 0
      for entry in retiring {
        guard cleanupRequests >= 3, let reference = references[entry.path] else { throw WebDAVFailure("sync.cleanup.deferred") }
        _ = try await cleanupCurrent(config,head:head,tag:tag)
        let marker: [String: Any] = ["format":"credpivot-history","version":1,"head":reference.head,
          "important":reference.important,"retired":true,"published_at_ms":versionDate(entry).timeIntervalSince1970 * 1000]
        let body = try JSONSerialization.data(withJSONObject:marker,options:[.sortedKeys])
        let changed = try await cleanupRequest(config,entry.path,method:"PUT",data:body,
          headers:["If-Match":entry.etag,"Content-Type":"application/json"])
        guard [200,204].contains(changed.response.statusCode) else { throw WebDAVFailure("sync.cleanup.changed") }
        let verified = try await cleanupRequest(config,entry.path)
        guard verified.response.statusCode == 200, verified.data == body else { throw WebDAVFailure("sync.cleanup.changed") }
        cleanupReferences[entry.path] = try historyReference(verified.data,tag:etag(verified))
        marked += 1
      }
      for entry in retired {
        guard let reference = references[entry.path] else { throw WebDAVFailure("sync.cleanup.incomplete") }
        if !protected.contains(reference.snapshot), !removedSnapshots.contains(reference.snapshot),
           let snapshot = snapshotsByPath[reference.snapshot] {
          // 如果失败或中断，保留淘汰标记；下次继续，避免把正常历史误当成 7 天孤立文件。
          guard snapshot.modified < readCutoff else { continue }
          try await removeCleanupEntry(config,entry:snapshot,head:head,tag:tag)
          removedSnapshots.insert(snapshot.path)
        }
        try await removeCleanupEntry(config,entry:entry,head:head,tag:tag)
        cleanupReferences.removeValue(forKey:entry.path); removedHeads += 1
      }
      for entry in unused + abandonedProbes {
        try await removeCleanupEntry(config,entry:entry,head:head,tag:tag)
        if entry.path.hasPrefix("snapshots/") { removedSnapshots.insert(entry.path) } else { removedProbes += 1 }
      }
      return ["completed":true,"retired_heads":marked,"deleted_heads":removedHeads,
              "deleted_snapshots":removedSnapshots.count,"deleted_probes":removedProbes]
    } catch let failure as WebDAVFailure {
      if failure.key == "sync.cleanup.deferred" { cleanupDue = Date().addingTimeInterval(5 * 60) }
      throw failure
    }
  }
  func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    let bootstrap = call.method == "webdavBootstrapRead"
    if bootstrap {
      guard let state = LocalVaultUnlock.request(["type":"status"]), state["vault_exists"] as? Bool == false, state["unlocked"] as? Bool != true else {
        result(FlutterError(code:"sync.bootstrap.existing",message:NativePresentation.tr("sync.bootstrap.existing"),details:nil)); return
      }
    } else if !unlocked() { result(FlutterError(code:"locked",message:NativePresentation.tr("sync.errors.locked"),details:nil)); return }
    if call.method == "webdavSettings" {
      var value = settings() ?? [:]
      if let location = value["location"] as? String { value["password_saved"] = (try? password(location)) != nil }
      result(value); return
    }
    guard !busy else { result(FlutterError(code:"sync_busy",message:NativePresentation.tr("sync.errors.busy"),details:nil)); return }
    busy = true
    Task { @MainActor in
      defer { busy = false }
      var testChecks: [[String: Any]] = []
      do {
        let args = call.arguments as? [String: Any] ?? [:]
        if bootstrap {
          let next = try normalized(args)
          guard let password = args["password"] as? String, !password.isEmpty else { throw WebDAVFailure("sync.errors.passwordMissing") }
          var config = next
          config["_password"] = password; config["_bootstrap_read_only"] = true; config["_transfer_generation"] = generation
          var value = try await read(config,knownETag:args["etag"] as? String)
          value["configuration"] = next; result(value); return
        }
        if call.method == "webdavRemove" {
          guard LocalVaultUnlock.request(["type":"sync_disconnect"]) != nil else { throw WebDAVFailure("sync.errors.authentication") }
          try saveSettings(NSNull())
          try forgetPasswords()
          result(["removed":true]); return
        }
        if call.method == "webdavSave" || call.method == "webdavTest" {
          try authorize()
          let next = try normalized(args)
          guard let location = next["location"] as? String else { throw WebDAVFailure("sync.errors.configuration") }
          let supplied = args["password"] as? String ?? ""
          let previousPassword = try? password(location)
          guard let credential = supplied.isEmpty ? previousPassword : supplied else { throw WebDAVFailure("sync.errors.passwordMissing") }
          if call.method == "webdavTest" {
            let previousCapabilities = writeCapabilities, testGeneration = generation
            defer {
              // 草稿测试不能改变已保存连接的运行能力，也不能恢复被锁定操作清除的缓存。
              if generation == testGeneration { writeCapabilities = previousCapabilities }
            }
            var draft = next
            draft["_transfer_generation"] = generation
            draft["_password"] = credential
            await retryProbeCleanup(draft,testDirectoriesOnly:true)
            try await probe(draft,onCheck:{ testChecks.append($0) })
            result(["ok":true,"checks":testChecks,"initial_creation":writeCapabilities?.initialCreation ?? ""])
            return
          }
          // 显式 false 表示当前草稿已手动测试过，保存时不再重复发起探测。
          let shouldVerify = args["verify"] as? Bool ?? (settings()?["location"] as? String != location || WebDAVProviderPolicy(settings() ?? [:]) != WebDAVProviderPolicy(next) || !supplied.isEmpty)
          if shouldVerify {
            var draft = next
            draft["_transfer_generation"] = generation
            draft["_password"] = credential
            await retryProbeCleanup(draft,testDirectoriesOnly:true)
            try await probe(draft)
          }
          guard unlocked() else { throw WebDAVFailure("sync.errors.locked") }
          if !supplied.isEmpty { try savePassword(supplied,location:location) }
          do { try saveSettings(next) }
          catch {
            // 配置落盘失败时恢复同连接的旧应用密码，保留原来的可用配置。
            if !supplied.isEmpty {
              if let old = previousPassword { try savePassword(old,location:location) }
              else { _ = SecItemDelete(keyQuery(location) as CFDictionary) }
            }
            throw error
          }
          if args["verify"] as? Bool == true || !supplied.isEmpty {
            cleanupLocation = ""; cleanupReferences.removeAll(); cleanupDeleteVerified = false
          }
          var saved = next
          saved["password_saved"] = true
          result(saved); return
        }
        guard var config = settings() else { throw WebDAVFailure("sync.errors.configuration") }
        config["_transfer_generation"] = generation
        await retryProbeCleanup(config)
        switch call.method {
        case "webdavProbe": try await probe(config); result(["ok":true])
        case "webdavRead": result(try await read(config,knownETag:args["etag"] as? String))
        case "webdavPublish": result(try await publish(config,args:args))
        case "webdavCleanup": result(try await cleanup(config,args:args))
        default: result(FlutterMethodNotImplemented)
        }
      } catch let error as WebDAVFailure {
        var message = NativePresentation.tr(error.key), details: [String: Any] = [:]
        if let stage = error.stage {
          message = NativePresentation.tr("sync.errors.stageDetail", arguments:["message":message,"stage":NativePresentation.tr("sync.probe." + stage)])
          details["stage"] = stage
        }
        if let status = error.status {
          message = NativePresentation.tr("sync.errors.httpDetail", arguments:["message":message,"status":String(status)])
          details["http_status"] = status
        }
        if let statuses = error.statuses {
          message = NativePresentation.tr("sync.errors.httpDetail", arguments:["message":message,"status":statuses.map(String.init).joined(separator:", ")])
          details["http_statuses"] = statuses
        }
        if call.method == "webdavTest" { details["checks"] = testChecks }
        if let retryAfter = error.retryAfter { details["retry_after"] = retryAfter }
        // 诊断仅返回固定阶段和 HTTP 状态，不返回 URL、ETag、账户或服务端正文。
        result(FlutterError(code:error.key,message:message,details:details.isEmpty ? nil : details))
      } catch {
        // 不返回 URLSession/服务端正文，异常中可能带账户、URL 或认证信息。
        result(FlutterError(code:"sync_network",message:NativePresentation.tr("sync.errors.network"),details:call.method == "webdavTest" ? ["checks":testChecks] : nil))
      }
    }
  }
}

extension Notification.Name {
  static let credPivotVaultLocked = Notification.Name("CredPivotVaultLocked")
}

final class CredPivotPlatform: NSObject {
  private let channel: FlutterMethodChannel
  private var sshAuthorizationTimer: Timer?
  private var pollingAuthorizations = false
  private var showingSshAuthorization = false
  private var showingPasskeyAuthorization = false
  private var shortcutController: CredPivotShortcuts?
  private var foregroundUnlockArmed = true

  init(messenger: FlutterBinaryMessenger) {
    channel = FlutterMethodChannel(name: "credpivot/agent", binaryMessenger: messenger)
    super.init()
    channel.setMethodCallHandler(handle)
    DispatchQueue.main.async { [weak self] in self?.startInteractionServices() }
    NotificationCenter.default.addObserver(
      self,
      selector: #selector(vaultLockedExternally),
      name: .credPivotVaultLocked,
      object: nil
    )
    NotificationCenter.default.addObserver(self, selector: #selector(appBecameActive),
      name: NSApplication.didBecomeActiveNotification, object: nil)
    NotificationCenter.default.addObserver(self, selector: #selector(appResignedActive),
      name: NSApplication.didResignActiveNotification, object: nil)
    NotificationCenter.default.addObserver(self, selector: #selector(mainWindowBecameKey(_:)),
      name: NSWindow.didBecomeKeyNotification, object: nil)
    NotificationCenter.default.addObserver(self, selector: #selector(mainWindowResignedKey(_:)),
      name: NSWindow.didResignKeyNotification, object: nil)
  }

  private var isMainWindowForeground: Bool {
    guard let window = (NSApp.delegate as? AppDelegate)?.mainFlutterWindow else { return false }
    return NSApp.isActive && window.isVisible && !window.isMiniaturized
  }

  @objc private func appResignedActive() {
    // 验证弹窗和原生模态窗口也会暂时夺走焦点，返回时不能再次自动验证。
    foregroundUnlockArmed = !TouchIdGate.isAuthenticating && NSApp.modalWindow == nil
  }

  @objc private func appBecameActive() {
    guard foregroundUnlockArmed else { return }
    notifyAppForeground()
  }

  @objc private func mainWindowBecameKey(_ notification: Notification) {
    guard foregroundUnlockArmed,
      let window = notification.object as? NSWindow,
      window === (NSApp.delegate as? AppDelegate)?.mainFlutterWindow else { return }
    notifyAppForeground()
  }

  @objc private func mainWindowResignedKey(_ notification: Notification) {
    guard let window = notification.object as? NSWindow,
      window === (NSApp.delegate as? AppDelegate)?.mainFlutterWindow else { return }
    appResignedActive()
  }

  func notifyAppForeground() {
    guard isMainWindowForeground, !TouchIdGate.isAuthenticating, NSApp.modalWindow == nil else { return }
    foregroundUnlockArmed = false
    channel.invokeMethod("onAppForeground", arguments: nil)
  }

  private func startInteractionServices() {
    NativePresentation.reload()
    DispatchQueue.global(qos: .utility).async { CredPivotGitSsh.refreshIfManaged() }
    shortcutController = CredPivotShortcuts { [weak self] action in
      if action == "lock" {
        (NSApp.delegate as? AppDelegate)?.lockFromMenu()
      } else {
        self?.channel.invokeMethod("onShortcut", arguments: action)
      }
    }
    shortcutController?.apply(AppPreferences.settings())
    sshAuthorizationTimer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { [weak self] _ in
      guard let self = self, !self.pollingAuthorizations, !self.showingSshAuthorization,
            !self.showingPasskeyAuthorization, !TouchIdGate.isAuthenticating, NSApp.modalWindow == nil else { return }
      self.pollingAuthorizations = true
      let epoch = TouchIdGate.authenticationEpoch
      // Agent 忙碌时只延后本次查询，不能让周期轮询卡住主线程的指纹取消回调。
      DispatchQueue.global(qos: .userInitiated).async { [weak self] in
        let passkeys = LocalVaultUnlock.request(["type": "passkey_requests_pending"])?["requests"] as? [[String: Any]] ?? []
        var ssh: [[String: Any]] = []
        if passkeys.isEmpty {
          ssh = LocalVaultUnlock.request(["type": "ssh_authorizations_pending"])?["requests"] as? [[String: Any]] ?? []
        }
        DispatchQueue.main.async { [weak self] in
          guard let self = self else { return }
          defer { self.pollingAuthorizations = false }
          guard epoch == TouchIdGate.authenticationEpoch else { return }
          self.consumePasskeyAuthorization(requests: passkeys)
          self.consumeSshAuthorization(requests: ssh)
        }
      }
    }
  }

  private func consumeSshAuthorization(requests: [[String: Any]]) {
    guard !showingSshAuthorization, !showingPasskeyAuthorization, !TouchIdGate.isAuthenticating, NSApp.modalWindow == nil,
          let request = requests.first, let id = request["id"] as? String else { return }
    showingSshAuthorization = true
    NSApp.activate(ignoringOtherApps: true)
    let alert = NSAlert()
    let policy = request["policy"] as? String ?? "confirm"
    let candidates = request["candidates"] as? [[String: Any]] ?? []
    let picker = NSPopUpButton(frame: NSRect(x: 0, y: 0, width: 520, height: 28), pullsDown: false)
    let remember = NSButton(checkboxWithTitle: NativePresentation.tr("ssh.git.remember"), target: nil, action: nil)
    remember.state = .on
    if policy == "git_select" {
      for candidate in candidates {
        picker.addItem(withTitle: "\(candidate["label"] as? String ?? "SSH") · \(candidate["partition"] as? String ?? "") · \(candidate["fingerprint"] as? String ?? "")")
      }
      let accessory = NSStackView(views: [picker, remember])
      accessory.orientation = .vertical; accessory.alignment = .leading; accessory.spacing = 8
      accessory.frame = NSRect(x: 0, y: 0, width: 520, height: 66)
      alert.accessoryView = accessory
    }
    alert.messageText = policy == "unlock" ? NativePresentation.tr("ssh.authorization.unlockTitle") : NativePresentation.tr("ssh.authorization.confirmTitle")
    var scope = policy == "session" ? NativePresentation.tr("ssh.authorization.sessionScope") : NativePresentation.tr("ssh.authorization.onceScope")
    let caller = request["caller"] as? String ?? NativePresentation.tr("common.unknownProcess")
    alert.informativeText = policy == "unlock"
      ? NativePresentation.tr("ssh.authorization.unlockBody", arguments: ["caller": caller])
      : NativePresentation.tr("ssh.authorization.signBody", arguments: ["label": request["key_label"] as? String ?? NativePresentation.tr("common.unknown"), "fingerprint": request["fingerprint"] as? String ?? "", "caller": caller, "scope": scope])
    if let repository = request["repository"] as? String, !repository.isEmpty {
      let reuseSeconds = (request["reuse_seconds"] as? NSNumber)?.uint64Value ?? 0
      if policy == "session", reuseSeconds > 0 {
        scope = NativePresentation.tr("ssh.git.authorization.reuseScope", arguments: ["minutes": String(reuseSeconds / 60)])
      }
      // 此信息来自受信任的 Git 适配器；普通 SSH 没有仓库上下文，继续使用原提示。
      let sources = ["local_memory": "ssh.git.source.localMemory", "remote_memory": "ssh.git.source.remoteMemory",
        "rule": "ssh.git.source.rule", "manual": "ssh.git.source.manual", "reselect": "ssh.git.source.reselect",
        "multiple_rules": "ssh.git.source.multipleRules", "no_rule": "ssh.git.source.noRule", "pending": "ssh.git.source.pending"]
      let source = NativePresentation.tr(sources[request["selection_source"] as? String ?? ""] ?? "ssh.git.source.pending")
      if policy == "unlock" {
        alert.informativeText = NativePresentation.tr("ssh.git.authorization.unlockBody", arguments: ["repository": repository, "caller": caller])
      } else if policy == "git_select" {
        alert.messageText = NativePresentation.tr("ssh.git.chooseTitle")
        alert.informativeText = NativePresentation.tr("ssh.git.chooseBody", arguments: ["repository": repository, "source": source])
        if reuseSeconds > 0 {
          alert.informativeText += "\n\n" + NativePresentation.tr("ssh.git.authorization.chooseReuse", arguments: ["minutes": String(reuseSeconds / 60)])
        }
      } else {
        alert.messageText = NativePresentation.tr("ssh.git.authorization.signTitle")
        alert.informativeText = NativePresentation.tr("ssh.git.authorization.signBody", arguments: ["repository": repository,
          "source": source, "label": request["key_label"] as? String ?? NativePresentation.tr("common.unknown"),
          "fingerprint": request["fingerprint"] as? String ?? "", "caller": caller, "scope": scope])
      }
      if let rule = request["matched_rule"] as? String, !rule.isEmpty {
        alert.informativeText += "\n" + NativePresentation.tr("ssh.git.authorization.matchedRule", arguments: ["rule": rule])
      }
    }
    alert.informativeText += "\n\n" + NativePresentation.tr("ssh.authorization.verificationNotice")
    alert.addButton(withTitle: NativePresentation.tr("common.continue"))
    alert.addButton(withTitle: NativePresentation.tr("common.deny"))
    // runModal 使用独立运行循环；请求已断开或过期时主动关闭，避免留下失效弹窗。
    let expiry = Timer(timeInterval: 0.5, repeats: true) { _ in
      guard let pending = LocalVaultUnlock.request(["type": "ssh_authorizations_pending"])?["requests"] as? [[String: Any]],
            pending.contains(where: { $0["id"] as? String == id }) else {
        NSApp.abortModal()
        alert.window.orderOut(nil)
        return
      }
    }
    RunLoop.main.add(expiry, forMode: .modalPanel)
    let response = alert.runModal()
    expiry.invalidate()
    guard response == .alertFirstButtonReturn else {
      _ = LocalVaultUnlock.request(["type": "ssh_authorization_resolve", "request_id": id, "approved": false])
      showingSshAuthorization = false
      return
    }
    let selected = candidates.indices.contains(picker.indexOfSelectedItem) ? candidates[picker.indexOfSelectedItem] : [:]
    let complete: (Bool) -> Void = { [weak self] ok in
      _ = LocalVaultUnlock.request(["type": "ssh_authorization_resolve", "request_id": id, "approved": ok,
        "key_id": selected["id"] as? String ?? "", "remember": ok && policy == "git_select" && remember.state == .on])
      self?.showingSshAuthorization = false
    }
    if policy == "biometric" || (policy == "git_select" && selected["policy"] as? String == "biometric") {
      TouchIdGate.shared.authenticateForExtensionGate(reason: NativePresentation.tr("ssh.authorization.biometricReason"), completion: complete)
    } else {
      TouchIdGate.shared.authenticateSensitiveOperation(reason: policy == "unlock" ? NativePresentation.tr("ssh.authorization.unlockReason") : NativePresentation.tr("ssh.authorization.reason"), completion: complete)
    }
  }

  @objc private func selectPasskeyAccount(_ sender: NSButton) {
    for case let button as NSButton in sender.superview?.subviews ?? [] {
      button.state = button === sender ? .on : .off
    }
  }

  private func consumePasskeyAuthorization(requests: [[String: Any]]) {
    guard !showingPasskeyAuthorization, !showingSshAuthorization, !TouchIdGate.isAuthenticating, NSApp.modalWindow == nil,
          let request = requests.first, let id = request["id"] as? String else { return }
    showingPasskeyAuthorization = true
    let create = request["create"] as? Bool == true
    let origin = request["origin"] as? String ?? ""
    let candidates = request["candidates"] as? [[String: Any]] ?? []
    let alert = NSAlert()
    alert.messageText = NativePresentation.tr(create ? NativePresentation.tr("passkey.authorization.createTitle") : NativePresentation.tr("passkey.authorization.loginTitle"))
    let website = NativePresentation.tr("passkey.authorization.website", arguments: ["origin": origin])
    let account = passkeyAccountLabel(request["username"] as? String ?? "", request["display_name"] as? String ?? "")
    alert.informativeText = create
      ? website + "\n" + NativePresentation.tr("passkey.authorization.createBody", arguments: ["account": account])
      : website + "\n\n" + NativePresentation.tr("native.consumePasskeyAuthorization.text.item3")
    let picker = NSPopUpButton(frame: NSRect(x: 0, y: 0, width: 380, height: 28), pullsDown: false)
    var accountButtons: [NSButton] = []
    var accountIds = [""]
    if create {
      if request["login_candidates_unavailable"] as? Bool == true {
        alert.informativeText += "\n\n" + NativePresentation.tr("passkey.links.unavailable")
      }
      var labels = [NativePresentation.tr("passkey.links.none")]
      let logins = request["login_candidates"] as? [[String: Any]] ?? []
      for (index, login) in logins.enumerated() {
        guard let loginId = login["id"] as? String, !loginId.isEmpty else { continue }
        let label = passkeyAccountLabel(login["username"] as? String ?? "", login["title"] as? String ?? "")
        let site = passkeyAccountLabel(login["origin"] as? String ?? "", "")
        let partition = login["partition_name"] as? String ?? ""
        let prefix = partition.isEmpty ? "" : "[\(partition)] "
        labels.append("\(index + 1). \(prefix)\(label) · \(site)")
        accountIds.append(loginId)
      }
      // 直接显示可取消的单选列表，避免下拉菜单的跟踪循环挡住确认窗操作。
      let contentHeight = CGFloat(labels.count) * 32
      let listHeight = min(contentHeight, 192)
      let choices = NSView(frame: NSRect(x: 0, y: 0, width: 380, height: contentHeight))
      for (index, title) in labels.enumerated() {
        let button = NSButton(radioButtonWithTitle: title, target: self, action: #selector(selectPasskeyAccount(_:)))
        button.frame = NSRect(x: 0, y: contentHeight - CGFloat(index + 1) * 32, width: 360, height: 28)
        button.cell?.lineBreakMode = .byTruncatingTail
        button.toolTip = title
        button.tag = index
        button.state = index == 0 ? .on : .off
        choices.addSubview(button)
        accountButtons.append(button)
      }
      let scroll = NSScrollView(frame: NSRect(x: 0, y: 0, width: 380, height: listHeight))
      scroll.documentView = choices
      scroll.hasVerticalScroller = true
      scroll.autohidesScrollers = true
      scroll.drawsBackground = false
      scroll.contentView.scroll(to: NSPoint(x: 0, y: contentHeight - listHeight))
      scroll.reflectScrolledClipView(scroll.contentView)
      let accessory = NSView(frame: NSRect(x: 0, y: 0, width: 380, height: listHeight + 30))
      let label = NSTextField(labelWithString: NativePresentation.tr("passkey.links.label"))
      label.frame = NSRect(x: 0, y: listHeight + 8, width: 380, height: 20)
      accessory.addSubview(label)
      accessory.addSubview(scroll)
      alert.accessoryView = accessory
    } else {
      for (index, candidate) in candidates.enumerated() {
        let label = passkeyAccountLabel(candidate["username"] as? String ?? "", candidate["display_name"] as? String ?? "")
        let partition = candidate["partition_name"] as? String ?? ""
        let prefix = partition.isEmpty ? "" : "[\(partition)] "
        picker.addItem(withTitle: "\(index + 1). \(prefix)\(label)")
        picker.lastItem?.representedObject = candidate["credential_id"] as? String
      }
      alert.accessoryView = picker
    }
    alert.addButton(withTitle: NativePresentation.tr(create ? NativePresentation.tr("passkey.authorization.save") : NativePresentation.tr("passkey.authorization.login")))
    alert.addButton(withTitle: NativePresentation.tr("passkey.authorization.useBrowser"))
    alert.addButton(withTitle: NativePresentation.tr("common.cancel"))
    alert.buttons[1].keyEquivalent = ""
    alert.buttons.last?.keyEquivalent = "\u{1b}"
    // 取消、跳转、锁库后关闭失效确认窗；实际签名前 Agent 还会再次校验请求。
    let expiry = Timer(timeInterval: 0.5, repeats: true) { _ in
      guard let pending = LocalVaultUnlock.request(["type": "passkey_requests_pending", "status_only": true])?["request_ids"] as? [String],
            pending.contains(id) else {
        NSApp.abortModal()
        alert.window.orderOut(nil)
        return
      }
    }
    RunLoop.main.add(expiry, forMode: .modalPanel)
    NSApp.activate(ignoringOtherApps: true)
    let decision = alert.runModal()
    expiry.invalidate()
    let selected = create ? accountIds[accountButtons.first(where: { $0.state == .on })?.tag ?? 0]
      : (picker.selectedItem?.representedObject as? String ?? "")
    let complete: (Bool) -> Void = { [weak self] approved in
      let result = LocalVaultUnlock.request(["type": "passkey_resolve", "request_id": id,
        "approved": approved, "credential_id": create ? "" : selected,
        "linked_login_id": create ? selected : "", "use_browser": decision == .alertSecondButtonReturn])
      if approved && result?["resolved"] as? Bool == true { self?.channel.invokeMethod("onVaultChanged", arguments: nil) }
      self?.showingPasskeyAuthorization = false
    }
    guard decision == .alertFirstButtonReturn else { complete(false); return }
    // WebAuthn 的 UV 标志对应本次真实验证，不借用浏览器会话或敏感操作宽限期。
    TouchIdGate.shared.authenticateForExtensionGate(
      reason: NativePresentation.tr(create ? NativePresentation.tr("passkey.authorization.createReason") : NativePresentation.tr("passkey.authorization.loginReason")), completion: complete)
  }

  private func passkeyAccountLabel(_ username: String, _ displayName: String) -> String {
    // 网站提供的名称只作标签，移除控制/方向字符，避免伪造弹窗中的网站说明。
    let raw = displayName.isEmpty || displayName == username ? username : "\(username) · \(displayName)"
    let safe = raw.unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) &&
      ![0x061c, 0x200e, 0x200f, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069].contains(Int($0.value)) }
    return String(String.UnicodeScalarView(safe)).prefix(160).description
  }

  deinit {
    sshAuthorizationTimer?.invalidate()
    NotificationCenter.default.removeObserver(self)
  }

  @objc private func vaultLockedExternally() {
    DispatchQueue.main.async {
      CredPivotWebDAV.shared.cancel()
      self.channel.invokeMethod("onVaultLocked", arguments: nil)
    }
  }

  static func publishVaultLocked() {
    NotificationCenter.default.post(name: .credPivotVaultLocked, object: nil)
  }

  private func agentIsUnlocked() -> Bool {
    let resp = credpivotAgentRequestJsonString(#"{"type":"status"}"#)
    return resp.contains("\"unlocked\":true")
  }

  private func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    switch call.method {
    case "componentVersions":
      DispatchQueue.global(qos: .userInitiated).async {
        var info = ChromeHostInstaller.status()
        info["app_version"] = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? ""
        info["app_build"] = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? ""
        let snapshot = info
        DispatchQueue.main.async { result(snapshot) }
      }
    case "isMainWindowForeground":
      result(isMainWindowForeground && !TouchIdGate.isAuthenticating && NSApp.modalWindow == nil)
    case "syncHostInfo":
      DispatchQueue.global(qos: .userInitiated).async {
        let status = LocalVaultUnlock.request(["type": "status"]) ?? [:]
        let info = AppPreferences.syncHostInfo(vaultId: status["vault_id"] as? String ?? "")
        DispatchQueue.main.async { result(info) }
      }
    case "setSyncHostName":
      guard let value = call.arguments as? String,
            let status = LocalVaultUnlock.request(["type": "status"]),
            status["unlocked"] as? Bool == true,
            let vaultId = status["vault_id"] as? String else {
        result(FlutterError(code: "locked", message: NativePresentation.tr("common.unlockFirst"), details: nil))
        return
      }
      let name = value.trimmingCharacters(in: .whitespacesAndNewlines)
      guard name.unicodeScalars.count <= 128,
            name.rangeOfCharacter(from: .controlCharacters) == nil else {
        result(FlutterError(code: "bad_args", message: NativePresentation.tr("vault.syncHost.invalid"), details: nil))
        return
      }
      var names = AppPreferences.settings()["sync_host_names"] as? [String: String] ?? [:]
      if name.isEmpty { names.removeValue(forKey: vaultId) } else { names[vaultId] = name }
      guard AppPreferences.update(["sync_host_names": names]) else {
        result(FlutterError(code: "settings", message: NativePresentation.tr("vault.syncHost.saveFailed"), details: nil))
        return
      }
      result(nil)
    case "webdavBootstrapRead", "webdavSettings", "webdavSave", "webdavTest", "webdavRead", "webdavPublish", "webdavProbe", "webdavRemove", "webdavCleanup":
      Task { @MainActor in CredPivotWebDAV.shared.handle(call, result: result) }
    case "webdavCancel":
      Task { @MainActor in CredPivotWebDAV.shared.cancel(); result(nil) }
    case "webdavTestCancel":
      Task { @MainActor in CredPivotWebDAV.shared.cancel(reason:"sync.test.cancelled"); result(nil) }
    case "startAgent":
      let code = CredPivotRustFFI.start()
      if code == 0 { NativePresentation.reload(); shortcutController?.apply(AppPreferences.settings()) }
      result(code == 0 ? nil : FlutterError(code: "agent", message: "start failed", details: code))
    case "restartAgent":
      let code = CredPivotRustFFI.restart()
      if code == 0 { NativePresentation.reload(); shortcutController?.apply(AppPreferences.settings()) }
      result(code == 0)
    case "agentIsRunning":
      result(CredPivotRustFFI.isRunning())
    case "relaunchApp":
      AppRelauncher.relaunch()
      result(nil)
    case "recordShortcut":
      guard let args = call.arguments as? [String: Any],
            let name = args["name"] as? String,
            let bindings = args["bindings"] as? [String: String],
            ["search", "lock", "new"].contains(name), let controller = shortcutController else {
        result(FlutterError(code: "bad_args", message: NativePresentation.tr("native.handle.message"), details: nil))
        return
      }
      result(controller.record(name: name, bindings: bindings))
    case "agentRequest":
      guard let json = call.arguments as? String else {
        result(FlutterError(code: "bad_args", message: "expected json string", details: nil))
        return
      }
      var requestObject: [String: Any]?
      if let data = json.data(using: .utf8) {
        requestObject = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
      }
      let requestType = requestObject?["type"] as? String ?? ""
      if ["status", "sync_status", "app_settings_get", "browser_mfa_pending"].contains(requestType) {
        let notice = LocalVaultUnlock.setupNotice
        let backgroundLaunch = AppDelegate.launchedForBrowser
        DispatchQueue.global(qos: .userInitiated).async {
          var response = credpivotAgentRequestJsonString(json)
          if requestType == "status", let responseData = response.data(using: .utf8),
             var object = try? JSONSerialization.jsonObject(with: responseData) as? [String: Any],
             var payload = object["payload"] as? [String: Any] {
            payload["local_unlock_configured"] = LocalVaultUnlock.configured
            payload["local_unlock_notice"] = notice
            payload["browser_background_launch"] = backgroundLaunch
            for (key, value) in AppPreferences.syncHostInfo(vaultId: payload["vault_id"] as? String ?? "") {
              payload[key] = value
            }
            object["payload"] = payload
            if let data = try? JSONSerialization.data(withJSONObject: object),
               let updated = String(data: data, encoding: .utf8) { response = updated }
          }
          let reply = response
          DispatchQueue.main.async { result(reply) }
        }
        return
      }
      let previousSettings = requestObject?["type"] as? String == "app_settings_set" ? AppPreferences.settings() : nil
      var response = credpivotAgentRequestJsonString(json)
      if let data = json.data(using: .utf8),
         let request = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
         response.contains("\"type\":\"ok\"") {
        switch request["type"] as? String {
        case "vault_create", "vault_security_rebuild":
          Task { @MainActor in CredPivotWebDAV.shared.cancel(reason:"sync.errors.localControlChanged") }
          LocalVaultUnlock.enroll()
        case "vault_change_password", "vault_reset_recovery_key":
          Task { @MainActor in CredPivotWebDAV.shared.cancel(reason:"sync.errors.localChanged") }
          LocalVaultUnlock.enroll()
        case "vault_export_ovb", "vault_export_json": _ = LocalVaultUnlock.persist(enroll: false)
        case "vault_open_dir":
          LocalVaultUnlock.invalidate()
          Task { @MainActor in CredPivotWebDAV.shared.cancel() }
        case "sync_apply":
          if let data = response.data(using:.utf8),
             let object = try? JSONSerialization.jsonObject(with:data) as? [String:Any],
             let payload = object["payload"] as? [String:Any], payload["vault_switched"] as? Bool == true {
            LocalVaultUnlock.enroll()
          }
        case "app_settings_set":
          var notices: [String] = []
          let next = AppPreferences.settings()
          if previousSettings?["webdav"] is [String:Any], next["webdav"] is NSNull || next["webdav"] == nil {
            Task { @MainActor in try? CredPivotWebDAV.shared.forgetPasswords() }
          }
          NativePresentation.reload()
          shortcutController?.apply(next)
          // 显式保存时也重试应用系统偏好，避免上次注册失败后只能反复切换开关。
          if let notice = LoginItemRegistrar.applyPreference() { notices.append(notice) }
          if (previousSettings?["chrome_extension_id"] as? String) != (next["chrome_extension_id"] as? String) {
            let installation = ChromeHostInstaller.applyPreference()
            if installation["ok"] as? Bool != true {
              notices.append(NativePresentation.tr("native.handle.text"))
            } else {
              notices.append((next["chrome_extension_id"] as? String ?? "").isEmpty ? NativePresentation.tr("native.handle.text.item2") : NativePresentation.tr("native.handle.text.item3"))
            }
          }
          if let data = response.data(using: .utf8),
             var object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
             var payload = object["payload"] as? [String: Any] {
            payload["platform_notice"] = notices.joined(separator: "\n")
            object["payload"] = payload
            if let updated = try? JSONSerialization.data(withJSONObject: object),
               let text = String(data: updated, encoding: .utf8) { response = text }
          }
        default: break
        }
      }
      result(response)
    case "lockVault":
      TouchIdGate.invalidateInFlightAuthentication()
      _ = credpivotAgentRequestJsonString(#"{"type":"lock"}"#)
      CredPivotPlatform.publishVaultLocked()
      result(nil)
    case "unlockPassword":
      guard let password = call.arguments as? String else {
        result(false)
        return
      }
      result(LocalVaultUnlock.unlockPassword(password))
    case "authenticateTouchId":
      let reason = (call.arguments as? String) ?? NativePresentation.tr("agent.authenticateTouchId.reason")
      TouchIdGate.shared.authenticateSensitiveOperation(reason: reason) { ok in
        DispatchQueue.main.async {
          result(ok)
        }
      }
    case "unlockTouchId":
      LocalVaultUnlock.unlockBiometric { ok in result(ok) }
    case "registerLoginItem":
      let enabled = (call.arguments as? Bool) ?? true
      LoginItemRegistrar.setEnabled(enabled, result: result)
    case "loginItemStatus":
      result(LoginItemRegistrar.status())
    case "getChromeExtensionId":
      result(ChromeHostInstaller.storedExtensionId() ?? "")
    case "chromeHostStatus":
      result(ChromeHostInstaller.status())
    case "installChromeHost":
      let extId = call.arguments as? String
      result(ChromeHostInstaller.install(extensionId: extId))
    case "revealChromeExtensionDir":
      result(ChromeHostInstaller.revealExtensionDirectory())
    case "openChromeExtensionsPage":
      result(ChromeHostInstaller.openChromeExtensionsPage())
    case "sshIdentityAgentStatus":
      result(SshIdentityAgentHelper.status())
    case "gitSshStatus":
      DispatchQueue.global(qos: .userInitiated).async {
        let value = CredPivotGitSsh.status()
        DispatchQueue.main.async { result(value) }
      }
    case "prepareSshIdentityFile":
      guard let id = call.arguments as? String else { result(FlutterError(code: "bad_args", message: "SSH identity required", details: nil)); return }
      do { result(try CredPivotGitSsh.publicReference(id).path) }
      catch { result(FlutterError(code: "ssh", message: NativePresentation.tr("ssh.git.failed"), details: nil)) }
    case "gitSshConfigure":
      guard LocalVaultUnlock.request(["type": "sync_control_authorize"]) != nil else {
        result(FlutterError(code: "auth_required", message: NativePresentation.tr("common.unlockFirst"), details: nil)); return
      }
      let enabled = call.arguments as? Bool == true
      DispatchQueue.global(qos: .userInitiated).async {
        do {
          let value = try CredPivotGitSsh.configure(enabled: enabled)
          DispatchQueue.main.async { result(value) }
        } catch {
          DispatchQueue.main.async { result(FlutterError(code: "git_ssh", message: NativePresentation.tr("ssh.git.configureFailed"), details: nil)) }
        }
      }
    case "appendSshIdentityAgent":
      if !agentIsUnlocked() {
        result([
          "ok": false,
          "message": NativePresentation.tr("native.result.text"),
        ])
        return
      }
      result(SshIdentityAgentHelper.appendSnippet())
    case "removeSshIdentityAgent":
      result(SshIdentityAgentHelper.removeSnippet())
    case "residentMemoryBytes":
      result(ProcessMemory.residentBytes())
    case "pickDirectory":
      DispatchQueue.main.async {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        panel.prompt = NativePresentation.tr("native.result.text.item2")
        result(panel.runModal() == .OK ? panel.url?.path : nil)
      }
    case "pickOpenFile":
      DispatchQueue.main.async {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.allowedContentTypes = [.data]
        panel.prompt = NativePresentation.tr("native.result.text.item3")
        result(panel.runModal() == .OK ? panel.url?.path : nil)
      }
    case "pickSaveFile":
      let defaultName = (call.arguments as? String) ?? "backup.ovb"
      DispatchQueue.main.async {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = defaultName
        panel.allowedContentTypes = [.data]
        panel.prompt = NativePresentation.tr("common.save")
        result(panel.runModal() == .OK ? panel.url?.path : nil)
      }
    case "readTextFile":
      guard let path = call.arguments as? String else {
        result(FlutterError(code: "bad_args", message: "path required", details: nil))
        return
      }
      do {
        let url = URL(fileURLWithPath: path)
        guard try url.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile == true else {
          throw CocoaError(.fileReadUnknown)
        }
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        let data = try handle.read(upToCount: 4 * 1024 * 1024 + 1) ?? Data()
        guard data.count <= 4 * 1024 * 1024, let text = String(data: data, encoding: .utf8) else {
          throw CocoaError(.fileReadCorruptFile)
        }
        result(text)
      } catch {
        result(FlutterError(code: "io", message: NativePresentation.tr("native.result.message"), details: nil))
      }
    case "showMainWindow":
      NSApp.activate(ignoringOtherApps: true)
      NSApp.windows.first(where: { $0.contentViewController is FlutterViewController })?.makeKeyAndOrderFront(nil)
      result(nil)
    case "scanQrImage":
      let embeddedImage = (call.arguments as? [String: String])?["image"]
      DispatchQueue.main.async {
        let imageData: Data?
        let imageUrl: URL?
        if let embeddedImage = embeddedImage {
          guard embeddedImage.utf8.count <= 2 * 1024 * 1024,
                embeddedImage.hasPrefix("data:image/png;base64,") || embeddedImage.hasPrefix("data:image/jpeg;base64,"),
                let separator = embeddedImage.firstIndex(of: ","),
                let data = Data(base64Encoded: String(embeddedImage[embeddedImage.index(after: separator)...])) else {
            result(FlutterError(code: "qr", message: NativePresentation.tr("native.result.message.item2"), details: nil)); return
          }
          imageData = data; imageUrl = nil
        } else {
          let panel = NSOpenPanel()
          panel.allowedContentTypes = [.image]
          panel.allowsMultipleSelection = false
          guard panel.runModal() == .OK, let url = panel.url else { result([]); return }
          imageUrl = url; imageData = nil
        }
        DispatchQueue.global(qos: .userInitiated).async {
          do {
            let request = VNDetectBarcodesRequest()
            request.symbologies = [.qr]
            let handler = imageData.map { VNImageRequestHandler(data: $0, options: [:]) } ?? VNImageRequestHandler(url: imageUrl!)
            try handler.perform([request])
            let uris = (request.results ?? []).compactMap { $0.payloadStringValue }
              .filter { $0.lowercased().hasPrefix("otpauth://totp/") }
            DispatchQueue.main.async { result(uris) }
          } catch {
            DispatchQueue.main.async { result(FlutterError(code: "qr", message: NativePresentation.tr("native.result.message.item2"), details: nil)) }
          }
        }
      }
    case "writeTextFile":
      guard let args = call.arguments as? [String: String], let path = args["path"],
            let text = args["text"], let data = text.data(using: .utf8) else {
        result(FlutterError(code: "bad_args", message: "path and text required", details: nil)); return
      }
      // 明文私钥和语言文件均使用私有临时文件，原子替换，避免短暂的宽权限文件。
      let temporary = path + "." + UUID().uuidString + ".tmp"
      let fd = Darwin.open(temporary, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR)
      guard fd >= 0 else { result(FlutterError(code: "io", message: NativePresentation.tr("native.result.message.item3"), details: nil)); return }
      do {
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        try handle.write(contentsOf: data)
        try handle.synchronize()
        try handle.close()
        guard Darwin.rename(temporary, path) == 0 else { throw CocoaError(.fileWriteUnknown) }
        result(nil)
      } catch {
        try? FileManager.default.removeItem(atPath: temporary)
        result(FlutterError(code: "io", message: NativePresentation.tr("native.result.message.item4"), details: nil))
      }
    case "copyConcealed":
      guard let args = call.arguments as? [String: Any],
            let secret = args["secret"] as? String,
            let expected = args["vault_lock_generation"] as? NSNumber else {
        result(FlutterError(code: "bad_args", message: "secret and vault session required", details: nil))
        return
      }
      let seconds = (AppPreferences.settings()["clipboard_clear_seconds"] as? NSNumber)?.doubleValue ?? 5
      // 在实际写剪贴板的主线程同步校验，不能只依赖 Flutter 已关闭旧弹窗。
      guard let status = LocalVaultUnlock.request(["type": "status"]),
            status["unlocked"] as? Bool == true else {
        result(FlutterError(code: "locked", message: NativePresentation.tr("common.unlockFirst"), details: nil)); return
      }
      guard let generation = status["vault_lock_generation"] as? NSNumber,
            generation.uint64Value == expected.uint64Value else {
        result(FlutterError(code: "clipboard_session_changed", message: NativePresentation.tr("common.operationFailed"), details: nil)); return
      }
      ConcealedPasteboard.copyConcealed(secret, clearAfterSeconds: seconds)
      result(nil)
    case "getTerminalPreference":
      result(TerminalLauncher.preferencePayload())
    case "setTerminalLaunchConfig":
      guard let args = call.arguments as? [String: Any] else {
        result(FlutterError(code: "bad_args", message: "map required", details: nil))
        return
      }
      result(TerminalLauncher.applyLaunchConfig(args) ? nil : FlutterError(code: "settings_write", message: NativePresentation.tr("native.result.message.item5"), details: nil))
    case "pickTerminalApplication":
      if let picked = TerminalLauncher.pickApplication() {
        result(picked)
      } else {
        result(nil)
      }
    case "setTerminalPreference":
      guard let id = call.arguments as? String else {
        result(FlutterError(code: "bad_args", message: "terminal id required", details: nil))
        return
      }
      TerminalLauncher.setLegacyPreset(id)
      result(nil)
    case "openSshInTerminal":
      guard let args = call.arguments as? [String: Any],
            let host = args["host"] as? String,
            let username = args["username"] as? String else {
        result(FlutterError(code: "bad_args", message: "host/username required", details: nil))
        return
      }
      let port = args["port"] as? Int ?? 22
      if let err = TerminalLauncher.openSsh(host: host, port: port, user: username, identityFile: args["identityFile"] as? String) {
        result(err)
      } else {
        result(nil)
      }
    case "materializeSshAskpass":
      do {
        let path = try SshAskpassLauncher.materializeInstalledBinary()
        result(path)
      } catch {
        result(FlutterError(code: "ssh_askpass", message: error.localizedDescription, details: nil))
      }
    case "openSshWithAskpass":
      guard let args = call.arguments as? [String: Any],
            let host = args["host"] as? String,
            let username = args["username"] as? String,
            let sessionId = args["sessionId"] as? String else {
        result(FlutterError(code: "bad_args", message: "host/username/sessionId required", details: nil))
        return
      }
      let port = args["port"] as? Int ?? 22
      if let err = SshAskpassLauncher.openInTerminal(
        host: host,
        port: port,
        user: username,
        sessionId: sessionId
      ) {
        result(err)
      } else {
        result(nil)
      }
    default:
      result(FlutterMethodNotImplemented)
    }
  }

}

// MARK: - Chrome 扩展指纹门槛

enum ExtensionGateCoordinator {
  private static var started = false
  private static var pending = false
  private static var handledRequest: String?
  private static var pendingContents: String?
  private static var pendingEpoch: UInt64?
  private static var notificationToken: Int32 = 0
  private static var activity: NSObjectProtocol?
  private static var pendingStartedAt: TimeInterval = 0

  static func start() {
    guard !started else { return }
    started = true
    NotificationCenter.default.addObserver(
      forName: NSApplication.didBecomeActiveNotification,
      object: nil,
      queue: .main
    ) { _ in
      consumePendingIfNeeded()
    }
    _ = notify_register_dispatch("com.credpivot.browser-verification", &notificationToken, .main) { _ in
      consumePendingIfNeeded()
    }
    let timer = Timer(timeInterval: 1.0, repeats: true) { _ in
      consumePendingIfNeeded()
    }
    RunLoop.main.add(timer, forMode: .common)
    RunLoop.main.add(timer, forMode: .modalPanel)
    consumePendingIfNeeded()
  }

  private static var pendingPath: URL {
    FileManager.default.homeDirectoryForCurrentUser
      .appendingPathComponent(".credpivot/extension_gate.pending")
  }

  private static func consumePendingIfNeeded() {
    let contents = try? String(contentsOf: pendingPath, encoding: .utf8)
    if pending {
      // 网页面板撤销了当前请求时，取消对应的系统弹窗；不能误取消其他 App 操作的验证。
      if contents != pendingContents || (pendingEpoch != nil && !TouchIdGate.isAuthenticating) {
        let epoch = pendingEpoch
        let obsoleteRequest = handledRequest
        CredPivotRustFFI.logBrowserAuth(6, since: pendingStartedAt)
        finishPending()
        if epoch == TouchIdGate.authenticationEpoch { TouchIdGate.invalidateInFlightAuthentication() }
        if let requestId = obsoleteRequest { cancelRequest(requestId) }
      } else {
        return
      }
    }
    guard let contents = contents, let data = contents.data(using: .utf8),
          let request = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
          let session = request["session_id"] as? String, UUID(uuidString: session) != nil,
          let requestId = request["request_id"] as? String, UUID(uuidString: requestId) != nil,
          requestId != handledRequest else { return }
    let age = Date().timeIntervalSince1970 * 1000 - ((request["created_ms"] as? NSNumber)?.doubleValue ?? 0)
    let startedAt = ProcessInfo.processInfo.systemUptime
    CredPivotRustFFI.logBrowserAuth(1, since: startedAt)
    // 已有验证/模态窗口时直接结束本次请求，不排队到用户忘记此次点击后再突然弹出。
    if TouchIdGate.isAuthenticating || NSApp.modalWindow != nil || age < 0 || age > 15_000 {
      handledRequest = requestId
      CredPivotRustFFI.logBrowserAuth(7, since: startedAt)
      cancelRequest(requestId)
      return
    }
    // 即使清理标记失败，同一请求也只提示一次。手动重试会携带新的请求标识，无需冷却等待。
    handledRequest = requestId
    pendingContents = contents
    pending = true
    pendingStartedAt = startedAt
    activity = ProcessInfo.processInfo.beginActivity(options: .userInitiatedAllowingIdleSystemSleep,
                                                     reason: "CredPivot browser verification")
    // 状态预检可能等待 Agent 锁，不能占用展示弹窗、处理取消回调的主线程。
    DispatchQueue.global(qos: .userInitiated).async {
      let status = LocalVaultUnlock.request(["type": "status"])
      DispatchQueue.main.async {
        guard pendingContents == contents else { return }
        CredPivotRustFFI.logBrowserAuth(2, since: startedAt)
        let currentAge = Date().timeIntervalSince1970 * 1000 - ((request["created_ms"] as? NSNumber)?.doubleValue ?? 0)
        guard let status = status, !TouchIdGate.isAuthenticating, NSApp.modalWindow == nil,
              currentAge >= 0, currentAge <= 15_000,
              (try? String(contentsOf: pendingPath, encoding: .utf8)) == contents else {
          CredPivotRustFFI.logBrowserAuth(7, since: startedAt)
          finishPending(); cancelRequest(requestId)
          return
        }
        // LocalAuthentication 自行展示系统弹窗，不激活 App，避免打断 Chrome。
        TouchIdGate.shared.authenticateForExtensionGate(reason: NativePresentation.tr("browser.authorization.reason"), preparedStatus: status) { ok in
          // 旧系统弹窗的迟到回调不能清除新请求的在途状态。
          guard pendingContents == contents else { return }
          CredPivotRustFFI.logBrowserAuth(ok ? 4 : 5, since: startedAt)
          finishPending()
          // 授权提交和清理也不能阻塞下一次手动验证；Agent 会核对独立请求标识。
          DispatchQueue.global(qos: .userInitiated).async {
            if ok {
              let granted = LocalVaultUnlock.request(["type": "extension_gate_grant", "session_id": session,
                                                      "request_id": requestId, "ttl_secs": 0]) != nil
              CredPivotRustFFI.logBrowserAuth(granted ? 8 : 9, since: startedAt)
            }
            _ = LocalVaultUnlock.request(["type": "extension_gate_cancel", "request_id": requestId])
          }
        }
        CredPivotRustFFI.logBrowserAuth(3, since: startedAt)
        if pendingContents == contents { pendingEpoch = TouchIdGate.authenticationEpoch }
      }
    }
  }

  private static func cancelRequest(_ requestId: String) {
    DispatchQueue.global(qos: .userInitiated).async {
      _ = LocalVaultUnlock.request(["type": "extension_gate_cancel", "request_id": requestId])
    }
  }

  private static func finishPending() {
    pending = false
    pendingEpoch = nil
    pendingContents = nil
    if let token = activity { ProcessInfo.processInfo.endActivity(token) }
    activity = nil
  }
}

// MARK: - 用户偏好统一由 Rust 校验和原子写入 settings.json

enum AppPreferences {
  static func syncHostInfo(vaultId: String) -> [String: String] {
    let localized = Host.current().localizedName?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    let raw = localized.isEmpty ? ProcessInfo.processInfo.hostName : localized
    let scalars = Array(raw.unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) }.prefix(128))
    let computer = String(String.UnicodeScalarView(scalars))
    let names = settings()["sync_host_names"] as? [String: String] ?? [:]
    let custom = names[vaultId] ?? ""
    return ["sync_host_name": custom.isEmpty ? computer : custom,
            "sync_host_name_override": custom, "computer_name": computer]
  }

  static func settings() -> [String: Any] {
    LocalVaultUnlock.request(["type": "app_settings_get"])?["settings"] as? [String: Any] ?? [:]
  }

  @discardableResult
  static func update(_ changes: [String: Any]) -> Bool {
    guard let payload = LocalVaultUnlock.request(["type": "app_settings_get"]),
          (payload["warning"] as? String ?? "").isEmpty,
          var current = payload["settings"] as? [String: Any] else { return false }
    current.merge(changes) { _, new in new }
    return LocalVaultUnlock.request(["type": "app_settings_set", "settings": current]) != nil
  }

}

// MARK: - 本机解锁（Secure Enclave + 登录钥匙串，不依赖共享钥匙串 entitlement）

enum LocalVaultUnlock {
  private static let service = "com.credpivot.macos.local-unlock.v1"
  private static let materialAccount = "encrypted-vmk"
  private static let policyAccount = "verification-policy"
  private(set) static var setupNotice = ""

  static func enroll() {
    if persist(enroll: true) {
      setupNotice = ""
    } else {
      _ = SecItemDelete(query(materialAccount) as CFDictionary)
      _ = SecItemDelete(query(policyAccount) as CFDictionary)
      setupNotice = NativePresentation.tr("native.enroll.text")
    }
  }

  static func request(_ body: [String: Any]) -> [String: Any]? {
    guard let data = try? JSONSerialization.data(withJSONObject: body),
          let json = String(data: data, encoding: .utf8),
          let response = credpivotAgentRequestJsonString(json).data(using: .utf8),
          let result = try? JSONSerialization.jsonObject(with: response) as? [String: Any],
          result["type"] as? String == "ok" else { return nil }
    return result["payload"] as? [String: Any]
  }

  private static func query(_ account: String) -> [String: Any] {
    // 临时签名不能假定具有 Data Protection Keychain 的访问组权限。
    // 登录钥匙串中只保存 Secure Enclave 加密材料，绝不保存主密码或明文 VMK。
    [kSecClass as String: kSecClassGenericPassword,
     kSecAttrService as String: service, kSecAttrAccount as String: account,
     kSecUseDataProtectionKeychain as String: false]
  }

  private static func read(_ account: String, allowPrompt: Bool = true) -> Data? {
    var q = query(account)
    q[kSecReturnData as String] = true
    q[kSecMatchLimit as String] = kSecMatchLimitOne
    if !allowPrompt {
      let context = LAContext()
      context.interactionNotAllowed = true
      q[kSecUseAuthenticationContext as String] = context
    }
    var item: CFTypeRef?
    guard SecItemCopyMatching(q as CFDictionary, &item) == errSecSuccess else { return nil }
    return item as? Data
  }

  private static func write(_ account: String, data: Data) -> Bool {
    let q = query(account)
    let status = SecItemUpdate(q as CFDictionary, [kSecValueData as String: data] as CFDictionary)
    if status == errSecSuccess { return true }
    guard status == errSecItemNotFound else { return false }
    var add = q
    add[kSecValueData as String] = data
    return SecItemAdd(add as CFDictionary, nil) == errSecSuccess
  }

  static var configured: Bool { read(materialAccount, allowPrompt: false) != nil }

  static func restorePolicy() {
    if request(["type": "status"])?["unlocked"] as? Bool == true { return }
    guard let data = read(policyAccount, allowPrompt: false),
          let policy = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return }
    _ = request(["type": "local_unlock_policy_set", "policy": policy])
  }

  static func invalidate() {
    _ = SecItemDelete(query(materialAccount) as CFDictionary)
    _ = SecItemDelete(query(policyAccount) as CFDictionary)
    _ = request(["type": "local_unlock_policy_set", "policy": ["binding": "", "last_master_ms": 0, "last_unlock_ms": 0]])
  }

  @discardableResult
  static func persist(enroll: Bool) -> Bool {
    guard let material = request(["type": "local_unlock_material"])?["material"] as? [String: Any],
          let policy = material["policy"] as? [String: Any],
          let binding = policy["binding"] as? String,
          let policyData = try? JSONSerialization.data(withJSONObject: policy) else { return false }
    if enroll {
      guard SecureEnclave.isAvailable,
            let encoded = material["vmk"] as? String,
            var vmk = Data(base64Encoded: encoded),
            let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                        [.privateKeyUsage, .biometryCurrentSet], nil) else { return false }
      defer { vmk.resetBytes(in: 0..<vmk.count) }
      do {
        // 临时 Secure Enclave 密钥的 dataRepresentation 是硬件封装数据，不是私钥。
        // 加密只用其公钥；解密必须由同一设备、同一指纹集合完成私钥运算。
        let enclave = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let secret = try ephemeral.sharedSecretFromKeyAgreement(with: enclave.publicKey)
        let aad = Data(binding.utf8)
        let key = secret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: aad,
                                                sharedInfo: Data("CredPivot local unlock v1".utf8), outputByteCount: 32)
        let sealed = try AES.GCM.seal(vmk, using: key, authenticating: aad)
        guard let combined = sealed.combined else { return false }
        let record: [String: Any] = ["enclave_key": enclave.dataRepresentation.base64EncodedString(),
                                    "ephemeral_public_key": ephemeral.publicKey.x963Representation.base64EncodedString(),
                                    "sealed_vmk": combined.base64EncodedString(), "binding": binding]
        let recordData = try JSONSerialization.data(withJSONObject: record)
        guard write(materialAccount, data: recordData) else { return false }
      } catch { return false }
    }
    return write(policyAccount, data: policyData)
  }

  static func unlockPassword(_ password: String) -> Bool {
    TouchIdGate.invalidateInFlightAuthentication()
    guard request(["type": "unlock_password", "password": password])?["unlocked"] as? Bool == true else { return false }
    enroll()
    return true
  }

  static func verifyPassword(_ password: String) -> Bool {
    TouchIdGate.invalidateInFlightAuthentication()
    let unlocked = request(["type": "status"])?["unlocked"] as? Bool == true
    if !unlocked { return unlockPassword(password) }
    guard request(["type": "verify_master_password", "password": password])?["verified"] as? Bool == true else { return false }
    enroll()
    return true
  }

  static func unlockBiometric(preparedStatus: [String: Any]? = nil, completion: @escaping (Bool) -> Void) {
    guard !TouchIdGate.isAuthenticating,
          (preparedStatus ?? request(["type": "status"]) ?? [:])["master_password_required"] as? Bool == false,
          let data = read(materialAccount),
          let record = try? JSONSerialization.jsonObject(with: data) as? [String: String],
          let binding = record["binding"],
          let policyData = read(policyAccount),
          let storedPolicy = try? JSONSerialization.jsonObject(with: policyData) as? [String: Any],
          storedPolicy["binding"] as? String == binding,
          let enclaveData = record["enclave_key"].flatMap({ Data(base64Encoded: $0) }),
          let publicData = record["ephemeral_public_key"].flatMap({ Data(base64Encoded: $0) }),
          let sealedData = record["sealed_vmk"].flatMap({ Data(base64Encoded: $0) }) else { completion(false); return }
    let context = LAContext()
    context.localizedReason = NativePresentation.tr("auth.biometric.unlockReason")
    context.localizedFallbackTitle = ""
    let epoch = TouchIdGate.beginAuthentication(context: context)
    DispatchQueue.global(qos: .userInitiated).async {
      let decrypted: Data?
      do {
        let enclave = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: enclaveData,
                                                                    authenticationContext: context)
        let publicKey = try P256.KeyAgreement.PublicKey(x963Representation: publicData)
        let secret = try enclave.sharedSecretFromKeyAgreement(with: publicKey)
        let aad = Data(binding.utf8)
        let key = secret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: aad,
                                                sharedInfo: Data("CredPivot local unlock v1".utf8), outputByteCount: 32)
        decrypted = try AES.GCM.open(AES.GCM.SealedBox(combined: sealedData), using: key, authenticating: aad)
      } catch { decrypted = nil }
      DispatchQueue.main.async {
        var vmk = decrypted
        defer { if let count = vmk?.count { vmk?.resetBytes(in: 0..<count) } }
        guard TouchIdGate.endAuthentication(epoch), let key = vmk else { completion(false); return }
        let material: [String: Any] = ["vmk": key.base64EncodedString(), "policy": storedPolicy]
        let ok = request(["type": "unlock_local", "material": material])?["unlocked"] as? Bool == true
        if ok { _ = persist(enroll: false) }
        completion(ok)
      }
    }
  }
}

final class TouchIdGate {
  static let shared = TouchIdGate()
  static var isAuthenticating = false
  private(set) static var authenticationEpoch: UInt64 = 0
  private static var activeContext: LAContext?

  static func invalidateInFlightAuthentication() {
    authenticationEpoch &+= 1
    activeContext?.invalidate()
    activeContext = nil
    isAuthenticating = false
  }

  static func beginAuthentication(context: LAContext? = nil) -> UInt64 {
    authenticationEpoch &+= 1
    activeContext?.invalidate()
    activeContext = context
    isAuthenticating = true
    return authenticationEpoch
  }

  static func endAuthentication(_ epoch: UInt64) -> Bool {
    guard epoch == authenticationEpoch else { return false }
    isAuthenticating = false
    activeContext = nil
    return true
  }

  private func askMasterPassword(reason: String, completion: @escaping (Bool) -> Void) {
    let epoch = TouchIdGate.beginAuthentication()
    NSApp.activate(ignoringOtherApps: true)
    let alert = NSAlert()
    alert.messageText = NativePresentation.tr("auth.masterPassword.title")
    alert.informativeText = reason
    let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 300, height: 24))
    field.placeholderString = NativePresentation.tr("auth.masterPassword.placeholder")
    alert.accessoryView = field
    alert.addButton(withTitle: NativePresentation.tr("auth.verify"))
    alert.addButton(withTitle: NativePresentation.tr("common.cancel"))
    alert.window.initialFirstResponder = field
    let accepted = alert.runModal() == .alertFirstButtonReturn
    defer { field.stringValue = "" }
    guard TouchIdGate.endAuthentication(epoch), accepted else { completion(false); return }
    completion(LocalVaultUnlock.verifyPassword(field.stringValue))
  }

  func authenticateForExtensionGate(reason: String, preparedStatus: [String: Any]? = nil, completion: @escaping (Bool) -> Void) {
    authenticate(reason: reason, allowReuse: false, preparedStatus: preparedStatus, completion: completion)
  }

  func authenticateSensitiveOperation(reason: String, completion: @escaping (Bool) -> Void) {
    authenticate(reason: reason, allowReuse: true, completion: completion)
  }

  private func authenticate(reason: String, allowReuse: Bool, preparedStatus: [String: Any]? = nil, completion: @escaping (Bool) -> Void) {
    let localizedReason = NativePresentation.tr(reason)
    guard !TouchIdGate.isAuthenticating else { completion(false); return }
    let status = preparedStatus ?? LocalVaultUnlock.request(["type": "status"]) ?? [:]
    if allowReuse && status["sensitive_auth_active"] as? Bool == true { completion(true); return }
    if status["master_password_required"] as? Bool != false {
      askMasterPassword(reason: localizedReason, completion: completion)
      return
    }
    if status["unlocked"] as? Bool != true {
      let context = LAContext()
      var error: NSError?
      if !LocalVaultUnlock.configured || !context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
        askMasterPassword(reason: localizedReason, completion: completion)
      } else {
        LocalVaultUnlock.unlockBiometric(preparedStatus: status, completion: completion)
      }
      return
    }
    let context = LAContext()
    context.localizedFallbackTitle = NativePresentation.tr("vault.actions.useMasterPassword")
    var error: NSError?
    guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
      askMasterPassword(reason: localizedReason, completion: completion)
      return
    }
    let epoch = TouchIdGate.beginAuthentication(context: context)
    context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: localizedReason) { success, error in
      DispatchQueue.main.async {
        if success && preparedStatus != nil {
          guard epoch == TouchIdGate.authenticationEpoch else { completion(false); return }
          DispatchQueue.global(qos: .userInitiated).async {
            let verified = LocalVaultUnlock.request(["type": "sensitive_auth_grant"])?["verified"] as? Bool == true
            DispatchQueue.main.async {
              guard TouchIdGate.endAuthentication(epoch) else { completion(false); return }
              completion(verified)
            }
          }
          return
        }
        guard TouchIdGate.endAuthentication(epoch) else { completion(false); return }
        if success {
          completion(LocalVaultUnlock.request(["type": "sensitive_auth_grant"])?["verified"] as? Bool == true)
        } else if let error = error as? LAError, error.code == .userFallback || error.code == .biometryLockout {
          self.askMasterPassword(reason: localizedReason, completion: completion)
        } else { completion(false) }
      }
    }
  }
}

enum LoginItemRegistrar {
  static func status() -> [String: Any] {
    if #available(macOS 13.0, *) {
      return ["supported": true, "enabled": SMAppService.mainApp.status == .enabled,
              "requires_approval": SMAppService.mainApp.status == .requiresApproval]
    }
    return ["supported": false, "enabled": false, "requires_approval": false]
  }

  /// JSON 保存用户意图，系统实际状态另行展示；注册失败不能伪装成已启用。
  static func applyPreference() -> String? {
    guard let desired = AppPreferences.settings()["launch_at_login"] as? Bool else { return nil }
    if #available(macOS 13.0, *) {
      let service = SMAppService.mainApp
      if desired && service.status == .requiresApproval { return NativePresentation.tr("native.applyPreference.text") }
      if desired && service.status == .enabled { return nil }
      if !desired && service.status != .enabled && service.status != .requiresApproval { return nil }
      do {
        if desired { try service.register() } else { try service.unregister() }
        if service.status == .requiresApproval { return NativePresentation.tr("native.applyPreference.text.item2") }
        return (service.status == .enabled) == desired ? nil : NativePresentation.tr("native.applyPreference.text.item3")
      } catch { return NativePresentation.tr("native.applyPreference.text.item4") }
    }
    return desired ? NativePresentation.tr("native.applyPreference.text.item5") : nil
  }

  static func setEnabled(_ enabled: Bool, result: @escaping FlutterResult) {
    guard AppPreferences.update(["launch_at_login": enabled]) else {
      result(FlutterError(code: "settings_write", message: NativePresentation.tr("native.setEnabled.message"), details: nil)); return
    }
    if let notice = applyPreference() { result(FlutterError(code: "login_item", message: notice, details: nil)) }
    else { result(nil) }
  }
}

enum ChromeHostInstaller {
  private static let hostName = "com.credpivot.chrome.m0"
  private static let credPivotDir: URL = {
    FileManager.default.homeDirectoryForCurrentUser
      .appendingPathComponent(".credpivot", isDirectory: true)
  }()
  // 按内容寻址安装：运行中的旧 Host 不会被原地覆盖，新连接读取新清单即可切换。
  private static var installedHostPath: URL {
    guard let bundled = Bundle.main.path(forResource: "credpivot-native-host", ofType: nil),
          let data = try? Data(contentsOf: URL(fileURLWithPath: bundled)) else {
      return credPivotDir.appendingPathComponent("credpivot-native-host")
    }
    let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    return credPivotDir.appendingPathComponent("native-host/\(digest)/credpivot-native-host")
  }
  private static let manifestURL: URL = {
    FileManager.default.homeDirectoryForCurrentUser
      .appendingPathComponent(
        "Library/Application Support/Google/Chrome/NativeMessagingHosts/\(hostName).json",
        isDirectory: false
      )
  }()

  static func status() -> [String: Any] {
    let stored = storedExtensionId() ?? ""
    let manifestId = manifestExtensionId()
    let bundledHost = resolveSourceHostBinary()
    var trustedHostConfigured = false
    var installedHostCurrent = false
    var installedHostDigest = ""
    if let bundledHost {
      if let trusted = getenv("CREDPIVOT_TRUSTED_NATIVE_HOST") {
        trustedHostConfigured = URL(fileURLWithPath: String(cString: trusted)).resolvingSymlinksInPath()
          == URL(fileURLWithPath: bundledHost).resolvingSymlinksInPath()
      }
      if let source = try? Data(contentsOf: URL(fileURLWithPath: bundledHost)),
         let installed = try? Data(contentsOf: installedHostPath) {
        installedHostCurrent = SHA256.hash(data: source) == SHA256.hash(data: installed)
        installedHostDigest = SHA256.hash(data: installed).map { String(format: "%02x", $0) }.joined()
      }
    }
    var out: [String: Any] = [
      "host_name": hostName,
      "manifest_path": manifestURL.path,
      "manifest_exists": FileManager.default.fileExists(atPath: manifestURL.path),
      "installed_host_path": installedHostPath.path,
      "installed_host_exists": FileManager.default.fileExists(atPath: installedHostPath.path),
      "trusted_host_configured": trustedHostConfigured,
      "installed_host_current": installedHostCurrent,
      "installed_host_sha256": installedHostDigest,
      "manifest_host_matches_installed": false,
      "stored_extension_id": stored,
      "manifest_extension_id": manifestId ?? "",
      "host_id_matches_manifest": !stored.isEmpty && manifestId == stored,
      "extension_dir_path": extensionDirectoryPath() ?? "",
      "extension_dir_exists": extensionDirectoryPath() != nil,
    ]
    if let data = try? Data(contentsOf: manifestURL),
       let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
      out["manifest_allowed_origins"] = json["allowed_origins"]
      out["manifest_host_binary"] = json["path"]
      out["manifest_host_matches_installed"] = (json["path"] as? String) == installedHostPath.path
    }
    return out
  }

  /// 供「加载已解压的扩展」使用；不固定扩展 ID，仅提供当前构建附带的目录。
  static func extensionDirectoryPath() -> String? {
    let manifestName = "manifest.json"
    if let bundled = Bundle.main.resourceURL?.appendingPathComponent("credpivot-chrome-extension", isDirectory: true) {
      if FileManager.default.fileExists(atPath: bundled.appendingPathComponent(manifestName).path) {
        // 开发者模式的 ID 与加载路径有关，固定目录避免 Debug/Release 切换改变扩展身份。
        let cached = credPivotDir.appendingPathComponent("chrome-extension", isDirectory: true)
        do {
          let files = try FileManager.default.contentsOfDirectory(at: bundled, includingPropertiesForKeys:[.isRegularFileKey, .isSymbolicLinkKey])
          try FileManager.default.createDirectory(at: cached, withIntermediateDirectories: true)
          // 先写脚本，最后写清单；每个文件原子替换，不留下先删除再复制的空窗。
          for file in files.sorted(by: { ($0.lastPathComponent == manifestName ? 1 : 0) < ($1.lastPathComponent == manifestName ? 1 : 0) }) {
            let values = try file.resourceValues(forKeys:[.isRegularFileKey, .isSymbolicLinkKey])
            guard values.isRegularFile == true, values.isSymbolicLink != true else { continue }
            let target = cached.appendingPathComponent(file.lastPathComponent)
            let data = try Data(contentsOf:file)
            if (try? Data(contentsOf:target)) != data { try data.write(to:target,options:.atomic) }
          }
          return cached.path
        } catch { return bundled.path }
      }
    }
    let cached = credPivotDir.appendingPathComponent("chrome-extension", isDirectory: true)
    if FileManager.default.fileExists(atPath: cached.appendingPathComponent(manifestName).path) {
      return cached.path
    }
    let pathFile = credPivotDir.appendingPathComponent("chrome_extension_dir.path")
    if let raw = try? String(contentsOf: pathFile, encoding: .utf8) {
      let p = raw.trimmingCharacters(in: .whitespacesAndNewlines)
      if FileManager.default.fileExists(atPath: URL(fileURLWithPath: p).appendingPathComponent(manifestName).path) {
        return p
      }
    }
    return nil
  }

  static func manifestExtensionId() -> String? {
    guard let data = try? Data(contentsOf: manifestURL),
          let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          let origins = json["allowed_origins"] as? [String],
          let first = origins.first
    else { return nil }
    return extensionIdFromOrigin(first)
  }

  private static func extensionIdFromOrigin(_ origin: String) -> String? {
    let prefix = "chrome-extension://"
    guard origin.hasPrefix(prefix) else { return nil }
    var s = String(origin.dropFirst(prefix.count))
    if s.hasSuffix("/") {
      s = String(s.dropLast())
    }
    return s.isEmpty ? nil : s
  }

  static func revealExtensionDirectory() -> [String: Any] {
    guard let path = extensionDirectoryPath() else {
      return [
        "ok": false,
        "message": NativePresentation.tr("native.revealExtensionDirectory.text"),
      ]
    }
    NSWorkspace.shared.selectFile(
      URL(fileURLWithPath: path).appendingPathComponent("manifest.json").path,
      inFileViewerRootedAtPath: path
    )
    return ["ok": true, "message": NativePresentation.tr("native.revealExtensionDirectory.text.item2"), "path": path]
  }

  static func openChromeExtensionsPage() -> [String: Any] {
    guard let url = URL(string: "chrome://extensions") else {
      return ["ok": false, "message": NativePresentation.tr("native.openChromeExtensionsPage.text")]
    }
    NSWorkspace.shared.open(url)
    return [
      "ok": true,
      "message": NativePresentation.tr("native.openChromeExtensionsPage.text.item2"),
    ]
  }

  private static func resolveSourceHostBinary() -> String? {
    // 校验基准必须来自当前 App，不能把待校验的安装副本作为可信源。
    if let bundled = Bundle.main.path(forResource: "credpivot-native-host", ofType: nil) {
      return bundled
    }
    return nil
  }

  private static func materializeHostBinary() throws -> String {
    guard let src = resolveSourceHostBinary() else {
      throw NSError(
        domain: "CredPivot",
        code: 1,
        userInfo: [NSLocalizedDescriptionKey: NativePresentation.tr("native.materializeHostBinary.text")]
      )
    }
    let source = try Data(contentsOf: URL(fileURLWithPath: src))
    let directory = installedHostPath.deletingLastPathComponent()
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    if (try? Data(contentsOf: installedHostPath)) != source {
      let staged = directory.appendingPathComponent(UUID().uuidString + ".tmp")
      defer { try? FileManager.default.removeItem(at: staged) }
      try source.write(to: staged, options: .atomic)
      try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: staged.path)
      guard Darwin.rename(staged.path, installedHostPath.path) == 0 else { throw CocoaError(.fileWriteUnknown) }
    }
    // 冷启动绑定实际安装的 App 路径，避免 Launch Services 在 Debug/Release 同 Bundle ID 中任选。
    try Bundle.main.bundleURL.path.write(to: credPivotDir.appendingPathComponent("native_host_app.path"), atomically: true, encoding: .utf8)
    try writeNativeHostDigest(sourcePath: src)
    return installedHostPath.path
  }

  private static func writeNativeHostDigest(sourcePath: String) throws {
    let data = try Data(contentsOf: URL(fileURLWithPath: sourcePath))
    let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    let out = credPivotDir.appendingPathComponent("native_host.sha256")
    try digest.write(to: out, atomically: true, encoding: .utf8)
  }

  static func storedExtensionId() -> String? {
    guard let raw = AppPreferences.settings()["chrome_extension_id"] as? String else { return nil }
    let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
    return trimmed.isEmpty ? nil : trimmed
  }

  private static func normalizeExtensionId(_ input: String) -> String {
    var s = input.trimmingCharacters(in: .whitespacesAndNewlines)
    if s.hasPrefix("chrome-extension://") {
      s = String(s.dropFirst("chrome-extension://".count))
    }
    if s.hasSuffix("/") {
      s = String(s.dropLast())
    }
    return s
  }

  /// Agent 使用 App 包内原件校验 Chrome 启动的安装副本。
  static func applyTrustedNativeHostEnv() {
    guard let bundled = Bundle.main.path(forResource: "credpivot-native-host", ofType: nil),
          !bundled.isEmpty else {
      return
    }
    setenv("CREDPIVOT_TRUSTED_NATIVE_HOST", bundled, 1)
  }

  static func install(extensionId: String?) -> [String: Any] {
    let candidate = extensionId ?? storedExtensionId() ?? ""
    let extId = normalizeExtensionId(candidate)
    if extId.range(of: "^[a-p]{32}$", options: .regularExpression) == nil {
      return [
        "ok": false,
        "message": NativePresentation.tr("native.install.text"),
      ]
    }
    guard AppPreferences.update(["chrome_extension_id": extId]) else { return ["ok": false, "message": NativePresentation.tr("native.install.text.item2")] }

    do {
      let host = try materializeHostBinary()
      let manifest: [String: Any] = [
        "name": hostName,
        "description": "CredPivot Native Messaging Host",
        "path": host,
        "type": "stdio",
        "allowed_origins": ["chrome-extension://\(extId)/"],
      ]
      let dir = manifestURL.deletingLastPathComponent()
      try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
      let data = try JSONSerialization.data(withJSONObject: manifest, options: [.prettyPrinted])
      try data.write(to: manifestURL, options: .atomic)
      applyTrustedNativeHostEnv()
      return [
        "ok": true,
        "message": NativePresentation.tr("native.install.text.item3"),
        "manifest_path": manifestURL.path,
        "extension_id": extId,
        "host_binary": host,
      ]
    } catch {
      return ["ok": false, "message": error.localizedDescription]
    }
  }

  /// 设置里还没有扩展 ID 时，只认升级前写在私有目录中的那一份。
  private static func legacyExtensionId() -> String? {
    let url = credPivotDir.appendingPathComponent("chrome_extension_id")
    guard let values = try? url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey]),
          values.isRegularFile == true, values.isSymbolicLink != true,
          let size = values.fileSize, size > 0, size <= 16384,
          let text = try? String(contentsOf: url, encoding: .utf8) else { return nil }
    let id = text.trimmingCharacters(in: .whitespacesAndNewlines)
    return id.range(of: "^[a-p]{32}$", options: .regularExpression) == nil ? nil : id
  }

  static func applyPreference() -> [String: Any] {
    // 启动新版 App 时同步固定目录，避免只更新 Native Host、插件文件仍停留在旧版本。
    _ = extensionDirectoryPath()
    let raw = AppPreferences.settings()["chrome_extension_id"]
    if let id = (raw as? String)?.trimmingCharacters(in: .whitespacesAndNewlines), !id.isEmpty {
      return install(extensionId: id)
    }
    // 没有这项设置时不能删掉现有连接；只有用户明确保存成空字符串才移除清单。
    if raw == nil || raw is NSNull {
      if let legacy = legacyExtensionId() { return install(extensionId: legacy) }
      return ["ok": true]
    }
    do {
      if FileManager.default.fileExists(atPath: manifestURL.path) { try FileManager.default.removeItem(at: manifestURL) }
      return ["ok": true]
    } catch { return ["ok": false, "message": NativePresentation.tr("native.applyPreference.text.item6")] }
  }
}

// Git 只接入 core.sshCommand；独立恢复 CLI 仍然单独分发。
enum CredPivotGitSsh {
  private static let lock = NSRecursiveLock()
  private static var directory: URL { FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".credpivot") }
  private static var record: URL { directory.appendingPathComponent("git-ssh-installation.json") }
  static func publicReference(_ id: String) throws -> URL {
    guard UUID(uuidString: id) != nil, LocalVaultUnlock.request(["type": "status"])?["unlocked"] as? Bool == true,
      let keys = LocalVaultUnlock.request(["type": "ssh_key_list"])?["items"] as? [[String: Any]],
      let publicKey = keys.first(where: { $0["id"] as? String == id })?["public_openssh"] as? String else { throw NSError(domain: "GitSSH", code: 7) }
    let folder = directory.appendingPathComponent("ssh-public", isDirectory: true)
    try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    let path = folder.appendingPathComponent(id + ".pub")
    try (publicKey + "\n").write(to: path, atomically: true, encoding: .utf8)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path.path)
    return path
  }
  private static func run(_ arguments: [String]) throws -> (Int32, String) {
    let task = Process(), output = Pipe()
    task.executableURL = URL(fileURLWithPath: "/usr/bin/git"); task.arguments = ["config", "--global"] + arguments
    task.standardOutput = output; task.standardError = FileHandle.nullDevice; task.standardInput = FileHandle.nullDevice
    try task.run()
    let data = output.fileHandleForReading.readDataToEndOfFile(); task.waitUntilExit()
    guard data.count < 65536, let text = String(data: data, encoding: .utf8) else { throw NSError(domain: "GitSSH", code: 1) }
    return (task.terminationStatus, text.trimmingCharacters(in: .newlines))
  }
  private static func current() throws -> String? {
    let (code, text) = try run(["--get", "core.sshCommand"])
    guard code == 0 || code == 1 else { throw NSError(domain: "GitSSH", code: 2) }
    return code == 0 ? text : nil
  }
  private static func saved() -> [String: Any]? {
    guard let data = try? Data(contentsOf: record) else { return nil }
    return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
  }
  static func status() -> [String: Any] {
    lock.lock(); defer { lock.unlock() }
    do {
      let value = try current(), stored = saved()
      let enabled = value != nil && value == (stored?["current"] as? String)
      return ["enabled": enabled, "current": value ?? "", "backup": stored == nil ? "" : record.path,
              "helper_available": Bundle.main.path(forResource: "credpivot-git-ssh", ofType: nil) != nil]
    } catch { return ["enabled": false, "error": NativePresentation.tr("ssh.git.configureFailed")] }
  }
  static func configure(enabled: Bool) throws -> [String: Any] {
    lock.lock(); defer { lock.unlock() }
    let actual = try current(), stored = saved()
    if !enabled {
      guard let stored = stored, actual == (stored["current"] as? String) else { throw NSError(domain: "GitSSH", code: 3) }
      let previous = stored["previous"] as? String
      let result = try run(previous.map { ["--replace-all", "core.sshCommand", $0] } ?? ["--unset-all", "core.sshCommand"])
      guard result.0 == 0 || (previous == nil && result.0 == 5) else { throw NSError(domain: "GitSSH", code: 4) }
      try FileManager.default.removeItem(at: record)
      return status()
    }
    guard let bundled = Bundle.main.url(forResource: "credpivot-git-ssh", withExtension: nil) else { throw NSError(domain: "GitSSH", code: 5) }
    let binary = try Data(contentsOf: bundled), digest = SHA256.hash(data: binary).map { String(format: "%02x", $0) }.joined()
    let destination = directory.appendingPathComponent("git-ssh/" + digest, isDirectory: true)
    try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    let helper = destination.appendingPathComponent("credpivot-git-ssh")
    if (try? Data(contentsOf: helper)) != binary { try binary.write(to: helper, options: .atomic) }
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: helper.path)
    let command = "'" + helper.path.replacingOccurrences(of: "'", with: "'\\''") + "'"
    let managed = actual != nil && actual == (stored?["current"] as? String)
    var next: [String: Any] = ["current": command, "helper": helper.path]
    if let previous = managed ? stored?["previous"] as? String : actual { next["previous"] = previous }
    let oldData = try? Data(contentsOf: record)
    try JSONSerialization.data(withJSONObject: next).write(to: record, options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: record.path)
    do {
      guard try run(["--replace-all", "core.sshCommand", command]).0 == 0 else { throw NSError(domain: "GitSSH", code: 6) }
    } catch {
      if let oldData = oldData { try? oldData.write(to: record, options: .atomic) } else { try? FileManager.default.removeItem(at: record) }
      throw error
    }
    try Bundle.main.bundleURL.path.write(to: directory.appendingPathComponent("git-ssh-app.path"), atomically: true, encoding: .utf8)
    return status()
  }
  static func refreshIfManaged() {
    lock.lock(); defer { lock.unlock() }
    if status()["enabled"] as? Bool == true { _ = try? configure(enabled: true) }
  }
}

enum SshIdentityAgentHelper {
  private static let markerStart = "# >>> CredPivot M0 IdentityAgent"
  private static let markerEnd = "# <<< CredPivot M0"

  static func status() -> [String: Any] {
    let config = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ssh/config")
    guard FileManager.default.fileExists(atPath: config.path) else {
      return ["ok": true, "configured": false]
    }
    do {
      let text = try String(contentsOf: config, encoding: .utf8)
      // 只识别本应用管理的片段，不将用户自己的 IdentityAgent 配置视为已接入。
      if let start = text.range(of: markerStart),
         text.range(of: markerEnd, range: start.upperBound..<text.endIndex) == nil {
        return ["ok": false, "message": NativePresentation.tr("native.status.text")]
      }
      return ["ok": true, "configured": text.contains(markerStart)]
    } catch {
      return ["ok": false, "message": NativePresentation.tr("native.status.text.item2")]
    }
  }

  /// 写入 ~/.ssh/config；返回给 Flutter 展示结果（M0 无静默成功）。
  static func appendSnippet() -> [String: Any] {
    let home = FileManager.default.homeDirectoryForCurrentUser
    let credDir = home.appendingPathComponent(".credpivot", isDirectory: true)
    try? FileManager.default.createDirectory(at: credDir, withIntermediateDirectories: true)
    let socket = credDir.appendingPathComponent("ssh.sock").path
    let block = """
\(markerStart)
Host *
  IdentityAgent \(socket)
\(markerEnd)
"""
    let sshDir = home.appendingPathComponent(".ssh", isDirectory: true)
    let config = sshDir.appendingPathComponent("config")

    do {
      try FileManager.default.createDirectory(at: sshDir, withIntermediateDirectories: true)
      var text = (try? String(contentsOf: config, encoding: .utf8)) ?? ""

      if text.contains(markerStart) {
        if text.contains("IdentityAgent") && !text.contains("    Host *") {
          return [
            "ok": true,
            "already": true,
            "message": NativePresentation.tr("native.appendSnippet.text"),
            "configPath": config.path,
            "socketPath": socket,
          ]
        }
        text = replaceCredPivotBlock(in: text, with: block)
      } else {
        if !text.isEmpty && !text.hasSuffix("\n") {
          text += "\n"
        }
        text += "\n" + block + "\n"
      }

      try text.write(to: config, atomically: true, encoding: .utf8)
      return [
        "ok": true,
        "already": false,
        "message": NativePresentation.tr("native.appendSnippet.text.item2"),
        "configPath": config.path,
        "socketPath": socket,
      ]
    } catch {
      return [
        "ok": false,
        "message": NativePresentation.tr("ssh.configuration.writeFailed", arguments: ["error": String(describing: error.localizedDescription)]),
        "configPath": config.path,
        "socketPath": socket,
      ]
    }
  }

  /// 从 ~/.ssh/config 移除 CredPivot 标记块（设计文档「一键撤销」）。
  static func removeSnippet() -> [String: Any] {
    let home = FileManager.default.homeDirectoryForCurrentUser
    let config = home.appendingPathComponent(".ssh/config")
    guard FileManager.default.fileExists(atPath: config.path) else {
      return [
        "ok": false,
        "message": NativePresentation.tr("native.removeSnippet.text"),
        "configPath": config.path,
      ]
    }
    do {
      var text = try String(contentsOf: config, encoding: .utf8)
      guard text.contains(markerStart) else {
        return [
          "ok": false,
          "message": NativePresentation.tr("native.removeSnippet.text.item2"),
          "configPath": config.path,
        ]
      }
      text = removeCredPivotBlock(from: text)
      try text.write(to: config, atomically: true, encoding: .utf8)
      return [
        "ok": true,
        "message": NativePresentation.tr("native.removeSnippet.text.item3"),
        "configPath": config.path,
      ]
    } catch {
      return [
        "ok": false,
        "message": NativePresentation.tr("ssh.configuration.removeFailed", arguments: ["error": String(describing: error.localizedDescription)]),
        "configPath": config.path,
      ]
    }
  }

  private static func replaceCredPivotBlock(in text: String, with block: String) -> String {
    guard let start = text.range(of: markerStart),
          let end = text.range(of: markerEnd) else {
      return text
    }
    let afterEnd = text[end.upperBound...]
    let before = text[..<start.lowerBound]
    return String(before) + block + "\n" + String(afterEnd)
  }

  private static func removeCredPivotBlock(from text: String) -> String {
    guard let start = text.range(of: markerStart),
          let end = text.range(of: markerEnd) else {
      return text
    }
    var before = String(text[..<start.lowerBound])
    var after = String(text[end.upperBound...])
    while before.hasSuffix("\n") && before.count > 1 {
      before.removeLast()
    }
    while after.hasPrefix("\n") {
      after.removeFirst()
    }
    if before.isEmpty {
      return after
    }
    if after.isEmpty {
      return before + "\n"
    }
    return before + "\n" + after
  }
}

enum AppRelauncher {
  static func relaunch() {
    let path = Bundle.main.bundlePath
    let task = Process()
    task.executableURL = URL(fileURLWithPath: "/usr/bin/open")
    task.arguments = ["-n", path]
    try? task.run()
    DispatchQueue.main.asyncAfter(deadline: .now() + 0.25) {
      NSApp.terminate(nil)
    }
  }
}

// MARK: - M2-11 剪贴板：ConcealedType + changeCount 清理

enum ConcealedPasteboard {
  private static let concealed = NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")
  private static var clearWorkItem: DispatchWorkItem?

  static func copyConcealed(_ secret: String, clearAfterSeconds: TimeInterval) {
    let pb = NSPasteboard.general
    let baseline = pb.changeCount
    pb.clearContents()
    pb.setString(secret, forType: .string)
    pb.setString("", forType: concealed)
    clearWorkItem?.cancel()
    let work = DispatchWorkItem {
      let current = NSPasteboard.general
      if current.changeCount == baseline + 1 || current.string(forType: .string) == secret {
        current.clearContents()
      }
    }
    clearWorkItem = work
    DispatchQueue.main.asyncAfter(deadline: .now() + clearAfterSeconds, execute: work)
  }
}

enum TerminalLauncher {
  /// 旧版自定义启动项，已不再使用。
  private static let legacyLaunchModeKey = "credpivot.terminal.launch_mode"
  private static let legacyLauncherPathKey = "credpivot.terminal.launcher_path"
  private static let legacyArgvTemplateKey = "credpivot.terminal.argv_template"
  private static let legacyCwdKey = "credpivot.terminal.cwd"

  private static let launchScriptName = "terminal_launch.sh"

  static func preferencePayload() -> [String: String] {
    clearLegacyLaunchExtras()
    if let path = currentAppPath(), !path.isEmpty {
      let name = FileManager.default.displayName(atPath: path)
      return ["path": path, "name": name]
    }
    return ["path": "", "name": ""]
  }

  static func applyLaunchConfig(_ map: [String: Any]) -> Bool {
    if let appPath = map["path"] as? String, !appPath.isEmpty {
      guard setAppPath(appPath) else { return false }
    }
    clearLegacyLaunchExtras()
    return true
  }

  private static func clearLegacyLaunchExtras() {
    UserDefaults.standard.removeObject(forKey: legacyLaunchModeKey)
    UserDefaults.standard.removeObject(forKey: legacyLauncherPathKey)
    UserDefaults.standard.removeObject(forKey: legacyArgvTemplateKey)
    UserDefaults.standard.removeObject(forKey: legacyCwdKey)
  }

  static func currentAppPath() -> String? {
    let path = AppPreferences.settings()["terminal_app_path"] as? String ?? ""
    return path.isEmpty ? nil : path
  }

  /// 旧版预设 id（terminal/iterm/warp），首次选择 .app 后不再使用。
  static func setLegacyPreset(_ id: String) {
    if id == "terminal" {
      setAppPath("/System/Applications/Utilities/Terminal.app")
    } else if id == "iterm" {
      setAppPath("/Applications/iTerm.app")
    } else if id == "warp" {
      setAppPath("/Applications/Warp.app")
    }
  }

  @discardableResult
  static func setAppPath(_ path: String) -> Bool {
    return AppPreferences.update(["terminal_app_path": path])
  }

  static func pickApplication() -> [String: String]? {
    let panel = NSOpenPanel()
    panel.canChooseFiles = true
    panel.canChooseDirectories = false
    panel.allowsMultipleSelection = false
    panel.allowedContentTypes = [UTType.application]
    panel.message = NativePresentation.tr("native.pickApplication.message")
    panel.prompt = NativePresentation.tr("native.result.text.item2")
    guard panel.runModal() == .OK, let url = panel.url else {
      return nil
    }
    let path = url.path
    // 选择只修改页面草稿，用户点击保存后才写统一配置。
    return ["path": path, "name": url.deletingPathExtension().lastPathComponent]
  }

  private static var lastLaunchPlanURL: URL {
    FileManager.default.homeDirectoryForCurrentUser
      .appendingPathComponent(".credpivot/last_terminal_launch.txt", isDirectory: false)
  }

  /// 供用户核对：一键连接实际执行的启动方式（不含真实密码）。
  static func describeLaunchPlan(appPath: String, shellCommand: String) -> String {
    let scriptPath = launchScriptURL(sessionId: nil).path
    _ = writeLaunchScript(shellCommand: shellCommand)
    var lines: [String] = []
    lines.append(NativePresentation.tr("native.describeLaunchPlan.text"))
    lines.append("")
    lines.append(NativePresentation.tr("native.describeLaunchPlan.text.item2"))
    lines.append(shellCommand)
    lines.append("")
    if let cli = tabbyCliPath(appPath: appPath) ?? inferredTabbyCli(appPath: appPath) {
      lines.append("【2】Tabby CLI：")
      lines.append("\(cli) run /bin/zsh \(scriptPath)")
    } else {
      lines.append(NativePresentation.tr("native.describeLaunchPlan.text.item3"))
      lines.append("/usr/bin/open -na \(shellQuote(appPath)) --args /bin/zsh \(scriptPath)")
    }
    lines.append("")
    lines.append(NativePresentation.tr("native.describeLaunchPlan.text.item4"))
    lines.append(NativePresentation.tr("native.describeLaunchPlan.text.item5"))
    let text = lines.joined(separator: "\n")
    persistLaunchPlan(text)
    return text
  }

  private static func inferredTabbyCli(appPath: String) -> String? {
    let lower = appPath.lowercased()
    if lower.contains("tabby") {
      return tabbyCliPath(appPath: appPath)
    }
    return nil
  }

  private static func persistLaunchPlan(_ text: String) {
    let dir = lastLaunchPlanURL.deletingLastPathComponent()
    try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    try? text.write(to: lastLaunchPlanURL, atomically: true, encoding: .utf8)
  }

  static func sshShellCommand(host: String, port: Int, user: String, identityFile: String? = nil) -> String {
    var args = ["ssh"]
    if let file = identityFile {
      args += ["-o", "IdentityAgent=" + FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".credpivot/ssh.sock").path,
        "-o", "IdentitiesOnly=yes", "-o", "ControlPath=none", "-i", file]
    }
    if port != 22 { args += ["-p", String(port)] }
    args.append("\(user)@\(host)")
    return args.map { shellQuote($0) }.joined(separator: " ")
  }

  /// 成功返回 nil；失败返回错误文案。
  static func openSsh(host: String, port: Int, user: String, identityFile: String? = nil) -> String? {
    guard let appPath = currentAppPath(), !appPath.isEmpty else {
      return NativePresentation.tr("native.openSsh.text")
    }
    if !FileManager.default.fileExists(atPath: appPath) {
      return NativePresentation.tr("native.openSsh.text.item2", arguments: ["appPath": String(describing: appPath)])
    }
    let sshCmd = sshShellCommand(host: host, port: port, user: user, identityFile: identityFile)
    if let err = launchShellCommand(appPath: appPath, command: sshCmd) {
      let plan = describeLaunchPlan(appPath: appPath, shellCommand: sshCmd)
      return "\(err)\n\n\(plan)"
    }
    return nil
  }

  /// 在指定终端里执行一条 shell 命令（expect / ssh 等）。
  static func launchShellCommand(
    appPath: String,
    command: String,
    launchSessionId: String? = nil
  ) -> String? {
    if !FileManager.default.fileExists(atPath: appPath) {
      return NativePresentation.tr("native.openSsh.text.item2", arguments: ["appPath": String(describing: appPath)])
    }
    let bundleId = Bundle(path: appPath)?.bundleIdentifier ?? ""
    let appFile = (appPath as NSString).lastPathComponent.lowercased()

    let err: String?
    switch bundleId {
    case "com.apple.Terminal":
      let script = "tell application \"Terminal\" to do script \"\(escapeAppleScript(command))\""
      err = runOsascript(script)
    case "com.googlecode.iterm2":
      let script =
        "tell application \"iTerm\" to create window with default profile command \"\(escapeAppleScript(command))\""
      err = runOsascript(script)
    case "dev.warp.Warp-Stable", "dev.warp.Warp":
      let enc = command.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? command
      let url = "warp://action/new_tab?command=\(enc)"
      NSWorkspace.shared.open(URL(string: url)!)
      err = nil
    default:
      if appFile.contains("tabby") || bundleId.lowercased().contains("tabby") || tabbyCliPath(appPath: appPath) != nil {
        err = launchTabbyShellCommand(
          appPath: appPath,
          command: command,
          launchSessionId: launchSessionId
        )
      } else if let script = writeLaunchScript(shellCommand: command, sessionId: launchSessionId) {
        err = runProcess(
          executable: "/usr/bin/open",
          arguments: ["-na", appPath, "--args", "/bin/zsh", script],
          waitForExit: false
        )
      } else {
        err = NativePresentation.tr("native.launchShellCommand.text")
      }
    }

    if err == nil {
      schedulePurgeTerminalLaunchScripts(sessionId: launchSessionId)
    }
    return err
  }

  private static func launchScriptURL(sessionId: String?) -> URL {
    let name = sessionId.map { "terminal_launch_\($0).sh" } ?? launchScriptName
    return FileManager.default.homeDirectoryForCurrentUser
      .appendingPathComponent(".credpivot", isDirectory: true)
      .appendingPathComponent(name)
  }

  private static var credPivotRuntimeDir: URL {
    FileManager.default.homeDirectoryForCurrentUser
      .appendingPathComponent(".credpivot", isDirectory: true)
  }

  private static func launchScriptContainsLegacySecrets(_ url: URL) -> Bool {
    guard let text = try? String(contentsOf: url, encoding: .utf8) else {
      return false
    }
    return text.contains("password-file")
      || text.contains("--password-file")
      || text.contains("--otp '")
      || text.contains("--otp \"")
  }

  /// 旧版一键 SSH 会把密码/MFA 写进 `~/.credpivot/*.sh` 或诊断文件，启动时清掉。
  static func purgeLegacySensitiveLaunchScripts() {
    let dir = credPivotRuntimeDir
    guard let names = try? FileManager.default.contentsOfDirectory(atPath: dir.path) else {
      return
    }
    for name in names where name.hasSuffix(".sh") {
      let url = dir.appendingPathComponent(name)
      if launchScriptContainsLegacySecrets(url) {
        try? FileManager.default.removeItem(at: url)
      }
    }
    let diag = lastLaunchPlanURL
    if launchScriptContainsLegacySecrets(diag) {
      try? FileManager.default.removeItem(at: diag)
    }
  }

  /// 启动脚本仅用于 Tabby/open 拉起 zsh，读后无保留价值。
  static func purgeTerminalLaunchScripts() {
    let dir = credPivotRuntimeDir
    guard let names = try? FileManager.default.contentsOfDirectory(atPath: dir.path) else {
      return
    }
    for name in names {
      let isLaunchScript =
        name == launchScriptName
        || (name.hasPrefix("terminal_launch_") && name.hasSuffix(".sh"))
      if isLaunchScript {
        try? FileManager.default.removeItem(at: dir.appendingPathComponent(name))
      }
    }
    purgeLegacySensitiveLaunchScripts()
  }

  /// 终端进程启动后再删当次脚本，避免 Tabby/open 尚未 open(2) 文件。
  private static func schedulePurgeTerminalLaunchScripts(sessionId: String?) {
    DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 3) {
      if let sessionId {
        try? FileManager.default.removeItem(at: launchScriptURL(sessionId: sessionId))
      }
      purgeTerminalLaunchScripts()
    }
  }

  /// 将整条 shell 命令写入 `~/.credpivot/terminal_launch*.sh`，供 `zsh <path>` 执行。
  private static func writeLaunchScript(shellCommand: String, sessionId: String? = nil) -> String? {
    let url = launchScriptURL(sessionId: sessionId)
    let dir = url.deletingLastPathComponent()
    do {
      try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
      let body = "#!/bin/zsh\n\(shellCommand)\n"
      try body.write(to: url, atomically: true, encoding: .utf8)
      try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
      return url.path
    } catch {
      return nil
    }
  }

  /// Tabby：`run [command...]`；`-c` 后仅传脚本路径，避免长命令被拆成多个「脚本文件」参数。
  private static func launchTabbyShellCommand(
    appPath: String,
    command: String,
    launchSessionId: String? = nil
  ) -> String? {
    let cli = "\(appPath)/Contents/MacOS/Tabby"
    guard FileManager.default.fileExists(atPath: cli) else {
      return NativePresentation.tr("native.launchTabbyShellCommand.text", arguments: ["cli": String(describing: cli)])
    }
    guard let script = writeLaunchScript(shellCommand: command, sessionId: launchSessionId) else {
      return NativePresentation.tr("native.launchTabbyShellCommand.text.item2")
    }
    return runProcess(executable: cli, arguments: ["run", "/bin/zsh", script], waitForExit: false)
  }

  private static func tabbyCliPath(appPath: String) -> String? {
    let cli = "\(appPath)/Contents/MacOS/Tabby"
    return FileManager.default.fileExists(atPath: cli) ? cli : nil
  }

  /// expect 等：拼成一条 shell 命令后走统一启动逻辑。
  static func launchShellCommandLine(
    appPath: String,
    executable: String,
    arguments: [String],
    launchSessionId: String? = nil
  ) -> String? {
    let shellCmd = ([executable] + arguments).map { shellQuote($0) }.joined(separator: " ")
    return launchShellCommand(
      appPath: appPath,
      command: shellCmd,
      launchSessionId: launchSessionId
    )
  }

  private static func runProcess(
    executable: String,
    arguments: [String],
    waitForExit: Bool = true
  ) -> String? {
    let proc = Process()
    proc.executableURL = URL(fileURLWithPath: executable)
    proc.arguments = arguments
    do {
      try proc.run()
      if waitForExit {
        proc.waitUntilExit()
        if proc.terminationStatus != 0 {
          return NativePresentation.tr("terminal.errors.processExit", arguments: ["exitCode": String(describing: proc.terminationStatus)])
        }
      }
      return nil
    } catch {
      return error.localizedDescription
    }
  }

  private static func runOsascript(_ source: String) -> String? {
    let proc = Process()
    proc.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
    proc.arguments = ["-e", source]
    do {
      try proc.run()
      proc.waitUntilExit()
      if proc.terminationStatus != 0 {
        return NativePresentation.tr("terminal.errors.appleScriptExit", arguments: ["exitCode": String(describing: proc.terminationStatus)])
      }
      return nil
    } catch {
      return error.localizedDescription
    }
  }

  private static func shellQuote(_ s: String) -> String {
    "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
  }

  private static func escapeAppleScript(_ s: String) -> String {
    s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
  }
}

enum SshAskpassLauncher {
  private static let installedName = "credpivot-askpass"
  private static var credPivotDir: URL {
    FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".credpivot", isDirectory: true)
  }

  private static var installedURL: URL {
    credPivotDir.appendingPathComponent(installedName)
  }

  /// Agent 校验 askpass 副本时读取包内二进制路径。
  static func applyTrustedAskpassEnv() {
    guard let bundled = Bundle.main.path(forResource: installedName, ofType: nil),
          !bundled.isEmpty else {
      return
    }
    setenv("CREDPIVOT_TRUSTED_ASKPASS", bundled, 1)
  }

  private static func resolveSourceBinary() -> String? {
    if let bundled = Bundle.main.path(forResource: installedName, ofType: nil) {
      return bundled
    }
    let pathFile = credPivotDir.appendingPathComponent("askpass_binary.path")
    if let raw = try? String(contentsOf: pathFile, encoding: .utf8) {
      let p = raw.trimmingCharacters(in: .whitespacesAndNewlines)
      if FileManager.default.fileExists(atPath: p) {
        return p
      }
    }
    if FileManager.default.fileExists(atPath: installedURL.path) {
      return installedURL.path
    }
    return nil
  }

  /// 从 App 包复制到 ~/.credpivot/credpivot-askpass（与 native-host 相同策略）。
  static func materializeInstalledBinary() throws -> String {
    guard let src = resolveSourceBinary() else {
      throw NSError(
        domain: "CredPivot",
        code: 1,
        userInfo: [NSLocalizedDescriptionKey: NativePresentation.tr("native.materializeInstalledBinary.text")]
      )
    }
    try FileManager.default.createDirectory(at: credPivotDir, withIntermediateDirectories: true)
    if FileManager.default.fileExists(atPath: installedURL.path) {
      try FileManager.default.removeItem(at: installedURL)
    }
    try FileManager.default.copyItem(atPath: src, toPath: installedURL.path)
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: installedURL.path)
    try writeAskpassTrustArtifacts(sourcePath: src)
    return installedURL.path
  }

  private static func writeAskpassTrustArtifacts(sourcePath: String) throws {
    let data = try Data(contentsOf: URL(fileURLWithPath: sourcePath))
    let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    try digest.write(
      to: credPivotDir.appendingPathComponent("askpass.sha256"),
      atomically: true,
      encoding: .utf8
    )
    try sourcePath.write(
      to: credPivotDir.appendingPathComponent("askpass_trusted.path"),
      atomically: true,
      encoding: .utf8
    )
  }

  private static let expectScriptName = "ssh-expect-pass.exp"

  private static var expectScriptURL: URL {
    credPivotDir.appendingPathComponent(expectScriptName)
  }

  private static func resolveSourceExpectScript() -> String? {
    if let bundled = Bundle.main.path(forResource: "ssh-expect-pass", ofType: "exp") {
      return bundled
    }
    let pathFile = credPivotDir.appendingPathComponent("expect_script.source.path")
    if let raw = try? String(contentsOf: pathFile, encoding: .utf8) {
      let p = raw.trimmingCharacters(in: .whitespacesAndNewlines)
      if FileManager.default.fileExists(atPath: p) {
        return p
      }
    }
    if FileManager.default.fileExists(atPath: expectScriptURL.path) {
      return expectScriptURL.path
    }
    return nil
  }

  /// 每次从 App 包（或开发期源路径）覆盖 `~/.credpivot/ssh-expect-pass.exp`。
  static func materializeExpectScript() throws -> String {
    guard let src = resolveSourceExpectScript() else {
      throw NSError(
        domain: "CredPivot",
        code: 2,
        userInfo: [NSLocalizedDescriptionKey: NativePresentation.tr("native.materializeExpectScript.text")]
      )
    }
    let srcData = try Data(contentsOf: URL(fileURLWithPath: src))
    let srcText = String(data: srcData, encoding: .utf8) ?? ""
    if !srcText.contains("credpivot-expect-version: 2") {
      throw NSError(
        domain: "CredPivot",
        code: 3,
        userInfo: [NSLocalizedDescriptionKey: NativePresentation.tr("native.materializeExpectScript.text.item2")]
      )
    }
    try FileManager.default.createDirectory(at: credPivotDir, withIntermediateDirectories: true)
    let dst = expectScriptURL
    if FileManager.default.fileExists(atPath: dst.path) {
      try FileManager.default.removeItem(at: dst)
    }
    try FileManager.default.copyItem(atPath: src, toPath: dst.path)
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: dst.path)
    return dst.path
  }

  /// 一键连接：PTY + expect 处理 keyboard-interactive MFA；密码/OTP 经 askpass 向 Agent 领取。
  static func openInTerminal(
    host: String,
    port: Int,
    user: String,
    sessionId: String
  ) -> String? {
    let askpassPath: String
    let expectPath: String
    do {
      askpassPath = try materializeInstalledBinary()
      expectPath = try materializeExpectScript()
    } catch {
      return error.localizedDescription
    }
    if !FileManager.default.fileExists(atPath: "/usr/bin/expect") {
      return NativePresentation.tr("native.openInTerminal.text")
    }
    guard let appPath = TerminalLauncher.currentAppPath(), !appPath.isEmpty else {
      return NativePresentation.tr("native.openInTerminal.text.item2")
    }
    var args = [
      expectPath,
      "--user", user,
      "--host", host,
      "--session-id", sessionId,
      "--askpass", askpassPath,
    ]
    if port != 22 {
      args.append(contentsOf: ["--port", String(port)])
    }
    if let err = TerminalLauncher.launchShellCommandLine(
      appPath: appPath,
      executable: "/usr/bin/expect",
      arguments: args,
      launchSessionId: sessionId
    ) {
      let shellCmd = (["/usr/bin/expect"] + args).map { TerminalLauncher.shellQuoteForPlan($0) }.joined(separator: " ")
      let plan = TerminalLauncher.describeLaunchPlan(appPath: appPath, shellCommand: shellCmd)
      return "\(err)\n\n\(plan)"
    }
    return nil
  }
}

extension TerminalLauncher {
  fileprivate static func shellQuoteForPlan(_ s: String) -> String {
    "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
  }
}

// 只监听主窗口事件，不注册系统全局热键；原生录入期间暂停业务快捷键。
final class CredPivotShortcuts {
  private var localMonitor: Any?
  private var localBindings: [String: (UInt16, NSEvent.ModifierFlags)] = [:]
  private var recording = false
  private let action: (String) -> Void
  private let keys: [String: UInt16] = ["a":0,"s":1,"d":2,"f":3,"h":4,"g":5,"z":6,"x":7,"c":8,"v":9,"b":11,"q":12,"w":13,"e":14,"r":15,"y":16,"t":17,"1":18,"2":19,"3":20,"4":21,"6":22,"5":23,"9":25,"7":26,"8":28,"0":29,"o":31,"u":32,"i":34,"p":35,"l":37,"j":38,"k":40,"n":45,"m":46,"space":49]
  private let modifiers: NSEvent.ModifierFlags = [.command, .control, .option, .shift]
  private let labels = ["search": "shortcuts.actions.search", "lock": "vault.actions.lock", "new": "credentials.actions.new"]
  private let reserved = ["command+c", "command+v", "command+x", "command+a", "command+z", "command+shift+z", "command+w", "command+q", "command+h", "command+m"]

  init(action: @escaping (String) -> Void) {
    self.action = action
    localMonitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { [weak self] event in
      guard let self = self, !self.recording, NSApp.modalWindow == nil,
            let window = (NSApp.delegate as? AppDelegate)?.mainFlutterWindow,
            NSApp.isActive, event.window === window, window.isKeyWindow else { return event }
      let flags = event.modifierFlags.intersection(self.modifiers)
      for (name, binding) in self.localBindings where binding.0 == event.keyCode && binding.1 == flags {
        if !event.isARepeat { self.action(name) }
        return nil
      }
      return event
    }
  }

  private func parse(_ text: String) -> (UInt16, NSEvent.ModifierFlags)? {
    let parts = text.split(separator: "+").map(String.init)
    guard let last = parts.last, let key = keys[last], (2...5).contains(parts.count) else { return nil }
    var flags: NSEvent.ModifierFlags = []
    for part in parts.dropLast() {
      switch part {
      case "command": flags.insert(.command)
      case "control": flags.insert(.control)
      case "option": flags.insert(.option)
      case "shift": flags.insert(.shift)
      default: return nil
      }
    }
    guard flags.contains(.command) || flags.contains(.control) else { return nil }
    return (key, flags)
  }

  func apply(_ settings: [String: Any]) {
    localBindings.removeAll()
    for name in ["search", "lock", "new"] {
      if let text = settings["shortcut_" + name] as? String, let binding = parse(text) {
        localBindings[name] = binding
      }
    }
  }

  func record(name: String, bindings: [String: String]) -> String? {
    guard !recording, NSApp.modalWindow == nil else { return nil }
    recording = true
    defer { recording = false }
    let alert = NSAlert()
    alert.messageText = NativePresentation.tr("shortcuts.recorder.title", arguments: ["action": NativePresentation.tr(labels[name] ?? name)])
    alert.informativeText = NativePresentation.tr("native.record.text.item2")
    let preview = NSTextField(wrappingLabelWithString: NativePresentation.tr("native.record.text.item3"))
    preview.frame = NSRect(x: 0, y: 0, width: 380, height: 60)
    alert.accessoryView = preview
    alert.addButton(withTitle: NativePresentation.tr("native.record.text.item4"))
    alert.addButton(withTitle: NativePresentation.tr("common.cancel"))
    alert.buttons.first?.isEnabled = false
    var chosen: String?
    let monitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { [weak self] event in
      guard let self = self, event.window === alert.window else { return event }
      let flags = event.modifierFlags.intersection(self.modifiers)
      if event.keyCode == 53 && flags.isEmpty {
        NSApp.abortModal()
        alert.window.orderOut(nil)
        return nil
      }
      if event.keyCode == 36 && flags.isEmpty && chosen != nil { return event }
      if event.isARepeat { return nil }
      chosen = nil
      alert.buttons.first?.isEnabled = false
      guard let key = self.keys.first(where: { $0.value == event.keyCode })?.key,
            flags.contains(.command) || flags.contains(.control) else {
        preview.stringValue = NativePresentation.tr("native.record.text.item5")
        return nil
      }
      if self.reserved.contains(where: { self.parse($0).map { $0.0 == event.keyCode && $0.1 == flags } ?? false }) {
        preview.stringValue = NativePresentation.tr("native.record.text.item6")
        return nil
      }
      if let duplicate = bindings.first(where: { entry in
        entry.key != name && (self.parse(entry.value).map { $0.0 == event.keyCode && $0.1 == flags } ?? false)
      }) {
        preview.stringValue = NativePresentation.tr("shortcuts.recorder.duplicate", arguments: ["action": NativePresentation.tr(self.labels[duplicate.key] ?? duplicate.key)])
        return nil
      }
      var parts: [String] = []
      if flags.contains(.control) { parts.append("control") }
      if flags.contains(.option) { parts.append("option") }
      if flags.contains(.shift) { parts.append("shift") }
      if flags.contains(.command) { parts.append("command") }
      chosen = (parts + [key]).joined(separator: "+")
      preview.stringValue = (flags.contains(.control) ? "⌃" : "") + (flags.contains(.option) ? "⌥" : "") + (flags.contains(.shift) ? "⇧" : "") + (flags.contains(.command) ? "⌘" : "") + (key == "space" ? "Space" : key.uppercased())
      alert.buttons.first?.isEnabled = true
      return nil
    }
    defer { if let monitor = monitor { NSEvent.removeMonitor(monitor) } }
    return alert.runModal() == .alertFirstButtonReturn ? chosen : nil
  }

  deinit {
    if let localMonitor = localMonitor { NSEvent.removeMonitor(localMonitor) }
  }
}

// 与 Flutter 共用用户导入的 JSON 语言包；这里只处理 UI 文案，不读取保险库内容。
enum NativePresentation {
  private static let lock = NSLock()
  private static let tokenPattern = try! NSRegularExpression(pattern: "\\{([a-zA-Z][a-zA-Z0-9_]*)\\}")
  private static let reference: [String: [String: Any]] = {
    // Flutter 已把同一份内置目录打包进 App.framework，无须复制或另存默认文案。
    guard let root = Bundle.main.privateFrameworksURL,
          let data = try? Data(contentsOf: root.appendingPathComponent("App.framework/Resources/flutter_assets/assets/languages/zh-CN.json")),
          let pack = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          pack["format"] as? String == "credpivot-language", pack["version"] as? Int == 2,
          let messages = pack["messages"] as? [String: [String: Any]] else { return [:] }
    return messages
  }()
  private static var messages: [String: String] = reference.reduce(into: [:]) { result, entry in
    result[entry.key] = entry.value["source"] as? String
  }

  private static func parameters(_ template: String) -> Set<String> {
    let text = template as NSString
    return Set(tokenPattern.matches(in: template, range: NSRange(location: 0, length: text.length)).map { text.substring(with: $0.range(at: 1)) })
  }

  static func reload() {
    var updated: [String: String] = reference.reduce(into: [:]) { result, entry in result[entry.key] = entry.value["source"] as? String }
    // 终端操作可能在后台线程返回错误文案，不能与主线程切换语言并发读写字典。
    defer { lock.lock(); messages = updated; lock.unlock() }
    guard let locale = AppPreferences.settings()["language"] as? String, locale != "zh-CN",
          locale.range(of: "^[a-zA-Z0-9_-]{1,64}$", options: .regularExpression) != nil else { return }
    let path = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".credpivot/languages/\(locale).json")
    guard let handle = try? FileHandle(forReadingFrom: path) else { return }
    defer { try? handle.close() }
    guard let data = try? handle.read(upToCount: 4 * 1024 * 1024 + 1), data.count <= 4 * 1024 * 1024,
          let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          value["format"] as? String == "credpivot-language", value["version"] as? Int == 2,
          value["locale"] as? String == locale,
          let translated = value["messages"] as? [String: [String: Any]], translated.count <= 10000 else { return }
    var candidate = updated
    for (key, entry) in translated {
      // 版本下线的文案不能让整份语言包失效，原生界面继续使用其余译文。
      guard let source = reference[key]?["source"] as? String else { continue }
      guard let translation = entry["translation"] as? String, translation.count <= 8192 else { return }
      if translation.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { continue }
      guard parameters(source) == parameters(translation) else { return }
      candidate[key] = translation
    }
    updated = candidate
  }

  static func tr(_ key: String, arguments: [String: String] = [:]) -> String {
    lock.lock()
    let template = messages[key] ?? key
    lock.unlock()
    guard !arguments.isEmpty else { return template }
    let text = template as NSString
    var result = template
    // 按原始范围逆序替换，不递归展开参数中的花括号或用户数据。
    for match in tokenPattern.matches(in: template, range: NSRange(location: 0, length: text.length)).reversed() {
      let name = text.substring(with: match.range(at: 1))
      guard let value = arguments[name], let range = Range(match.range, in: result) else { continue }
      result.replaceSubrange(range, with: value)
    }
    return result
  }
}
