import Cocoa
import Vision
import Darwin
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
  private var cleanupReferences: [String: (etag: String, snapshot: String)] = [:]
  private var cleanupDeleteVerified = false
  private var cleanupRequests = 0

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
    let serverInput = args["server_url"] as? String ?? ""
    let input = serverInput.isEmpty ? args["root"] as? String ?? "" : serverInput
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
            "automatic":args["automatic"] as? Bool ?? true,"interval_seconds":interval]
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
  private func authorizePublish(_ config: [String: Any]) throws {
    guard let head = config["_publish_head"] as? [String: Any] else { return }
    let body = try JSONSerialization.data(withJSONObject:["type":"sync_publish_authorize","location":config["location"] ?? "","head":head])
    guard let text = String(data:body,encoding:.utf8),
          let data = credpivotAgentRequestJsonString(text).data(using:.utf8),
          let response = try JSONSerialization.jsonObject(with:data) as? [String:Any] else { throw WebDAVFailure("sync.errors.operation") }
    if response["type"] as? String == "ok" { return }
    if response["code"] as? String == "locked" { throw WebDAVFailure("sync.errors.locked") }
    let key = response["message"] as? String ?? ""
    guard ["sync.errors.localControlChanged","sync.errors.localChanged"].contains(key) else { throw WebDAVFailure("sync.errors.operation") }
    throw WebDAVFailure(key)
  }
  private func request(_ config: [String: Any], _ path: String, method: String = "GET", data: Data? = nil,
                       headers: [String: String] = [:], limit: Int = 64 * 1024 * 1024,
                       listingPage: URL? = nil) async throws -> WebDAVTransfer.Reply {
    guard unlocked() else { throw WebDAVFailure("sync.errors.locked") }
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
      guard unlocked() else { throw WebDAVFailure("sync.errors.locked") }
      guard currentGeneration == generation else { throw WebDAVFailure(cancellationKey) }
      throw error
    }
    guard unlocked() else { throw WebDAVFailure("sync.errors.locked") }
    guard currentGeneration == generation else { throw WebDAVFailure(cancellationKey) }
    try authorizePublish(config)
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
  private func probe(_ config: [String: Any], onCheck: (([String: Any]) -> Void)? = nil) async throws {
    let policy = WebDAVProviderPolicy(config)
    func checked(_ key: String, _ statuses: [Int] = [], passed: Bool = true, skipped: Bool = false) {
      onCheck?(["key":key,"passed":passed,"statuses":statuses,"skipped":skipped])
    }
    writeCapabilities = nil
    if let server = config["server_url"] as? String, !server.isEmpty,
       let root = config["root"] as? String {
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
    } else { try await directory(config,"") }
    checked("directory")
    let path = ".credpivot-probe-" + UUID().uuidString.lowercased()
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
      let deleted = try await request(config,path,method:"DELETE",limit:1024)
      guard [200,204,404].contains(deleted.response.statusCode) else { throw WebDAVFailure("sync.errors.probeCleanup") }
      let removed = try await request(config,path,limit:1024)
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
        let gate = ".credpivot-init-probe-" + UUID().uuidString.lowercased() + "/"
        var statuses: [Int] = []
        do {
          async let one = request(config,gate,method:"MKCOL",limit:1024)
          async let two = request(config,gate,method:"MKCOL",limit:1024)
          let (a,b) = try await (one,two)
          statuses = [a.response.statusCode,b.response.statusCode]
          exclusive = statuses == [201,405] || statuses == [405,201]
          let deleted = try await request(config,gate,method:"DELETE",limit:1024)
          guard [200,204,404].contains(deleted.response.statusCode) else { throw WebDAVFailure("sync.errors.probeCleanup") }
          let removed = try await request(config,gate,method:"PROPFIND",headers:["Depth":"0"],limit:256 * 1024)
          guard removed.response.statusCode == 404 else { throw WebDAVFailure("sync.errors.probeCleanup", status:removed.response.statusCode) }
        } catch {
          _ = try? await request(config,gate,method:"DELETE",limit:1024)
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
    try await directory(config,"snapshots/")
    try await directory(config,"backups/")
    checked("layout")
    checked("cleanup")
    writeCapabilities = (location:config["location"] as? String ?? "", policy:policy, createOnly:createOnly, initialCreation:initialCreation)
  }
  private func probeInitialMove(_ config: [String: Any], onCheck: (([String: Any]) -> Void)?) async throws {
    // 所有源和目标均为本次随机探针；不触碰 head.json，也不移动任何已有同步数据。
    let paths = (0..<4).map { _ in ".credpivot-probe-" + UUID().uuidString.lowercased() }
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
        let deleted = try await request(config,path,method:"DELETE",limit:1024)
        guard [200,204,404].contains(deleted.response.statusCode) else { throw WebDAVFailure("sync.errors.probeCleanup", stage:"cleanup", status:deleted.response.statusCode) }
        let removed = try await request(config,path,limit:1024)
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
    guard head["format"] as? String == "credpivot-sync", head["version"] as? Int == 1,
          let path = head["snapshot"] as? String,
          path.range(of:"^snapshots/credpivot_[A-Za-z0-9_-]+\\.ovb$", options:.regularExpression) != nil,
          path.count <= 180 else { throw WebDAVFailure("sync.errors.format") }
    return path
  }
  private func read(_ config: [String: Any], knownETag: String?) async throws -> [String: Any] {
    let reply = try await request(config,"head.json",headers:knownETag.map { ["If-None-Match":$0] } ?? [:],limit:64 * 1024)
    if reply.response.statusCode == 304 { return ["not_modified":true,"location":config["location"] ?? ""] }
    if reply.response.statusCode == 404 { return ["empty":true,"location":config["location"] ?? ""] }
    guard reply.response.statusCode == 200,
          let head = try JSONSerialization.jsonObject(with:reply.data) as? [String: Any] else { throw WebDAVFailure("sync.errors.format") }
    let tag = try etag(reply), path = try validSnapshot(head)
    let snapshot = try await request(config,path,limit:maxSnapshot)
    guard snapshot.response.statusCode == 200, let expected = head["sha256"] as? String,
          hash(snapshot.data) == expected else { throw WebDAVFailure("sync.errors.integrity") }
    return ["head":head,"etag":tag,"remote_ovb":snapshot.data.base64EncodedString(),"location":config["location"] ?? ""]
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
    try authorizePublish(publishing)
    let policy = WebDAVProviderPolicy(config)
    if writeCapabilities?.location != config["location"] as? String || writeCapabilities?.policy != policy { try await probe(config) }
    guard let capabilities = writeCapabilities, capabilities.location == config["location"] as? String, capabilities.policy == policy else {
      throw WebDAVFailure("sync.errors.conditionalWrite")
    }
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
      try await uploadUnique(publishing,path:backupPath,data:prior.data,limit:64 * 1024,createOnly:capabilities.createOnly)
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
    // 限制额外请求量，引用缓存由每轮完整列表中的 ETag 校验，不缓存密文或凭据。
    cleanupRequests = 64; cleanupDue = Date().addingTimeInterval(15 * 60)
    do {
      var protected: Set<String> = [try validSnapshot(head)]
      let current = try await cleanupCurrent(config,head:head,tag:tag)
      guard let serverTime = httpDate(current.response.value(forHTTPHeaderField:"Date")) else { throw WebDAVFailure("sync.cleanup.incomplete") }
      // 无引用文件留 7 天，为失败重试和其他设备尚未完成的上传留出缓冲。
      let now = min(serverTime,Date()), historyCutoff = now.addingTimeInterval(-30 * 86400), orphanCutoff = now.addingTimeInterval(-7 * 86400)
      let backupListing = try await cleanupListing(config,"backups/")
      let snapshotListing = try await cleanupListing(config,"snapshots/")
      let rootListing = try await cleanupListing(config,"")
      let backups = backupListing.compactMap { cleanupEntry($0,directory:"backups/") }.sorted { $0.modified < $1.modified }
      // 无法辨认的入口也可能引用有效快照，此时不猜测、不删除。
      guard backups.count == backupListing.count else { throw WebDAVFailure("sync.cleanup.incomplete") }
      let listed = Set(backups.map { $0.path })
      cleanupReferences = cleanupReferences.filter { listed.contains($0.key) }
      for entry in backups {
        if cleanupReferences[entry.path]?.etag != entry.etag {
          let reply = try await cleanupRequest(config,entry.path,headers:["If-Match":entry.etag])
          guard reply.response.statusCode == 200, try etag(reply) == entry.etag,
                let old = try JSONSerialization.jsonObject(with:reply.data) as? [String: Any] else { throw WebDAVFailure("sync.cleanup.incomplete") }
          cleanupReferences[entry.path] = (entry.etag,try validSnapshot(old))
        }
        if entry.modified >= historyCutoff, let reference = cleanupReferences[entry.path] { protected.insert(reference.snapshot) }
      }
      let expired = backups.filter { $0.modified < historyCutoff }
      let unused = snapshotListing.compactMap { cleanupEntry($0,directory:"snapshots/") }
        .filter { $0.modified < orphanCutoff && !protected.contains($0.path) }.sorted { $0.modified < $1.modified }
      let abandonedProbes = rootListing.compactMap { cleanupEntry($0,directory:"") }
        .filter { $0.modified < orphanCutoff }.sorted { $0.modified < $1.modified }
      guard !expired.isEmpty || !unused.isEmpty || !abandonedProbes.isEmpty else { return ["completed":true] }
      try await verifyCleanupDelete(config)
      var removedHeads = 0, removedSnapshots = 0, removedProbes = 0
      // 先删过期入口。任何失败都会停止本轮，不继续删除仍可能被该入口引用的快照。
      for entry in expired + unused + abandonedProbes {
        guard cleanupRequests >= 2 else { throw WebDAVFailure("sync.cleanup.deferred") }
        _ = try await cleanupCurrent(config,head:head,tag:tag)
        let removed = try await cleanupRequest(config,entry.path,method:"DELETE",headers:["If-Match":entry.etag])
        guard [200,204,404].contains(removed.response.statusCode) else { throw WebDAVFailure("sync.cleanup.changed") }
        if entry.path.hasPrefix("backups/") { removedHeads += 1; cleanupReferences.removeValue(forKey:entry.path) }
        else if entry.path.hasPrefix("snapshots/") { removedSnapshots += 1 }
        else { removedProbes += 1 }
      }
      return ["completed":true,"deleted_heads":removedHeads,"deleted_snapshots":removedSnapshots,"deleted_probes":removedProbes]
    } catch let failure as WebDAVFailure {
      if failure.key == "sync.cleanup.deferred" { cleanupDue = Date().addingTimeInterval(5 * 60) }
      throw failure
    }
  }
  func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    guard unlocked() else { result(FlutterError(code:"locked",message:NativePresentation.tr("sync.errors.locked"),details:nil)); return }
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
            try await probe(draft,onCheck:{ testChecks.append($0) })
            result(["ok":true,"checks":testChecks,"initial_creation":writeCapabilities?.initialCreation ?? ""])
            return
          }
          if args["verify"] as? Bool == true || settings()?["location"] as? String != location || WebDAVProviderPolicy(settings() ?? [:]) != WebDAVProviderPolicy(next) || !supplied.isEmpty {
            var draft = next
            draft["_transfer_generation"] = generation
            draft["_password"] = credential
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
  private var showingSshAuthorization = false
  private var showingPasskeyAuthorization = false
  private var shortcutController: CredPivotShortcuts?

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
  }

  private func startInteractionServices() {
    NativePresentation.reload()
    shortcutController = CredPivotShortcuts { [weak self] action in
      if action == "lock" {
        (NSApp.delegate as? AppDelegate)?.lockFromMenu()
      } else {
        self?.channel.invokeMethod("onShortcut", arguments: action)
      }
    }
    shortcutController?.apply(AppPreferences.settings())
    sshAuthorizationTimer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { [weak self] _ in
      self?.consumePasskeyAuthorization()
      self?.consumeSshAuthorization()
    }
  }

  private func consumeSshAuthorization() {
    guard !showingSshAuthorization, !showingPasskeyAuthorization, !TouchIdGate.isAuthenticating, NSApp.modalWindow == nil,
          let requests = LocalVaultUnlock.request(["type": "ssh_authorizations_pending"])?["requests"] as? [[String: Any]],
          let request = requests.first, let id = request["id"] as? String else { return }
    showingSshAuthorization = true
    NSApp.activate(ignoringOtherApps: true)
    let alert = NSAlert()
    let policy = request["policy"] as? String ?? "confirm"
    alert.messageText = policy == "unlock" ? NativePresentation.tr("ssh.authorization.unlockTitle") : NativePresentation.tr("ssh.authorization.confirmTitle")
    let scope = policy == "session" ? NativePresentation.tr("ssh.authorization.sessionScope") : NativePresentation.tr("ssh.authorization.onceScope")
    let caller = request["caller"] as? String ?? NativePresentation.tr("common.unknownProcess")
    alert.informativeText = policy == "unlock"
      ? NativePresentation.tr("ssh.authorization.unlockBody", arguments: ["caller": caller])
      : NativePresentation.tr("ssh.authorization.signBody", arguments: ["label": request["key_label"] as? String ?? NativePresentation.tr("common.unknown"), "fingerprint": request["fingerprint"] as? String ?? "", "caller": caller, "scope": scope])
    alert.addButton(withTitle: NativePresentation.tr("common.allow"))
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
    let complete: (Bool) -> Void = { [weak self] ok in
      _ = LocalVaultUnlock.request(["type": "ssh_authorization_resolve", "request_id": id, "approved": ok])
      self?.showingSshAuthorization = false
    }
    if policy == "biometric" {
      TouchIdGate.shared.authenticateForExtensionGate(reason: NativePresentation.tr("ssh.authorization.biometricReason"), completion: complete)
    } else {
      TouchIdGate.shared.authenticateSensitiveOperation(reason: policy == "unlock" ? NativePresentation.tr("ssh.authorization.unlockReason") : NativePresentation.tr("ssh.authorization.reason"), completion: complete)
    }
  }

  private func consumePasskeyAuthorization() {
    guard !showingPasskeyAuthorization, !showingSshAuthorization, !TouchIdGate.isAuthenticating, NSApp.modalWindow == nil,
          let requests = LocalVaultUnlock.request(["type": "passkey_requests_pending"])?["requests"] as? [[String: Any]],
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
    if !create {
      for (index, candidate) in candidates.enumerated() {
        let label = passkeyAccountLabel(candidate["username"] as? String ?? "", candidate["display_name"] as? String ?? "")
        picker.addItem(withTitle: "\(index + 1). \(label)")
        picker.lastItem?.representedObject = candidate["credential_id"] as? String
      }
      alert.accessoryView = picker
    }
    alert.addButton(withTitle: NativePresentation.tr(create ? NativePresentation.tr("passkey.authorization.save") : NativePresentation.tr("passkey.authorization.login")))
    alert.addButton(withTitle: NativePresentation.tr("passkey.authorization.useBrowser"))
    alert.addButton(withTitle: NativePresentation.tr("common.cancel"))
    // 取消、跳转、锁库后关闭失效确认窗；实际签名前 Agent 还会再次校验请求。
    let expiry = Timer(timeInterval: 0.5, repeats: true) { _ in
      guard let pending = LocalVaultUnlock.request(["type": "passkey_requests_pending"])?["requests"] as? [[String: Any]],
            pending.contains(where: { $0["id"] as? String == id }) else {
        NSApp.abortModal()
        alert.window.orderOut(nil)
        return
      }
    }
    RunLoop.main.add(expiry, forMode: .modalPanel)
    NSApp.activate(ignoringOtherApps: true)
    let decision = alert.runModal()
    expiry.invalidate()
    let selected = picker.selectedItem?.representedObject as? String ?? ""
    let complete: (Bool) -> Void = { [weak self] approved in
      let result = LocalVaultUnlock.request(["type": "passkey_resolve", "request_id": id,
        "approved": approved, "credential_id": selected, "use_browser": decision == .alertSecondButtonReturn])
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

  deinit { sshAuthorizationTimer?.invalidate() }

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
    case "webdavSettings", "webdavSave", "webdavTest", "webdavRead", "webdavPublish", "webdavProbe", "webdavRemove", "webdavCleanup":
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
      let previousSettings = requestObject?["type"] as? String == "app_settings_set" ? AppPreferences.settings() : nil
      var response = credpivotAgentRequestJsonString(json)
      if let requestData = json.data(using: .utf8),
         let request = try? JSONSerialization.jsonObject(with: requestData) as? [String: Any],
         request["type"] as? String == "status",
         let responseData = response.data(using: .utf8),
         var object = try? JSONSerialization.jsonObject(with: responseData) as? [String: Any],
         var payload = object["payload"] as? [String: Any] {
        payload["local_unlock_configured"] = LocalVaultUnlock.configured
        payload["local_unlock_notice"] = LocalVaultUnlock.setupNotice
        payload["browser_background_launch"] = AppDelegate.launchedForBrowser
        object["payload"] = payload
        if let data = try? JSONSerialization.data(withJSONObject: object),
           let updated = String(data: data, encoding: .utf8) { response = updated }
      }
      if let data = json.data(using: .utf8),
         let request = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
         response.contains("\"type\":\"ok\"") {
        switch request["type"] as? String {
        case "vault_create", "vault_change_password", "vault_security_rebuild":
          Task { @MainActor in CredPivotWebDAV.shared.cancel(reason:"sync.errors.localControlChanged") }
          LocalVaultUnlock.enroll()
        case "vault_export_ovb": _ = LocalVaultUnlock.persist(enroll: false)
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
    case "scanQrImage":
      DispatchQueue.main.async {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.image]
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { result([]); return }
        DispatchQueue.global(qos: .userInitiated).async {
          do {
            let request = VNDetectBarcodesRequest()
            request.symbologies = [.qr]
            try VNImageRequestHandler(url: url).perform([request])
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
      guard let secret = call.arguments as? String else {
        result(FlutterError(code: "bad_args", message: "secret required", details: nil))
        return
      }
      let seconds = (AppPreferences.settings()["clipboard_clear_seconds"] as? NSNumber)?.doubleValue ?? 5
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
      if let err = TerminalLauncher.openSsh(host: host, port: port, user: username) {
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
  /// 用户取消指纹/密码后短暂不再自动弹窗（毫秒时间戳）。
  private static var snoozeUntilMs: TimeInterval = 0

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
    Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { _ in
      consumePendingIfNeeded()
    }
    consumePendingIfNeeded()
  }

  private static var pendingPath: URL {
    FileManager.default.homeDirectoryForCurrentUser
      .appendingPathComponent(".credpivot/extension_gate.pending")
  }

  private static func consumePendingIfNeeded() {
    let nowMs = Date().timeIntervalSince1970 * 1000
    if nowMs < snoozeUntilMs {
      return
    }
    if !FileManager.default.fileExists(atPath: pendingPath.path) {
      return
    }
    if pending {
      return
    }
    guard !TouchIdGate.isAuthenticating,
          let session = try? String(contentsOf: pendingPath, encoding: .utf8),
          UUID(uuidString: session) != nil else { return }
    pending = true
    // LocalAuthentication 自行展示系统弹窗，不激活 App，避免打断 Chrome。
    TouchIdGate.shared.authenticateForExtensionGate(reason: NativePresentation.tr("browser.authorization.reason")) { ok in
      pending = false
      let current = try? String(contentsOf: pendingPath, encoding: .utf8)
      guard current == session else { return }
      if ok {
        _ = LocalVaultUnlock.request(["type": "extension_gate_grant", "session_id": session, "ttl_secs": 0])
      } else {
        snoozeUntilMs = Date().timeIntervalSince1970 * 1000 + 30_000
      }
      // 取消后不自动重弹；用户重新点扩展连接时再生成请求。
      if (try? String(contentsOf: pendingPath, encoding: .utf8)) == session {
        try? FileManager.default.removeItem(at: pendingPath)
      }
    }
  }
}

// MARK: - 用户偏好统一由 Rust 校验和原子写入 settings.json

enum AppPreferences {
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

  static func migrateLegacyPreferences() {
    let current = settings()
    guard !current.isEmpty else { return }
    var changes: [String: Any] = [:]
    let legacyChrome = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".credpivot/chrome_extension_id")
    if current["terminal_app_path"] as? String == nil {
      changes["terminal_app_path"] = UserDefaults.standard.string(forKey: "credpivot.terminal.app_path") ?? ""
    }
    if current["chrome_extension_id"] as? String == nil {
      let old = (try? String(contentsOf: legacyChrome, encoding: .utf8))?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
      changes["chrome_extension_id"] = old.range(of: "^[a-p]{32}$", options: .regularExpression) != nil ? old : ""
    }
    if current["launch_at_login"] as? Bool == nil {
      let login = LoginItemRegistrar.status()
      changes["launch_at_login"] = login["enabled"] as? Bool == true || login["requires_approval"] as? Bool == true
    }
    guard !changes.isEmpty, update(changes) else { return }
    // 只有统一配置写入成功后才移除旧存储，防止迁移失败丢失偏好。
    UserDefaults.standard.removeObject(forKey: "credpivot.terminal.app_path")
    UserDefaults.standard.removeObject(forKey: "credpivot.terminal.app")
    try? FileManager.default.removeItem(at: legacyChrome)
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

  static func unlockBiometric(completion: @escaping (Bool) -> Void) {
    guard !TouchIdGate.isAuthenticating,
          request(["type": "status"])?["master_password_required"] as? Bool == false,
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

  func authenticateForExtensionGate(reason: String, completion: @escaping (Bool) -> Void) {
    authenticate(reason: reason, allowReuse: false, completion: completion)
  }

  func authenticateSensitiveOperation(reason: String, completion: @escaping (Bool) -> Void) {
    authenticate(reason: reason, allowReuse: true, completion: completion)
  }

  private func authenticate(reason: String, allowReuse: Bool, completion: @escaping (Bool) -> Void) {
    let localizedReason = NativePresentation.tr(reason)
    guard !TouchIdGate.isAuthenticating else { completion(false); return }
    let status = LocalVaultUnlock.request(["type": "status"]) ?? [:]
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
        LocalVaultUnlock.unlockBiometric(completion: completion)
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
  private static let installedHostPath: URL = credPivotDir.appendingPathComponent("credpivot-native-host")
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
    if let bundledHost {
      if let trusted = getenv("CREDPIVOT_TRUSTED_NATIVE_HOST") {
        trustedHostConfigured = URL(fileURLWithPath: String(cString: trusted)).resolvingSymlinksInPath()
          == URL(fileURLWithPath: bundledHost).resolvingSymlinksInPath()
      }
      if let source = try? Data(contentsOf: URL(fileURLWithPath: bundledHost)),
         let installed = try? Data(contentsOf: installedHostPath) {
        installedHostCurrent = SHA256.hash(data: source) == SHA256.hash(data: installed)
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
        return bundled.path
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
    try FileManager.default.createDirectory(at: credPivotDir, withIntermediateDirectories: true)
    if FileManager.default.fileExists(atPath: installedHostPath.path) {
      try FileManager.default.removeItem(at: installedHostPath)
    }
    try FileManager.default.copyItem(atPath: src, toPath: installedHostPath.path)
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: installedHostPath.path)
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
      try data.write(to: manifestURL)
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

  static func applyPreference() -> [String: Any] {
    if let id = storedExtensionId() { return install(extensionId: id) }
    do {
      if FileManager.default.fileExists(atPath: manifestURL.path) { try FileManager.default.removeItem(at: manifestURL) }
      return ["ok": true]
    } catch { return ["ok": false, "message": NativePresentation.tr("native.applyPreference.text.item6")] }
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
  private static let legacyIdKey = "credpivot.terminal.app"
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
    guard AppPreferences.update(["terminal_app_path": path]) else { return false }
    UserDefaults.standard.removeObject(forKey: legacyIdKey)
    return true
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

  static func sshShellCommand(host: String, port: Int, user: String) -> String {
    let target = shellQuote("\(user)@\(host)")
    if port == 22 {
      return "ssh \(target)"
    }
    return "ssh -p \(port) \(target)"
  }

  /// 成功返回 nil；失败返回错误文案。
  static func openSsh(host: String, port: Int, user: String) -> String? {
    guard let appPath = currentAppPath(), !appPath.isEmpty else {
      return NativePresentation.tr("native.openSsh.text")
    }
    if !FileManager.default.fileExists(atPath: appPath) {
      return NativePresentation.tr("native.openSsh.text.item2", arguments: ["appPath": String(describing: appPath)])
    }
    let sshCmd = sshShellCommand(host: host, port: port, user: user)
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
