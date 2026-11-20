// iMochige remote login agent: runs on a GitHub-hosted macOS runner.
// It reads AES-256-GCM encrypted commands from issue comments, drives the
// official Apple sign-in UI through Accessibility, and reports the visible
// UI state back, encrypted with the same per-session key.
// Decrypted values are never printed to the job log.
import AppKit
import ApplicationServices
import Carbon
import CoreGraphics
import CryptoKit
import Foundation
import Vision

setvbuf(stdout, nil, _IOLBF, 0)
let env = ProcessInfo.processInfo.environment
// IMOCHIGE_SELFTEST=1: run the UU one-click flow locally without the GitHub channel, then exit.
let selfTest = env["IMOCHIGE_SELFTEST"] == "1"
func need(_ name: String) -> String {
    if selfTest { return name == "IMOCHIGE_KEY" ? Data(count: 32).base64EncodedString() : "selftest" }
    guard let value = env[name], !value.isEmpty else { print("Missing \(name)"); exit(2) }
    return value
}
guard let keyData = Data(base64Encoded: need("IMOCHIGE_KEY")), keyData.count == 32 else {
    print("Session key missing or malformed."); exit(2)
}
let key = SymmetricKey(data: keyData)
let sessionID = need("IMOCHIGE_SESSION")
let issue = need("IMOCHIGE_ISSUE")
let repo = need("GITHUB_REPOSITORY")
let token = need("GH_TOKEN")
let api = env["GITHUB_API_URL"] ?? "https://api.github.com"
let started = Date()
let maxMinutes = Double(env["IMOCHIGE_MAX_MINUTES"] ?? "") ?? 38
let idleMinutes = Double(env["IMOCHIGE_IDLE_MINUTES"] ?? "") ?? 15
let hardDeadline = started.addingTimeInterval(maxMinutes * 60)
var lastCommand = Date()

// MARK: - GitHub transport

func http(_ method: String, _ path: String, _ body: [String: Any]? = nil) -> (Int, Data) {
    var request = URLRequest(url: URL(string: api + path)!)
    request.httpMethod = method
    request.timeoutInterval = 20
    request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
    request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
    request.setValue("2022-11-28", forHTTPHeaderField: "X-GitHub-Api-Version")
    if let body {
        request.httpBody = try? JSONSerialization.data(withJSONObject: body)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    }
    let done = DispatchSemaphore(value: 0)
    var result: (Int, Data) = (0, Data())
    URLSession.shared.dataTask(with: request) { data, response, _ in
        result = ((response as? HTTPURLResponse)?.statusCode ?? 0, data ?? Data())
        done.signal()
    }.resume()
    done.wait()
    return result
}

/// Message with long strings (images) replaced by their length, for logs.
func brief(_ message: [String: Any]) -> [String: Any] {
    message.mapValues { value -> Any in
        if let text = value as? String, text.count > 200 { return "<\(text.count) chars>" }
        return value
    }
}

var outSeq = 0
func send(_ message: [String: Any]) {
    outSeq += 1
    if selfTest {
        print("[send] \(brief(message))")
        return
    }
    guard let plain = try? JSONSerialization.data(withJSONObject: message),
          let sealed = try? AES.GCM.seal(plain, using: key,
                                         authenticating: Data("imochige1|\(sessionID)|r2c|\(outSeq)".utf8)),
          let combined = sealed.combined else { return }
    let encoded = combined.base64EncodedString()
    let chunk = 60000
    let parts = stride(from: 0, to: encoded.count, by: chunk).map { start -> String in
        let a = encoded.index(encoded.startIndex, offsetBy: start)
        let b = encoded.index(a, offsetBy: min(chunk, encoded.count - start))
        return String(encoded[a..<b])
    }
    for (index, part) in parts.enumerated() {
        let body = "imochige1 r2c \(outSeq) \(index + 1)/\(parts.count) \(part)"
        for attempt in 0..<3 {
            let (status, _) = http("POST", "/repos/\(repo)/issues/\(issue)/comments", ["body": body])
            if status == 201 { break }
            print("Comment post status \(status), attempt \(attempt + 1)")
            Thread.sleep(forTimeInterval: 2)
        }
    }
    print("Sent encrypted message #\(outSeq) (\(message["type"] ?? "?"))")
}

var seenComments = Set<Int>()
var inSeq = 0
func fetchCommands() -> [[String: Any]] {
    var commands: [[String: Any]] = []
    var page = 1
    while page < 20 {
        let (status, data) = http("GET", "/repos/\(repo)/issues/\(issue)/comments?per_page=100&page=\(page)")
        guard status == 200, let list = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else {
            if status != 200 { print("Comment poll status \(status)") }
            break
        }
        for comment in list {
            guard let id = comment["id"] as? Int, !seenComments.contains(id) else { continue }
            seenComments.insert(id)
            let words = (comment["body"] as? String ?? "").split(separator: " ")
            guard words.count == 4, words[0] == "imochige1", words[1] == "c2r", let seq = Int(words[2]),
                  seq > inSeq, let blob = Data(base64Encoded: String(words[3])),
                  let box = try? AES.GCM.SealedBox(combined: blob),
                  let plain = try? AES.GCM.open(box, using: key,
                                                authenticating: Data("imochige1|\(sessionID)|c2r|\(seq)".utf8)),
                  let command = try? JSONSerialization.jsonObject(with: plain) as? [String: Any] else { continue }
            inSeq = seq
            commands.append(command)
        }
        if list.count < 100 { break }
        page += 1
    }
    return commands
}

// MARK: - Accessibility helpers

func attribute(_ node: AXUIElement, _ name: String) -> CFTypeRef? {
    var value: CFTypeRef?
    return AXUIElementCopyAttributeValue(node, name as CFString, &value) == .success ? value : nil
}
func string(_ node: AXUIElement, _ name: String) -> String { attribute(node, name) as? String ?? "" }
func role(_ node: AXUIElement) -> String { string(node, kAXRoleAttribute) }

func descendants(_ root: AXUIElement, limit: Int = 700) -> [AXUIElement] {
    var nodes = [root]
    var index = 0
    while index < nodes.count && nodes.count < limit {
        nodes.append(contentsOf: attribute(nodes[index], kAXChildrenAttribute) as? [AXUIElement] ?? [])
        index += 1
    }
    return Array(nodes.prefix(limit))
}

func pump(_ seconds: Double) { RunLoop.current.run(until: Date().addingTimeInterval(seconds)) }

let watchedBundles: Set<String> = ["com.apple.systempreferences", "com.apple.MobileSMS",
                                   "com.apple.UserNotificationCenter", "com.apple.SecurityAgent",
                                   "com.apple.CoreServicesUIAgent"]
func watchedApps() -> [NSRunningApplication] {
    NSWorkspace.shared.runningApplications.filter { app in
        guard let id = app.bundleIdentifier else { return false }
        let lower = id.lowercased()
        return watchedBundles.contains(id)
            || (env["UU_APP"] != nil && app.bundleURL?.path.hasPrefix(env["UU_APP"]!) == true)
            || (id.hasPrefix("com.apple.") && ["authkit", "appleid", "appleaccount", "akd", "icloud"].contains { lower.contains($0) })
    }
}

struct Element { let node: AXUIElement; let app: NSRunningApplication; let kind: String; let name: String }
var elements: [Element] = []
var lastStateJSON = ""

func snapshot() -> [String: Any] {
    elements = []
    var windowsOut: [[String: Any]] = []
    for app in watchedApps() {
        let process = AXUIElementCreateApplication(app.processIdentifier)
        let windows = attribute(process, kAXWindowsAttribute) as? [AXUIElement] ?? []
        for window in windows {
            let title = string(window, kAXTitleAttribute)
            var texts: [String] = []
            var fields: [[String: Any]] = []
            var buttons: [[String: Any]] = []
            for node in descendants(window) {
                let r = role(node)
                let label = [kAXTitleAttribute, kAXDescriptionAttribute, "AXPlaceholderValue", kAXHelpAttribute]
                    .map { string(node, $0) }.filter { !$0.isEmpty }.joined(separator: " | ")
                let enabled = (attribute(node, kAXEnabledAttribute) as? Bool) != false
                switch r {
                case kAXStaticTextRole:
                    let value = string(node, kAXValueAttribute).trimmingCharacters(in: .whitespacesAndNewlines)
                    let text = value.isEmpty ? label : value
                    if !text.isEmpty, texts.count < 60, !texts.contains(text) { texts.append(String(text.prefix(300))) }
                case kAXTextFieldRole, kAXTextAreaRole, "AXComboBox":
                    let subrole = string(node, kAXSubroleAttribute)
                    let secure = subrole == "AXSecureTextField"
                    let value = string(node, kAXValueAttribute)
                    let count = attribute(node, kAXNumberOfCharactersAttribute) as? Int ?? value.count
                    elements.append(Element(node: node, app: app, kind: "field", name: label))
                    var field: [String: Any] = ["id": elements.count - 1, "label": label, "secure": secure,
                                                "search": subrole == "AXSearchField", "length": count,
                                                "focused": (attribute(node, kAXFocusedAttribute) as? Bool) == true,
                                                "enabled": enabled]
                    if !secure { field["value"] = String(value.prefix(200)) }
                    fields.append(field)
                case kAXButtonRole, kAXCheckBoxRole, kAXRadioButtonRole, "AXLink", kAXPopUpButtonRole, kAXMenuButtonRole:
                    var actions: CFArray?
                    guard AXUIElementCopyActionNames(node, &actions) == .success,
                          (actions as? [String])?.contains(kAXPressAction) == true else { continue }
                    var name = label
                    if name.isEmpty {
                        name = descendants(node, limit: 20).filter { role($0) == kAXStaticTextRole }
                            .map { string($0, kAXValueAttribute) }.filter { !$0.isEmpty }.joined(separator: " ")
                    }
                    guard !name.isEmpty, buttons.count < 80 else { continue }
                    name = String(name.prefix(120))
                    elements.append(Element(node: node, app: app, kind: "button", name: name))
                    var button: [String: Any] = ["id": elements.count - 1, "title": name,
                                                 "role": r, "enabled": enabled]
                    if r == kAXCheckBoxRole || r == kAXRadioButtonRole {
                        button["value"] = attribute(node, kAXValueAttribute) as? Int ?? 0
                    }
                    buttons.append(button)
                default:
                    break
                }
            }
            windowsOut.append(["app": app.localizedName ?? app.bundleIdentifier ?? "?",
                               "bundle": app.bundleIdentifier ?? "", "title": title,
                               "active": app.isActive, "texts": texts, "fields": fields, "buttons": buttons])
        }
    }
    return ["windows": windowsOut, "frontmost": NSWorkspace.shared.frontmostApplication?.bundleIdentifier ?? ""]
}

var lastStateWindows: [String] = []
var lastStatePost = Date.distantPast
func reportState(force: Bool = false) {
    let state = snapshot()
    // Compare without volatile focus/activation flags so an unchanged UI is not re-posted.
    // Content signature only: element order inside Apple's views can shuffle between reads.
    let windows = (state["windows"] as? [[String: Any]] ?? []).map { window -> String in
        let texts = (window["texts"] as? [String] ?? []).sorted()
        let fields = (window["fields"] as? [[String: Any]] ?? []).map { f in
            "\(f["label"] ?? "")|\(f["secure"] ?? "")|\(f["length"] ?? "")|\(f["value"] ?? "")|\(f["enabled"] ?? "")"
        }.sorted()
        let buttons = (window["buttons"] as? [[String: Any]] ?? []).map { b in
            "\(b["title"] ?? "")|\(b["enabled"] ?? "")|\(b["value"] ?? "")"
        }.sorted()
        return ([window["app"] as? String ?? "", window["title"] as? String ?? ""] + texts + fields + buttons)
            .joined(separator: "\u{1}")
    }
    let json = windows.joined(separator: "\n")
    guard force || (json != lastStateJSON && Date().timeIntervalSince(lastStatePost) >= 10) else { return }
    if !force {
        // Diagnostics only: part counts, no content.
        let old = Set(lastStateJSON.components(separatedBy: CharacterSet(charactersIn: "\u{1}\n")))
        let new = Set(json.components(separatedBy: CharacterSet(charactersIn: "\u{1}\n")))
        print("State changed: parts \(old.count) -> \(new.count), added \(new.subtracting(old).count), removed \(old.subtracting(new).count)")
    }
    lastStateJSON = json
    lastStateWindows = windows
    lastStatePost = Date()
    send(["type": "state", "state": state])
}

func postKey(_ code: Int, flags: CGEventFlags = []) {
    for down in [true, false] {
        let event = CGEvent(keyboardEventSource: nil, virtualKey: CGKeyCode(code), keyDown: down)
        event?.flags = flags
        event?.post(tap: .cghidEventTap)
    }
    pump(0.05)
}

func typeText(_ text: String) {
    for unit in text.utf16 {
        var character = unit
        let down = CGEvent(keyboardEventSource: nil, virtualKey: 0, keyDown: true)
        let up = CGEvent(keyboardEventSource: nil, virtualKey: 0, keyDown: false)
        down?.keyboardSetUnicodeString(stringLength: 1, unicodeString: &character)
        up?.keyboardSetUnicodeString(stringLength: 1, unicodeString: &character)
        down?.post(tap: .cghidEventTap)
        up?.post(tap: .cghidEventTap)
        pump(0.04)
    }
}

func focus(_ element: Element) -> Bool {
    _ = element.app.activate(options: [])
    pump(0.3)
    if let window = attribute(element.node, kAXWindowAttribute), CFGetTypeID(window) == AXUIElementGetTypeID() {
        _ = AXUIElementPerformAction(unsafeDowncast(window, to: AXUIElement.self), kAXRaiseAction as CFString)
    }
    _ = AXUIElementSetAttributeValue(element.node, kAXFocusedAttribute as CFString, kCFBooleanTrue)
    pump(0.3)
    return (attribute(element.node, kAXFocusedAttribute) as? Bool) == true
}

func fieldLength(_ node: AXUIElement) -> Int {
    attribute(node, kAXNumberOfCharactersAttribute) as? Int ?? string(node, kAXValueAttribute).count
}

func fill(_ element: Element, _ value: String, keys: Bool) -> [String: Any] {
    let focused = focus(element)
    var method = "none"
    let secure = string(element.node, kAXSubroleAttribute) == "AXSecureTextField"
    func matches() -> Bool {
        secure ? fieldLength(element.node) == value.count : string(element.node, kAXValueAttribute) == value
    }
    if !keys {
        var writable: DarwinBoolean = false
        if AXUIElementIsAttributeSettable(element.node, kAXValueAttribute as CFString, &writable) == .success,
           writable.boolValue,
           AXUIElementSetAttributeValue(element.node, kAXValueAttribute as CFString, value as CFString) == .success {
            pump(0.4)
            method = "axvalue"
        }
    }
    if !matches() {
        // Clear and type through the keyboard into the frontmost, focused field.
        if focused && element.app.isActive {
            postKey(kVK_ANSI_A, flags: .maskCommand)
            postKey(kVK_Delete)
            typeText(value)
            pump(0.5)
            method = "keyboard"
        }
    }
    return ["ok": matches(), "method": method, "focused": focused, "length": fieldLength(element.node)]
}

func openTarget(_ target: String) -> [String: Any] {
    let opener = Process()
    opener.executableURL = URL(fileURLWithPath: "/usr/bin/open")
    switch target {
    case "messages":
        opener.arguments = ["-a", "Messages"]
    default:
        opener.arguments = ["x-apple.systempreferences:com.apple.systempreferences.AppleIDSettings"]
    }
    do { try opener.run(); opener.waitUntilExit() } catch { return ["ok": false, "error": "\(error)"] }
    pump(2)
    if target == "messages", let app = NSRunningApplication.runningApplications(withBundleIdentifier: "com.apple.MobileSMS").first {
        _ = app.activate(options: [])
        pump(1)
        postKey(kVK_ANSI_Comma, flags: .maskCommand)
        pump(1.5)
    }
    return ["ok": opener.terminationStatus == 0]
}

func osascript(_ source: String, _ args: [String] = []) -> [String: Any] {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
    process.arguments = ["-e", source] + args
    let out = Pipe(), err = Pipe()
    process.standardOutput = out
    process.standardError = err
    do { try process.run() } catch { return ["ok": false, "error": "\(error)"] }
    let deadline = Date().addingTimeInterval(30)
    while process.isRunning && Date() < deadline { pump(0.2) }
    if process.isRunning { process.terminate(); return ["ok": false, "error": "osascript timed out"] }
    let output = String(data: out.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    let error = String(data: err.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    return ["ok": process.terminationStatus == 0, "output": String(output.prefix(4000)), "error": String(error.prefix(2000))]
}

func screenshot() -> [String: Any] {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("imochige-\(UUID().uuidString)")
    try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: dir) }
    let raw = dir.appendingPathComponent("s.png").path, small = dir.appendingPathComponent("s.jpg").path
    for (tool, args) in [("/usr/sbin/screencapture", ["-x", "-t", "png", raw]),
                         ("/usr/bin/sips", ["-Z", "1100", "-s", "format", "jpeg", "-s", "formatOptions", "45", raw, "--out", small])] {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: tool)
        process.arguments = args
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        do { try process.run(); process.waitUntilExit() } catch { return ["ok": false, "error": "\(error)"] }
    }
    guard let data = FileManager.default.contents(atPath: small) else {
        return ["ok": false, "error": "Screen capture failed (Screen Recording permission?)"]
    }
    return ["ok": true, "jpeg": data.base64EncodedString()]
}

// MARK: - UU Remote login (QR code)

func uuApp() -> NSRunningApplication? {
    guard let path = env["UU_APP"] else { return nil }
    return NSWorkspace.shared.runningApplications.first { $0.bundleURL?.path.hasPrefix(path) == true }
}

func uuWindows(_ app: NSRunningApplication) -> [(id: Int, frame: CGRect)] {
    (CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID) as? [[String: Any]] ?? [])
        .compactMap { window in
            guard window[kCGWindowOwnerPID as String] as? Int32 == app.processIdentifier,
                  window[kCGWindowLayer as String] as? Int == 0,
                  let id = window[kCGWindowNumber as String] as? Int,
                  let bounds = window[kCGWindowBounds as String] as? NSDictionary,
                  let frame = CGRect(dictionaryRepresentation: bounds as CFDictionary),
                  frame.width >= 200, frame.height >= 120 else { return nil }
            return (id, frame)
        }
}

func captureWindow(_ id: Int, to path: String) -> Bool {
    let capture = Process()
    capture.executableURL = URL(fileURLWithPath: "/usr/sbin/screencapture")
    capture.arguments = ["-x", "-o", "-l", String(id), path]
    capture.standardError = FileHandle.nullDevice
    do { try capture.run(); capture.waitUntilExit() } catch { return false }
    return capture.terminationStatus == 0 && FileManager.default.fileExists(atPath: path)
}

let uuLoginLabels: Set<String> = ["登录", "立即登录", "点击登录", "登录账号", "去登录", "请登录", "登录/注册",
                                  "注册/登录", "登录注册", "账号登录", "扫码登录", "signin", "login"]

func launchUU() -> Bool {
    guard let path = env["UU_APP"] else { return false }
    let opener = Process()
    opener.executableURL = URL(fileURLWithPath: "/usr/bin/open")
    opener.arguments = [path]
    do { try opener.run(); opener.waitUntilExit() } catch { return false }
    return opener.terminationStatus == 0
}

/// Hide every other app (System Settings keeps covering UU) and raise UU's windows.
func bringUUToFront() -> [String: Any] {
    if uuApp() == nil { _ = launchUU(); for _ in 0..<20 where uuApp() == nil { pump(0.5) } }
    guard let app = uuApp() else { return ["ok": false, "error": "UU Remote is not running in this session"] }
    let me = ProcessInfo.processInfo.processIdentifier
    var hidden: [String] = []
    for other in NSWorkspace.shared.runningApplications
    where other.activationPolicy == .regular && other.processIdentifier != app.processIdentifier
        && other.processIdentifier != me && !other.isHidden {
        if other.hide() { hidden.append(other.localizedName ?? other.bundleIdentifier ?? "?") }
    }
    pump(0.5)
    _ = launchUU()  // reopens a closed main window
    _ = app.unhide()
    _ = app.activate(options: [.activateAllWindows])
    let root = AXUIElementCreateApplication(app.processIdentifier)
    AXUIElementSetAttributeValue(root, kAXFrontmostAttribute as CFString, kCFBooleanTrue)
    for window in attribute(root, kAXWindowsAttribute) as? [AXUIElement] ?? [] {
        AXUIElementSetAttributeValue(window, kAXMinimizedAttribute as CFString, kCFBooleanFalse)
        AXUIElementPerformAction(window, kAXRaiseAction as CFString)
    }
    pump(1.5)
    let front = NSWorkspace.shared.frontmostApplication?.processIdentifier == app.processIdentifier
    return ["ok": front, "hidden": hidden, "front": front,
            "error": front ? "" : "UU did not become the frontmost app"]
}

/// Whether the topmost on-screen window at `point` belongs to UU.
func pointHitsUU(_ point: CGPoint, _ app: NSRunningApplication) -> Bool {
    let windows = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID) as? [[String: Any]] ?? []
    let top = windows.first { window in
        guard window[kCGWindowLayer as String] as? Int == 0,
              (window[kCGWindowAlpha as String] as? Double ?? 1) > 0,
              let bounds = window[kCGWindowBounds as String] as? NSDictionary,
              let frame = CGRect(dictionaryRepresentation: bounds as CFDictionary) else { return false }
        return frame.contains(point)
    }
    return top?[kCGWindowOwnerPID as String] as? Int32 == app.processIdentifier
}

func uuLogin() -> [String: Any] {
    let front = bringUUToFront()
    guard let app = uuApp() else { return front }
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("imochige-uu-\(UUID().uuidString)")
    try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: dir) }
    let root = AXUIElementCreateApplication(app.processIdentifier)

    var method = "none"
    // 1) Accessibility button with a login title.
    let buttons = descendants(root).filter { node in
        let title = [kAXTitleAttribute, kAXDescriptionAttribute, kAXValueAttribute]
            .map { string(node, $0).lowercased().filter { !$0.isWhitespace } }
        return role(node) == kAXButtonRole as String && title.contains { uuLoginLabels.contains($0) }
    }
    if buttons.count == 1, AXUIElementPerformAction(buttons[0], kAXPressAction as CFString) == .success {
        method = "accessibility"
    }
    // 2) Text recognition on the window image, then a mouse click on the visible label.
    var labels: [String] = []
    if method == "none" {
        var matches: [CGPoint] = []
        // Windows come front to back; stop at the first one that shows the login label.
        for window in uuWindows(app) where matches.isEmpty {
            let image = dir.appendingPathComponent("ocr-\(window.id).png").path
            guard captureWindow(window.id, to: image) else { continue }
            let request = VNRecognizeTextRequest()
            request.recognitionLanguages = ["zh-Hans", "en-US"]
            try? VNImageRequestHandler(url: URL(fileURLWithPath: image)).perform([request])
            for observation in request.results ?? [] {
                guard let text = observation.topCandidates(1).first?.string else { continue }
                let label = text.lowercased().filter { !$0.isWhitespace }.replacingOccurrences(of: "／", with: "/")
                guard uuLoginLabels.contains(label) else { continue }
                labels.append(label)
                let box = observation.boundingBox
                matches.append(CGPoint(x: window.frame.minX + box.midX * window.frame.width,
                                       y: window.frame.minY + (1 - box.midY) * window.frame.height))
            }
        }
        if !matches.isEmpty, !matches.contains(where: { pointHitsUU($0, app) }) {
            _ = bringUUToFront()  // something covered UU again; retry once
        }
        // Several hits (duplicate windows, the label repeated in a banner): take the first visible one.
        if let target = matches.first(where: { pointHitsUU($0, app) }), CGPreflightPostEventAccess(),
           let move = CGEvent(mouseEventSource: nil, mouseType: .mouseMoved, mouseCursorPosition: target, mouseButton: .left),
           let down = CGEvent(mouseEventSource: nil, mouseType: .leftMouseDown, mouseCursorPosition: target, mouseButton: .left),
           let up = CGEvent(mouseEventSource: nil, mouseType: .leftMouseUp, mouseCursorPosition: target, mouseButton: .left) {
            move.post(tap: .cghidEventTap)
            pump(0.1)
            down.post(tap: .cghidEventTap)
            pump(0.05)
            up.post(tap: .cghidEventTap)
            method = "click"
        }
    }
    pump(method == "none" ? 1 : 6)

    // Capture the UU window(s) and look for a QR code; return the best image.
    var best: (data: Data, qr: Bool)? = nil
    for window in uuWindows(app) {
        let raw = dir.appendingPathComponent("w-\(window.id).png").path
        guard captureWindow(window.id, to: raw) else { continue }
        let request = VNDetectBarcodesRequest()
        request.symbologies = [.qr]
        try? VNImageRequestHandler(url: URL(fileURLWithPath: raw)).perform([request])
        let qr = request.results?.isEmpty == false
        let small = dir.appendingPathComponent("w-\(window.id).jpg").path
        let sips = Process()
        sips.executableURL = URL(fileURLWithPath: "/usr/bin/sips")
        sips.arguments = ["-Z", "900", "-s", "format", "jpeg", "-s", "formatOptions", "70", raw, "--out", small]
        sips.standardOutput = FileHandle.nullDevice
        sips.standardError = FileHandle.nullDevice
        try? sips.run(); sips.waitUntilExit()
        guard let data = FileManager.default.contents(atPath: small) else { continue }
        if best == nil || (qr && !best!.qr) { best = (data, qr) }
        if qr { break }
    }
    var result: [String: Any] = ["ok": best != nil, "method": method, "labels": labels, "qr": best?.qr ?? false,
                                 "front": front["front"] ?? false, "hidden": front["hidden"] ?? []]
    if let best { result["jpeg"] = best.data.base64EncodedString() } else { result["error"] = "Could not capture the UU window" }
    return result
}

// MARK: - UU one-click: QR login + allow same-account control
// Verified on macos-15 and macos-15-intel by the uu-probe workflow: UU's widgets are exposed
// through Accessibility with exact screen geometry, so every click below targets an AX frame
// (no OCR guessing). Settings > 安全 has a row "允许同账号控制本设备" with an AXButton toggle.

func axFrame(_ node: AXUIElement) -> CGRect? {
    guard let p = attribute(node, kAXPositionAttribute), let s = attribute(node, kAXSizeAttribute) else { return nil }
    var point = CGPoint.zero, size = CGSize.zero
    AXValueGetValue(p as! AXValue, .cgPoint, &point)
    AXValueGetValue(s as! AXValue, .cgSize, &size)
    return CGRect(origin: point, size: size)
}

func axLabel(_ node: AXUIElement) -> String {
    [kAXTitleAttribute, kAXValueAttribute, kAXDescriptionAttribute].map { string(node, $0) }.first { !$0.isEmpty } ?? ""
}

func uuWindowNodes(_ app: NSRunningApplication) -> [AXUIElement] {
    attribute(AXUIElementCreateApplication(app.processIdentifier), kAXWindowsAttribute) as? [AXUIElement] ?? []
}

/// First element in UU's windows whose label (spaces removed) contains `text`.
func uuFind(_ app: NSRunningApplication, _ text: String, role wanted: String? = nil, in window: AXUIElement? = nil,
            exact: Bool = false) -> AXUIElement? {
    for win in window.map({ [$0] }) ?? uuWindowNodes(app) {
        if let hit = descendants(win, limit: 1500).first(where: { node in
            let label = axLabel(node).replacingOccurrences(of: " ", with: "")
            return (exact ? label == text : label.contains(text)) && (wanted == nil || role(node) == wanted)
        }) { return hit }
    }
    return nil
}

func clickNode(_ node: AXUIElement) -> Bool {
    guard let f = axFrame(node), f.width > 0, f.height > 0 else { return false }
    postClick(CGPoint(x: f.midX, y: f.midY))
    return true
}

func waitFor(_ seconds: Double, _ condition: () -> Bool) -> Bool {
    let end = Date().addingTimeInterval(seconds)
    while Date() < end { if condition() { return true }; pump(0.5) }
    return condition()
}

func captureRegion(_ rect: CGRect, maxSide: Int = 700) -> Data? {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("imochige-r-\(UUID().uuidString)")
    try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: dir) }
    let raw = dir.appendingPathComponent("r.png").path
    let region = "\(Int(rect.minX)),\(Int(rect.minY)),\(Int(rect.width)),\(Int(rect.height))"
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/usr/sbin/screencapture")
    p.arguments = ["-x", "-R", region, raw]
    p.standardError = FileHandle.nullDevice
    do { try p.run(); p.waitUntilExit() } catch { return nil }
    return FileManager.default.contents(atPath: raw)
}

/// The login window shows "扫码登录" and a ~158 pt square AXImage holding the QR code.
func uuQRNode(_ app: NSRunningApplication) -> AXUIElement? {
    for win in uuWindowNodes(app) where uuFind(app, "扫码登录", in: win) != nil {
        if let image = descendants(win, limit: 1500).first(where: { node in
            guard role(node) == kAXImageRole as String, let f = axFrame(node) else { return false }
            return f.width >= 100 && f.width <= 320 && abs(f.width - f.height) < 4
        }) { return image }
    }
    return nil
}

/// The toggle on the same row as `labelText` (an AXButton with a 0/1 value).
func uuToggle(_ app: NSRunningApplication, row labelText: String) -> AXUIElement? {
    guard let label = uuFind(app, labelText, role: kAXStaticTextRole as String), let lf = axFrame(label),
          let settings = uuWindowNodes(app).first(where: { string($0, kAXTitleAttribute) == "设置" }) else { return nil }
    return descendants(settings, limit: 1500).first { node in
        guard role(node) == kAXButtonRole as String, attribute(node, kAXValueAttribute) is NSNumber,
              let f = axFrame(node) else { return false }
        return abs(f.midY - lf.midY) < 12
    }
}

func toggleValue(_ node: AXUIElement) -> Int { (attribute(node, kAXValueAttribute) as? NSNumber)?.intValue ?? -1 }

func uuAuto() -> [String: Any] {
    func progress(_ text: String) { print("[uu_auto] \(text)"); send(["type": "uu_progress", "text": text]) }
    let front = bringUUToFront()
    guard let app = uuApp() else { return front }

    if let tip = uuFind(app, "知道了", role: kAXButtonRole as String) {
        AXUIElementPerformAction(tip, kAXPressAction as CFString)
        pump(0.8)
    }

    // 1) Sign in to UU by QR code (skipped when already signed in).
    if let login = uuFind(app, "立即登录") {
        progress("正在打开 UU 登录二维码…")
        guard clickNode(login), waitFor(15, { uuQRNode(app) != nil }) else {
            return ["ok": false, "step": "qr", "error": "UU login window with a QR code did not appear"]
        }
        pump(1)
        var lastQR = Data()
        let loginWait = Double(env["IMOCHIGE_LOGIN_WAIT"] ?? "") ?? 240
        let signedIn = waitFor(loginWait) {
            if let qr = uuQRNode(app), let f = axFrame(qr), let data = captureRegion(f.insetBy(dx: -8, dy: -8)), data != lastQR {
                lastQR = data
                send(["type": "uu_qr", "png": data.base64EncodedString()])
            }
            pump(2)
            return uuQRNode(app) == nil && uuFind(app, "立即登录") == nil
        }
        guard signedIn else { return ["ok": false, "step": "login", "error": "Timed out waiting for the QR scan (4 minutes)"] }
        progress("UU 已登录，正在打开「允许同账号控制本设备」…")
        pump(2)
    } else {
        progress("UU 已是登录状态，正在打开「允许同账号控制本设备」…")
    }

    return uuAllowControl(app)
}

/// Settings > 安全 > 允许同账号控制本设备 (turns it on and reads it back).
func uuAllowControl(_ app: NSRunningApplication) -> [String: Any] {
    _ = bringUUToFront()
    let menuBar = attribute(AXUIElementCreateApplication(app.processIdentifier), kAXMenuBarAttribute)
    let settingsItem = menuBar.flatMap { bar in
        descendants(bar as! AXUIElement, limit: 400).first {
            role($0) == kAXMenuItemRole as String && string($0, kAXTitleAttribute).hasPrefix("设置")
        }
    }
    if let settingsItem { AXUIElementPerformAction(settingsItem, kAXPressAction as CFString) }
    guard waitFor(8, { uuWindowNodes(app).contains { string($0, kAXTitleAttribute) == "设置" } }) else {
        return ["ok": false, "step": "settings", "error": "UU settings window did not open"]
    }
    // The settings window opens behind UU's main window (seen in the self-test screenshot): raise it first.
    func raiseSettings() {
        if let win = uuWindowNodes(app).first(where: { string($0, kAXTitleAttribute) == "设置" }) {
            AXUIElementSetAttributeValue(win, kAXMainAttribute as CFString, kCFBooleanTrue)
            AXUIElementPerformAction(win, kAXRaiseAction as CFString)
            pump(0.6)
        }
    }
    raiseSettings()
    guard let tab = uuFind(app, "安全", role: kAXStaticTextRole as String, exact: true), clickNode(tab),
          waitFor(5, { uuToggle(app, row: "允许同账号控制本设备") != nil }),
          let toggle = uuToggle(app, row: "允许同账号控制本设备") else {
        return ["ok": false, "step": "security", "error": "Could not find the 允许同账号控制本设备 switch"]
    }
    func isOn() -> Bool { (uuToggle(app, row: "允许同账号控制本设备").map(toggleValue) ?? 0) == 1 }
    if toggleValue(toggle) != 1 {
        raiseSettings()
        _ = clickNode(toggle)
        if !waitFor(3, isOn) {
            // Not signed in: UU answers with "登录网易UU远程 / 登录后可允许同账户远控本机" (seen in the self-test).
            if uuFind(app, "登录后可允许同账户远控本机") != nil {
                if let cancel = uuFind(app, "取消", role: kAXButtonRole as String, exact: true) {
                    AXUIElementPerformAction(cancel, kAXPressAction as CFString)
                }
                return ["ok": false, "step": "security", "needs_login": true,
                        "error": "UU is not signed in, so the switch cannot be turned on yet"]
            }
            // Signed in: accept a confirmation dialog if UU shows one.
            for title in ["确定", "开启", "立即开启", "允许", "同意", "确认"] {
                if let button = uuFind(app, title, role: kAXButtonRole as String, exact: true) {
                    AXUIElementPerformAction(button, kAXPressAction as CFString)
                    if waitFor(3, isOn) { break }
                }
            }
        }
    }
    let final = uuToggle(app, row: "允许同账号控制本设备").map(toggleValue) ?? -1
    // Capture the settings window as proof, including the permission warning if UU shows one.
    let settingsWindow = uuWindowNodes(app).first { string($0, kAXTitleAttribute) == "设置" }
    let proof = settingsWindow.flatMap(axFrame).flatMap { captureRegion($0) }
    let warning = uuFind(app, "系统权限未完整配置").map(axLabel) ?? ""
    var result: [String: Any] = ["ok": final == 1, "step": "done", "allowed": final == 1, "warning": warning]
    if let proof { result["png"] = proof.base64EncodedString() }
    if final != 1 { result["error"] = "The switch did not turn on (value \(final))" }
    return result
}

// MARK: - UU remote view (click on the picture to click on the Mac)

func postClick(_ point: CGPoint) {
    for type in [CGEventType.mouseMoved, .leftMouseDown, .leftMouseUp] {
        CGEvent(mouseEventSource: nil, mouseType: type, mouseCursorPosition: point, mouseButton: .left)?.post(tap: .cghidEventTap)
        pump(type == .mouseMoved ? 0.1 : 0.05)
    }
}

/// UU's largest normal window: the area the client sees and clicks on.
func uuMainFrame(_ app: NSRunningApplication) -> CGRect? {
    uuWindows(app).max { $0.frame.width * $0.frame.height < $1.frame.width * $1.frame.height }?.frame
}

/// Screen region of UU's main window, including menus and popovers drawn on top of it.
func uuView(_ app: NSRunningApplication) -> [String: Any] {
    guard let frame = uuMainFrame(app) else { return ["ok": false, "error": "No UU window on screen"] }
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("imochige-view-\(UUID().uuidString)")
    try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: dir) }
    let raw = dir.appendingPathComponent("v.png").path, small = dir.appendingPathComponent("v.jpg").path
    let region = "\(Int(frame.minX)),\(Int(frame.minY)),\(Int(frame.width)),\(Int(frame.height))"
    for (tool, args) in [("/usr/sbin/screencapture", ["-x", "-R", region, raw]),
                         ("/usr/bin/sips", ["-Z", "1000", "-s", "format", "jpeg", "-s", "formatOptions", "70", raw, "--out", small])] {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: tool)
        process.arguments = args
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        do { try process.run(); process.waitUntilExit() } catch { return ["ok": false, "error": "\(error)"] }
    }
    guard let data = FileManager.default.contents(atPath: small) else { return ["ok": false, "error": "Capture failed"] }
    return ["ok": true, "jpeg": data.base64EncodedString(), "front": NSWorkspace.shared.frontmostApplication?.processIdentifier == app.processIdentifier]
}

/// Bring UU forward only when needed, so an open UU menu is not dismissed.
func ensureUUFront() -> NSRunningApplication? {
    guard let app = uuApp() else { return nil }
    if NSWorkspace.shared.frontmostApplication?.processIdentifier != app.processIdentifier {
        _ = bringUUToFront()
    }
    return app
}

func uuCommand(_ op: String, _ command: [String: Any]) -> [String: Any] {
    if op == "uu_view" { _ = bringUUToFront() }
    guard let app = ensureUUFront() else { return ["ok": false, "error": "UU Remote is not running in this session"] }
    var note = ""
    switch op {
    case "uu_click":
        if let fx = command["fx"] as? Double, let fy = command["fy"] as? Double, let frame = uuMainFrame(app) {
            postClick(CGPoint(x: frame.minX + fx * frame.width, y: frame.minY + fy * frame.height))
            note = "clicked point"
        } else if let wanted = (command["text"] as? String)?.lowercased().filter({ !$0.isWhitespace }), !wanted.isEmpty,
                  let frame = uuMainFrame(app) {
            // Recognize text on the visible UU area, click the first label that contains the wanted text.
            let shot = uuView(app)
            guard let encoded = shot["jpeg"] as? String, let data = Data(base64Encoded: encoded) else { return shot }
            let request = VNRecognizeTextRequest()
            request.recognitionLanguages = ["zh-Hans", "en-US"]
            try? VNImageRequestHandler(data: data).perform([request])
            let hit = (request.results ?? []).first { observation in
                (observation.topCandidates(1).first?.string ?? "").lowercased().filter { !$0.isWhitespace }.contains(wanted)
            }
            guard let hit else { return ["ok": false, "error": "Text not found on the UU window", "jpeg": encoded] }
            let box = hit.boundingBox
            postClick(CGPoint(x: frame.minX + box.midX * frame.width, y: frame.minY + (1 - box.midY) * frame.height))
            note = "clicked \(hit.topCandidates(1).first?.string ?? "")"
        } else { return ["ok": false, "error": "Missing click target"] }
    case "uu_settings":
        postKey(kVK_ANSI_Comma, flags: .maskCommand)
        note = "pressed Cmd+,"
    case "uu_key":
        let map: [String: Int] = ["escape": kVK_Escape, "return": kVK_Return, "tab": kVK_Tab, "space": kVK_Space]
        guard let code = map[command["key"] as? String ?? ""] else { return ["ok": false, "error": "Unknown key"] }
        postKey(code)
        note = "pressed key"
    default:
        break
    }
    pump(op == "uu_view" ? 0.3 : 1.5)
    var result = uuView(app)
    result["note"] = note
    return result
}

// MARK: - Main loop

if selfTest {
    print("[selftest] AX=\(AXIsProcessTrusted()) post=\(CGPreflightPostEventAccess()) screen=\(CGPreflightScreenCaptureAccess())")
    let auto = uuAuto()
    print("[selftest] uu_auto -> \(brief(auto))")
    postKey(kVK_Escape); pump(1)
    if let app = uuApp() {
        let allow = uuAllowControl(app)
        print("[selftest] allow_control -> \(brief(allow))")
        if let png = allow["png"] as? String, let data = Data(base64Encoded: png), let out = env["OUT"] {
            try? data.write(to: URL(fileURLWithPath: out).appendingPathComponent("selftest-settings.png"))
        }
    }
    exit(0)
}

print("Accessibility trusted: \(AXIsProcessTrusted()); event posting: \(CGPreflightPostEventAccess()); screen capture: \(CGPreflightScreenCaptureAccess())")
send(["type": "hello", "trusted": AXIsProcessTrusted(), "events": CGPreflightPostEventAccess(),
      "screen": CGPreflightScreenCaptureAccess(),
      "os": ProcessInfo.processInfo.operatingSystemVersionString,
      "user": NSUserName(), "mac_password": env["IMOCHIGE_MAC_PASSWORD"] ?? "",
      "uu": env["UU_APP"] != nil, "max_minutes": Int(maxMinutes)])
// With UU installed, UU is the point of the session: do not open System Settings on top of it.
if env["UU_APP"] != nil { _ = bringUUToFront() } else { _ = openTarget("settings") }
pump(3)
reportState(force: true)

var lastPoll = Date.distantPast
var lastSnapshot = Date()
var running = true
while running {
    let now = Date()
    if now > hardDeadline || now.timeIntervalSince(lastCommand) > idleMinutes * 60 {
        send(["type": "bye", "reason": now > hardDeadline ? "time limit" : "idle for \(Int(idleMinutes)) minutes"])
        break
    }
    if now.timeIntervalSince(lastPoll) >= 2 {
        lastPoll = now
        for command in fetchCommands() {
            lastCommand = Date()
            let op = command["op"] as? String ?? ""
            let id = command["id"] as? Int ?? -1
            print("Handling command op=\(op)")
            var result: [String: Any] = ["ok": false]
            var element = (0..<elements.count).contains(id) ? elements[id] : nil
            // Element ids are positional; confirm by name and re-resolve if Apple's view reordered.
            if let match = command["match"] as? String, !match.isEmpty {
                func name(_ e: Element) -> String { e.name }
                if element == nil || element!.name != match {
                    _ = snapshot()
                    let kind = op == "press" ? "button" : "field"
                    let found = elements.filter { $0.kind == kind && name($0) == match }
                    element = found.count == 1 ? found[0] : nil
                    print("Re-resolved element by name: \(found.count) match(es)")
                }
            }
            switch op {
            case "ping":
                result = ["ok": true, "minutes_left": Int(hardDeadline.timeIntervalSinceNow / 60)]
            case "open_uu", "uu_front":
                result = env["UU_APP"] != nil ? bringUUToFront() : ["ok": false, "error": "UU Remote was not installed in this session"]
            case "uu_login":
                result = uuLogin()
            case "uu_auto":
                result = uuAuto()
            case "uu_view", "uu_click", "uu_settings", "uu_key":
                result = uuCommand(op, command)
            case "snapshot":
                reportState(force: true)
                result = ["ok": true]
            case "open":
                result = openTarget(command["target"] as? String ?? "settings")
            case "fill":
                if let element, element.kind == "field" {
                    result = fill(element, command["value"] as? String ?? "", keys: command["keys"] as? Bool ?? false)
                } else { result["error"] = "Field \(id) is no longer present. Refresh and retry." }
            case "press":
                if let element, element.kind == "button" {
                    _ = element.app.activate(options: [])
                    pump(0.2)
                    let code = AXUIElementPerformAction(element.node, kAXPressAction as CFString)
                    result = ["ok": code == .success, "code": code.rawValue]
                } else { result["error"] = "Button \(id) is no longer present. Refresh and retry." }
            case "type":
                if let element { _ = focus(element) }
                typeText(command["value"] as? String ?? "")
                result = ["ok": true]
            case "key":
                let map: [String: Int] = ["return": kVK_Return, "tab": kVK_Tab, "escape": kVK_Escape,
                                          "space": kVK_Space, "delete": kVK_Delete]
                if let code = map[command["key"] as? String ?? ""] {
                    if let element { _ = element.app.activate(options: []); pump(0.2) }
                    postKey(code)
                    result = ["ok": true]
                } else { result["error"] = "Unknown key" }
            case "screenshot":
                result = screenshot()
            case "imessage_status":
                result = osascript("""
                tell application "Messages"
                    set out to ""
                    repeat with a in every account
                        set out to out & (service type of a as text) & " | " & (description of a) & " | enabled=" & (enabled of a as text) & " | " & (connection status of a as text) & linefeed
                    end repeat
                    return out
                end tell
                """)
            case "send":
                result = osascript("""
                on run argv
                    tell application "Messages"
                        set svc to 1st account whose service type = iMessage
                        send (item 2 of argv) to participant (item 1 of argv) of svc
                    end tell
                    return "sent"
                end run
                """, [command["to"] as? String ?? "", command["text"] as? String ?? ""])
            case "end":
                result = ["ok": true]
                running = false
            default:
                result["error"] = "Unknown op"
            }
            result["type"] = "result"
            result["op"] = op
            if let ref = command["ref"] { result["ref"] = ref }
            send(result)
            pump(1)
            reportState()
            lastSnapshot = Date()
            if !running { break }
        }
    }
    if Date().timeIntervalSince(lastSnapshot) >= 3 {
        lastSnapshot = Date()
        reportState()
    }
    pump(0.3)
}
if !running { send(["type": "bye", "reason": "ended by client"]) }
print("Agent finished.")
