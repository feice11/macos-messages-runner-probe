// Evidence run: what the UU window shows, where we click, and what happens after.
// Writes screenshots to $OUT and prints every decision to the job log.
import AppKit
import ApplicationServices
import CoreGraphics
import Vision

setvbuf(stdout, nil, _IOLBF, 0)
let out = URL(fileURLWithPath: ProcessInfo.processInfo.environment["OUT"]!)
func pump(_ s: Double) { RunLoop.current.run(until: Date().addingTimeInterval(s)) }
func run(_ tool: String, _ args: [String]) {
    let p = Process(); p.executableURL = URL(fileURLWithPath: tool); p.arguments = args
    p.standardError = FileHandle.nullDevice
    try? p.run(); p.waitUntilExit()
}
func shot(_ name: String) { run("/usr/sbin/screencapture", ["-x", out.appendingPathComponent("\(name).png").path]); print("[shot] \(name)") }
func windows() -> [[String: Any]] {
    CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID) as? [[String: Any]] ?? []
}
func dumpWindows(_ tag: String) {
    print("[windows \(tag)] frontmost=\(NSWorkspace.shared.frontmostApplication?.bundleIdentifier ?? "-")")
    for w in windows() where (w[kCGWindowLayer as String] as? Int ?? 99) < 30 {
        let b = w[kCGWindowBounds as String] as? [String: Any] ?? [:]
        print("  owner=\(w[kCGWindowOwnerName as String] ?? "?") id=\(w[kCGWindowNumber as String] ?? "?") layer=\(w[kCGWindowLayer as String] ?? "?") bounds=\(b["X"] ?? 0),\(b["Y"] ?? 0),\(b["Width"] ?? 0)x\(b["Height"] ?? 0) name=\(w[kCGWindowName as String] ?? "")")
    }
}
func qrOnScreen(_ name: String) -> Bool {
    let path = out.appendingPathComponent("\(name).png")
    let r = VNDetectBarcodesRequest(); r.symbologies = [.qr]
    try? VNImageRequestHandler(url: path).perform([r])
    return r.results?.isEmpty == false
}

print("AX trusted=\(AXIsProcessTrusted()) post=\(CGPreflightPostEventAccess()) screen=\(CGPreflightScreenCaptureAccess())")
var app: NSRunningApplication?
for _ in 0..<30 {
    app = NSRunningApplication.runningApplications(withBundleIdentifier: "com.netease.uuremote").first
    if app != nil { break }; pump(1)
}
guard let app else { print("UU not running"); exit(1) }
pump(8)
dumpWindows("start"); shot("01-start")

// Bring UU forward: hide every other regular app.
for o in NSWorkspace.shared.runningApplications where o.activationPolicy == .regular && o.processIdentifier != app.processIdentifier {
    _ = o.hide()
}
_ = app.activate(options: [.activateAllWindows]); pump(2)
dumpWindows("front"); shot("02-front")

// OCR every UU window from its own capture; print all text with screen coordinates.
var targets: [(String, CGPoint, Int)] = []
for w in windows() where w[kCGWindowOwnerPID as String] as? Int32 == app.processIdentifier && w[kCGWindowLayer as String] as? Int == 0 {
    guard let id = w[kCGWindowNumber as String] as? Int,
          let bd = w[kCGWindowBounds as String] as? NSDictionary,
          let f = CGRect(dictionaryRepresentation: bd as CFDictionary) else { continue }
    let img = out.appendingPathComponent("win-\(id).png")
    run("/usr/sbin/screencapture", ["-x", "-o", "-l", String(id), img.path])
    let size = NSImage(contentsOf: img)?.representations.first.map { CGSize(width: $0.pixelsWide, height: $0.pixelsHigh) } ?? .zero
    print("[ocr] window \(id) frame=\(f) image=\(size)")
    let r = VNRecognizeTextRequest(); r.recognitionLanguages = ["zh-Hans", "en-US"]
    try? VNImageRequestHandler(url: img).perform([r])
    for o in r.results ?? [] {
        let t = o.topCandidates(1).first?.string ?? ""
        let p = CGPoint(x: f.minX + o.boundingBox.midX * f.width, y: f.minY + (1 - o.boundingBox.midY) * f.height)
        print("   '\(t)' at \(Int(p.x)),\(Int(p.y))")
        if t.replacingOccurrences(of: " ", with: "") == "立即登录" { targets.append((t, p, id)) }
    }
}

// Accessibility view of UU: does the login button exist as an element?
let root = AXUIElementCreateApplication(app.processIdentifier)
var stack = [root], seen = 0
print("[ax] tree")
while let e = stack.popLast(), seen < 300 {
    seen += 1
    func s(_ a: String) -> String { var v: CFTypeRef?; AXUIElementCopyAttributeValue(e, a as CFString, &v); return v as? String ?? "" }
    let line = [s(kAXRoleAttribute), s(kAXTitleAttribute), s(kAXDescriptionAttribute), s(kAXValueAttribute)].filter { !$0.isEmpty }
    if line.count > 1 { print("   " + line.joined(separator: " | ")) }
    var c: CFTypeRef?; AXUIElementCopyAttributeValue(e, kAXChildrenAttribute as CFString, &c)
    stack.append(contentsOf: c as? [AXUIElement] ?? [])
}


// ---- Round 2: drive everything through Accessibility geometry ----
func ax(_ e: AXUIElement, _ a: String) -> CFTypeRef? { var v: CFTypeRef?; AXUIElementCopyAttributeValue(e, a as CFString, &v); return v }
func axs(_ e: AXUIElement, _ a: String) -> String { ax(e, a) as? String ?? "" }
func frameOf(_ e: AXUIElement) -> CGRect? {
    guard let p = ax(e, kAXPositionAttribute), let z = ax(e, kAXSizeAttribute) else { return nil }
    var pt = CGPoint.zero, sz = CGSize.zero
    AXValueGetValue(p as! AXValue, .cgPoint, &pt); AXValueGetValue(z as! AXValue, .cgSize, &sz)
    return CGRect(origin: pt, size: sz)
}
func all(_ root: AXUIElement, limit: Int = 1500) -> [AXUIElement] {
    var out: [AXUIElement] = [], st = [root]
    while let e = st.popLast(), out.count < limit {
        out.append(e)
        st.append(contentsOf: ax(e, kAXChildrenAttribute) as? [AXUIElement] ?? [])
    }
    return out
}
func label(_ e: AXUIElement) -> String { [axs(e, kAXTitleAttribute), axs(e, kAXValueAttribute), axs(e, kAXDescriptionAttribute)].first { !$0.isEmpty } ?? "" }
func windowsOnly(_ root: AXUIElement) -> [AXUIElement] { ax(root, kAXWindowsAttribute) as? [AXUIElement] ?? [] }
func dumpAX(_ tag: String) {
    print("[ax \(tag)]")
    for (i, w) in windowsOnly(root).enumerated() {
        print("  window \(i) '\(axs(w, kAXTitleAttribute))' frame=\(frameOf(w).map { "\($0)" } ?? "-")")
        for e in all(w) {
            let r = axs(e, kAXRoleAttribute), l = label(e)
            if r == kAXGroupRole as String && l.isEmpty { continue }
            if ["AXScrollArea", "AXSplitGroup", "AXLayoutArea"].contains(r) && l.isEmpty { continue }
            let v = ax(e, kAXValueAttribute).map { "\($0)" } ?? ""
            print("    \(r) '\(l)' val=\(v.prefix(20)) frame=\(frameOf(e).map { "\(Int($0.midX)),\(Int($0.midY)) \(Int($0.width))x\(Int($0.height))" } ?? "-") enabled=\(ax(e, kAXEnabledAttribute) as? Bool ?? true)")
        }
    }
}
func find(_ text: String, roles: [String]? = nil) -> AXUIElement? {
    all(root).first { e in
        label(e).replacingOccurrences(of: " ", with: "").contains(text) && (roles == nil || roles!.contains(axs(e, kAXRoleAttribute)))
    }
}
func click(_ p: CGPoint) {
    for t in [CGEventType.mouseMoved, .leftMouseDown, .leftMouseUp] {
        CGEvent(mouseEventSource: nil, mouseType: t, mouseCursorPosition: p, mouseButton: .left)?.post(tap: .cghidEventTap); pump(0.08)
    }
}
func clickAX(_ e: AXUIElement, _ why: String) {
    if let f = frameOf(e) { print("[click] \(why) at \(Int(f.midX)),\(Int(f.midY))"); click(CGPoint(x: f.midX, y: f.midY)) }
    else { print("[click] \(why): no frame, AXPress=\(AXUIElementPerformAction(e, kAXPressAction as CFString).rawValue)") }
}

if let ok = find("知道了", roles: [kAXButtonRole as String]) {
    print("[tip] AXPress 知道了 -> \(AXUIElementPerformAction(ok, kAXPressAction as CFString).rawValue)"); pump(1)
}
dumpWindows("after-tip")
if let login = find("立即登录") {
    clickAX(login, "立即登录")
    for wait in [3.0, 5.0, 8.0] {
        pump(wait == 3 ? 3 : (wait == 5 ? 2 : 3))
        let n = "04-login-\(Int(wait))s"; shot(n); print("[login \(Int(wait))s] qr=\(qrOnScreen(n))")
    }
    dumpWindows("login"); dumpAX("login")
} else { print("[login] 立即登录 not found in AX") }

// Close whatever the login opened, then open Settings through the app menu.
CGEvent(keyboardEventSource: nil, virtualKey: 0x35, keyDown: true)?.post(tap: .cghidEventTap)
CGEvent(keyboardEventSource: nil, virtualKey: 0x35, keyDown: false)?.post(tap: .cghidEventTap); pump(1)
let menuBar = ax(root, kAXMenuBarAttribute).map { $0 as! AXUIElement }
let settingsItem = menuBar.flatMap { mb in all(mb).first { axs($0, kAXRoleAttribute) == kAXMenuItemRole as String && axs($0, kAXTitleAttribute).hasPrefix("设置") } }
print("[settings] menu item found=\(settingsItem != nil) press=\(settingsItem.map { AXUIElementPerformAction($0, kAXPressAction as CFString).rawValue } ?? -1)")
pump(3); shot("05-settings"); dumpWindows("settings"); dumpAX("settings")
if let security = find("安全", roles: [kAXStaticTextRole as String, kAXButtonRole as String, "AXCell", "AXRow"]) {
    clickAX(security, "安全"); pump(2); shot("06-security"); dumpAX("security")
} else { print("[settings] 安全 not found") }
