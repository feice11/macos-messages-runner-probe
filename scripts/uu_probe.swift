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

print("[click] targets=\(targets.map { "\($0.2)@\(Int($0.1.x)),\(Int($0.1.y))" })")
if let t = targets.first {
    let top = windows().first { w in
        guard w[kCGWindowLayer as String] as? Int == 0, let bd = w[kCGWindowBounds as String] as? NSDictionary,
              let f = CGRect(dictionaryRepresentation: bd as CFDictionary) else { return false }
        return f.contains(t.1)
    }
    print("[click] topmost window at point: owner=\(top?[kCGWindowOwnerName as String] ?? "-") id=\(top?[kCGWindowNumber as String] ?? "-")")
    for type in [CGEventType.mouseMoved, .leftMouseDown, .leftMouseUp] {
        CGEvent(mouseEventSource: nil, mouseType: type, mouseCursorPosition: t.1, mouseButton: .left)?.post(tap: .cghidEventTap)
        pump(0.08)
    }
    for (i, wait) in [2.0, 4.0, 6.0, 10.0].enumerated() {
        pump(wait - (i == 0 ? 0 : [2.0, 4.0, 6.0, 10.0][i - 1]))
        let name = "03-after-\(Int(wait))s"
        shot(name)
        print("[after \(Int(wait))s] qr=\(qrOnScreen(name))")
    }
    dumpWindows("after")
}
