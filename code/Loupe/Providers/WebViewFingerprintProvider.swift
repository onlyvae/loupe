//
//  WebViewFingerprintProvider.swift
//  Loupe
//
//  Hosts a hidden WKWebView and asks its JavaScript runtime for the
//  same properties a tracking script on the web would collect: user
//  agent, languages, hardwareConcurrency, deviceMemory, a 2D canvas
//  hash, and a WebGL renderer string. This makes in-app web content
//  fingerprintable the moment a WebView opens.
//

import CryptoKit
import Foundation
import WebKit

@MainActor
struct WebViewFingerprintProvider: SignalProvider {
    let category: SignalCategory = .webViewFingerprint

    func collect() async -> [FingerprintSignal] {
        let host = WebViewFingerprintHost.shared
        let payload = await host.fingerprint()

        var signals: [FingerprintSignal] = []
        signals.append(
            .make(
                "userAgent",
                category: category,
                name: String(localized: "navigator.userAgent", comment: "Signal card name in the WebView Fingerprint category — JavaScript navigator.userAgent string."),
                value: payload.userAgent,
                rationale: String(localized: "Default user agent string. Includes device class and WebKit version.", comment: "Signal card rationale beneath the navigator.userAgent value.")))
        signals.append(
            .make(
                "platform",
                category: category,
                name: String(localized: "navigator.platform", comment: "Signal card name in the WebView Fingerprint category — JavaScript navigator.platform string."),
                value: payload.platform,
                rationale: String(localized: "Platform string reported by the browser (e.g., 'iPhone', 'iPad').", comment: "Signal card rationale beneath the navigator.platform value.")))
        signals.append(
            .make(
                "languages",
                category: category,
                name: String(localized: "navigator.languages", comment: "Signal card name in the WebView Fingerprint category — JavaScript navigator.languages array."),
                value: payload.languages,
                rationale: String(localized: "Preferred languages as reported by the browser.", comment: "Signal card rationale beneath the navigator.languages value.")))
        signals.append(
            .make(
                "hardwareConcurrency",
                category: category,
                name: String(localized: "navigator.hardwareConcurrency", comment: "Signal card name in the WebView Fingerprint category — JavaScript navigator.hardwareConcurrency (logical CPU count)."),
                value: payload.hardwareConcurrency,
                rationale: String(localized: "Logical CPU core count as reported to JavaScript.", comment: "Signal card rationale beneath the navigator.hardwareConcurrency value.")))
        signals.append(
            .make(
                "deviceMemory",
                category: category,
                name: String(localized: "navigator.deviceMemory", comment: "Signal card name in the WebView Fingerprint category — JavaScript navigator.deviceMemory (approximate RAM)."),
                value: payload.deviceMemory,
                rationale: String(localized: "Approximate device memory as reported to JavaScript.", comment: "Signal card rationale beneath the navigator.deviceMemory value.")))
        signals.append(
            .make(
                "timezoneIdentifier",
                category: category,
                name: String(localized: "Time zone identifier", comment: "Signal card name in the Locale & Region category — TimeZone.identifier (e.g., 'Europe/Berlin')."),
                value: payload.timezoneIdentifier,
                rationale: String(localized: "Time zone identifier (e.g., `Europe/Berlin`).", comment: "Signal card rationale beneath the Time zone identifier value.")))
        signals.append(
            .make(
                "timezoneOffset",
                category: category,
                name: String(localized: "Date.getTimezoneOffset", comment: "Signal card name in the WebView Fingerprint category — JavaScript Date.getTimezoneOffset (minutes)."),
                value: payload.timezoneOffset,
                rationale: String(localized: "Time zone offset in minutes as reported by JavaScript.", comment: "Signal card rationale beneath the Date.getTimezoneOffset value.")))
        signals.append(
            .make(
                "screen",
                category: category,
                name: String(localized: "screen (JS)", comment: "Signal card name in the WebView Fingerprint category — JavaScript window.screen dimensions and devicePixelRatio."),
                value: payload.screen,
                rationale: String(localized: "Screen dimensions and pixel ratio as reported by JavaScript.", comment: "Signal card rationale beneath the screen (JS) value.")))
        signals.append(
            .make(
                "canvasHash",
                category: category,
                name: String(localized: "Canvas fingerprint", comment: "Signal card name in the WebView Fingerprint category — SHA-256 hash of a rendered 2D canvas."),
                value: payload.canvasHash,
                rationale: String(localized: "Hash of a rendered 2D canvas. Varies by GPU and WebKit version.", comment: "Signal card rationale beneath the Canvas fingerprint value.")))
        signals.append(
            .make(
                "webgl",
                category: category,
                name: String(localized: "WebGL renderer", comment: "Signal card name in the WebView Fingerprint category — WebGL UNMASKED_VENDOR/UNMASKED_RENDERER strings."),
                value: payload.webglRenderer,
                rationale: String(localized: "GPU renderer string reported by WebGL.", comment: "Signal card rationale beneath the WebGL renderer value.")))
        return signals
    }
}

/// Owns the hidden WKWebView. We keep a single instance to avoid the
/// ~100ms boot cost per collection.
@MainActor
final class WebViewFingerprintHost {
    static let shared = WebViewFingerprintHost()

    struct Payload: Sendable {
        var userAgent: String = "?"
        var platform: String = "?"
        var languages: String = "?"
        var hardwareConcurrency: String = "?"
        var deviceMemory: String = "?"
        var timezoneIdentifier: String = "?"
        var timezoneOffset: String = "?"
        var screen: String = "?"
        var canvasHash: String = "?"
        var webglRenderer: String = "?"
    }

    private let webView: WKWebView

    init() {
        let config = WKWebViewConfiguration()
        self.webView = WKWebView(frame: .zero, configuration: config)
    }

    func fingerprint() async -> Payload {
        var payload = Payload()
        payload.userAgent = (try? await evaluate("navigator.userAgent") as? String) ?? "?"
        payload.platform = (try? await evaluate("navigator.platform") as? String) ?? "?"
        if let langs = try? await evaluate("JSON.stringify(navigator.languages)") as? String {
            payload.languages = langs
        }
        if let cc = try? await evaluate("String(navigator.hardwareConcurrency)") as? String {
            payload.hardwareConcurrency = cc
        }
        if let dm = try? await evaluate("String(navigator.deviceMemory || 'n/a')") as? String {
            payload.deviceMemory = dm
        }
        if let tzid = try? await evaluate("String(Intl.DateTimeFormat().resolvedOptions().timeZone || 'n/a')") as? String {
            payload.timezoneIdentifier = tzid
        }
        if let tz = try? await evaluate("String(new Date().getTimezoneOffset())") as? String {
            payload.timezoneOffset = tz
        }
        if let screen = try? await evaluate(
            "JSON.stringify({w:screen.width, h:screen.height, d:window.devicePixelRatio, cd:screen.colorDepth})")
            as? String
        {
            payload.screen = screen
        }
        if let canvas = try? await canvasHash() {
            payload.canvasHash = canvas
        }
        if let gl = try? await webglRenderer() {
            payload.webglRenderer = gl
        }
        return payload
    }

    private func evaluate(_ script: String) async throws -> Any? {
        try await webView.evaluateJavaScript(script)
    }

    private func canvasHash() async throws -> String {
        let script = """
            (function(){
              var c = document.createElement('canvas');
              c.width = 200; c.height = 60;
              var g = c.getContext('2d');
              g.textBaseline = 'top';
              g.font = '14px Arial';
              g.fillStyle = '#f60';
              g.fillRect(0,0,200,60);
              g.fillStyle = '#069';
              g.fillText('Loupe, hello?', 2, 4);
              g.strokeStyle = 'rgba(100,200,0,0.7)';
              g.beginPath(); g.arc(80,30,20,0,Math.PI*2); g.stroke();
              return c.toDataURL();
            })();
            """
        guard let dataURL = try await evaluate(script) as? String else { return "?" }
        let digest = SHA256.hash(data: Data(dataURL.utf8))
        return digest.map { String(format: "%02x", $0) }.joined().prefix(32).description
    }

    private func webglRenderer() async throws -> String {
        let script = """
            (function(){
              try {
                var c = document.createElement('canvas');
                var g = c.getContext('webgl') || c.getContext('experimental-webgl');
                if (!g) return 'no-webgl';
                var ext = g.getExtension('WEBGL_debug_renderer_info');
                if (ext) {
                  return (g.getParameter(ext.UNMASKED_VENDOR_WEBGL)||'?') + ' | ' +
                         (g.getParameter(ext.UNMASKED_RENDERER_WEBGL)||'?');
                }
                return (g.getParameter(g.VENDOR)||'?') + ' | ' + (g.getParameter(g.RENDERER)||'?');
              } catch(e) { return 'err:' + e.message; }
            })();
            """
        if let s = try await evaluate(script) as? String { return s }
        return "?"
    }
}
