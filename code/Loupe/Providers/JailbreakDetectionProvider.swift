//
//  JailbreakDetectionProvider.swift
//  Loupe
//
//  Checks common jailbreak artifacts using the same read-only file lookup
//  available to any third-party app. The sandbox may hide paths that exist.
//

import Foundation

struct JailbreakDetectionProvider: SignalProvider {
    let category: SignalCategory = .jailbreakDetection

    static let knownPaths = [
        "/.bootstrapped_electra",
        "/.cydia_no_stash",
        "/.installed_unc0ver",
        "/Applications/Cydia.app",
        "/Applications/FakeCarrier.app",
        "/Applications/Icy.app",
        "/Applications/IntelliScreen.app",
        "/Applications/MxTube.app",
        "/Applications/RockApp.app",
        "/Applications/SBSettings.app",
        "/Applications/WinterBoard.app",
        "/Applications/blackra1n.app",
        "/Library/MobileSubstrate/CydiaSubstrate.dylib",
        "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
        "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/bin/bash",
        "/etc/apt",
        "/etc/apt/sources.list.d/electra.list",
        "/etc/apt/sources.list.d/sileo.sources",
        "/etc/apt/undecimus/undecimus.list",
        "/private/var/lib/apt",
        "/private/var/lib/apt/",
        "/private/var/lib/cydia",
        "/private/var/mobile/Library/SBSettings/Themes",
        "/private/var/stash",
        "/usr/bin/ssh",
        "/usr/libexec/sftp-server",
        "/usr/sbin/frida-server",
        "/usr/sbin/sshd",
        "/var/lib/cydia",
        "/var/lib/dpkg/info/mobilesubstrate.md5sums",
    ]

    func collect() async -> [FingerprintSignal] {
        var seen = Set<String>()
        let matches = Self.knownPaths.compactMap { path -> String? in
            guard FileManager.default.fileExists(atPath: path) else { return nil }
            let normalized = path.hasSuffix("/") ? String(path.dropLast()) : path
            return seen.insert(normalized).inserted ? normalized : nil
        }

        return [
            .make(
                "knownPaths",
                category: category,
                name: String(localized: "Known jailbreak paths", comment: "Signal card name in the Jailbreak Detection category — known jailbreak filesystem paths visible to the app."),
                value: "\(matches.count) / \(Self.knownPaths.count)",
                rationale: String(localized: "Any app can quietly check whether known jailbreak files are visible. A match can reveal that your \(PlatformDevice.localizedModel) has been modified.", comment: "Signal card rationale beneath Known jailbreak paths. %@ is the device model name (e.g., iPhone, iPad)."),
                displayHint: matches.isEmpty ? .plain : .tags,
                entries: matches.isEmpty ? nil : matches.map { SignalEntry(label: $0, value: "") })
        ]
    }
}
