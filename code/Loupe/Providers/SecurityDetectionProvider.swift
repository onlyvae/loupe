//
//  SecurityDetectionProvider.swift
//  Loupe
//
//  Checks common jailbreak artifacts, inspects the dynamic libraries loaded
//  into this process, and verifies where selected Objective-C method
//  implementations live. These checks are read-only, and each can miss
//  indicators hidden by the sandbox or by the hooking framework itself.
//

import Foundation
import Darwin
import MachO
import ObjectiveC.runtime

struct SecurityDetectionProvider: SignalProvider {
    let category: SignalCategory = .securityDetection

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
        "/bin/sh",
        "/etc/apt",
        "/etc/apt/sources.list.d/electra.list",
        "/etc/apt/sources.list.d/sileo.sources",
        "/etc/apt/undecimus/undecimus.list",
        "/etc/ssh/sshd_config",
        "/jb/amfid_payload.dylib",
        "/jb/jailbreakd.plist",
        "/jb/libjailbreak.dylib",
        "/jb/lzma",
        "/jb/offsets.plist",
        "/private/var/Users/",
        "/private/var/cache/apt/",
        "/private/var/lib/apt",
        "/private/var/lib/cydia",
        "/private/var/log/syslog",
        "/private/var/mobile/Library/SBSettings/Themes",
        "/private/var/stash",
        "/private/var/tmp/cydia.log",
        "/var/jb",
        "/var/jb/etc/apt",
        "/var/jb/Library/Frameworks/ElleKit.framework",
        "/var/jb/Library/MobileSubstrate",
        "/var/jb/usr/bin/bash",
        "/var/jb/usr/bin/ssh",
        "/var/jb/usr/sbin/sshd",
        "/cores/jbinit.log",
        "/usr/bin/ssh",
        "/usr/bin/sshd",
        "/usr/lib/libjailbreak.dylib",
        "/usr/libexec/cydia/firmware.sh",
        "/usr/libexec/sftp-server",
        "/usr/libexec/ssh-keysign",
        "/usr/share/jailbreak/injectme.plist",
        "/usr/sbin/frida-server",
        "/usr/sbin/sshd",
        "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
        "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
        "/var/log/apt",
        "/var/lib/cydia",
        "/var/lib/dpkg/info/mobilesubstrate.md5sums",
    ]

    static let hookFrameworkMarkers = [
        "substrate",
        "frida",
        "substitute",
        "libhooker",
        "ellekit",
        "cycript",
        "captainhook",
    ]

    private struct RuntimeProbe {
        let type: AnyClass
        let selector: Selector
    }

    private struct PathMatch {
        let path: String
        let successfulProbes: [String]
    }

    private static let runtimeProbes = [
        RuntimeProbe(type: NSObject.self, selector: NSSelectorFromString("description")),
        RuntimeProbe(type: NSString.self, selector: NSSelectorFromString("length")),
        RuntimeProbe(type: NSArray.self, selector: NSSelectorFromString("count")),
        RuntimeProbe(type: NSDictionary.self, selector: NSSelectorFromString("objectForKey:")),
        RuntimeProbe(type: FileManager.self, selector: NSSelectorFromString("attributesOfItemAtPath:error:")),
        RuntimeProbe(type: ProcessInfo.self, selector: NSSelectorFromString("operatingSystemVersionString")),
    ]

    func collect() async -> [FingerprintSignal] {
        let pathMatches = knownPathMatches()
        let hookMatches = loadedHookFrameworkMatches()
        let runtimeHookMatches = objectiveCRuntimeHookMatches()

        return [
            .make(
                "knownPaths",
                category: category,
                name: String(localized: "Known jailbreak paths", comment: "Signal card name in the Security Detection category — known jailbreak filesystem paths visible to the app."),
                value: "\(pathMatches.count) / \(Self.knownPaths.count)",
                rationale: String(localized: "Any app can quietly check whether known jailbreak files are visible. A match can reveal that your \(PlatformDevice.localizedModel) has been modified.", comment: "Signal card rationale beneath Known jailbreak paths. %@ is the device model name (e.g., iPhone, iPad)."),
                displayHint: pathMatches.isEmpty ? .plain : .list,
                entries: pathMatches.isEmpty ? nil : pathMatches.map {
                    SignalEntry(label: $0.path, value: $0.successfulProbes.joined(separator: ", "))
                }),
            .make(
                "hookFrameworks",
                category: category,
                name: String(localized: "Loaded hook frameworks", comment: "Signal card name in the Security Detection category — hook or instrumentation frameworks loaded into the app process."),
                value: String(hookMatches.count),
                rationale: String(localized: "Any app can quietly inspect the libraries loaded into its own process. Names linked to Substrate, Frida, and other hook frameworks can reveal injected code. A hidden framework may not appear here.", comment: "Signal card rationale beneath Loaded hook frameworks. Explains both what a match means and the limits of this check."),
                displayHint: hookMatches.isEmpty ? .plain : .list,
                entries: hookMatches.isEmpty ? nil : hookMatches.map { SignalEntry(label: $0, value: "") }),
            .make(
                "objectiveCRuntimeHooks",
                category: category,
                name: String(localized: "Objective-C runtime hooks", comment: "Signal card name in the Security Detection category — Objective-C methods whose implementations point outside Apple's system libraries."),
                value: String(runtimeHookMatches.count),
                rationale: String(localized: "Any app can quietly check where common Objective-C methods are implemented. If an implementation points outside Apple's system libraries, another component may have replaced or redirected it. Some hooks can hide from this check.", comment: "Signal card rationale beneath Objective-C runtime hooks. Explains how method implementation addresses can reveal hooks and the limits of this check."),
                displayHint: runtimeHookMatches.isEmpty ? .plain : .keyValue,
                entries: runtimeHookMatches.isEmpty ? nil : runtimeHookMatches),
        ]
    }

    private func knownPathMatches() -> [PathMatch] {
        var seen = Set<String>()
        return Self.knownPaths.compactMap { path in
            let successfulProbes = successfulPathProbes(path)
            guard !successfulProbes.isEmpty else { return nil }
            let normalized = path.hasSuffix("/") ? String(path.dropLast()) : path
            guard seen.insert(normalized).inserted else { return nil }
            return PathMatch(path: normalized, successfulProbes: successfulProbes)
        }
    }

    /// Uses independent POSIX calls so a hook on one filesystem API does not
    /// automatically hide the path from every probe. A sandbox denial still
    /// produces no match because it is indistinguishable from an intentionally
    /// hidden path from inside a third-party app.
    private func successfulPathProbes(_ path: String) -> [String] {
        path.withCString { fileSystemPath in
            var successfulProbes: [String] = []

            var metadata = stat()
            if Darwin.lstat(fileSystemPath, &metadata) == 0 {
                successfulProbes.append("lstat")
            }

            if Darwin.access(fileSystemPath, F_OK) == 0 {
                successfulProbes.append("access")
            }

            let descriptor = Darwin.open(fileSystemPath, O_RDONLY | O_CLOEXEC)
            if descriptor >= 0 {
                successfulProbes.append("open")
                Darwin.close(descriptor)
            }

            return successfulProbes
        }
    }

    private func loadedHookFrameworkMatches() -> [String] {
        var seen = Set<String>()
        var matches: [String] = []

        for index in 0..<_dyld_image_count() {
            guard let imageName = _dyld_get_image_name(index) else { continue }
            let path = String(cString: imageName)
            let lowercasePath = path.lowercased()
            guard Self.hookFrameworkMarkers.contains(where: lowercasePath.contains),
                  seen.insert(path).inserted else { continue }
            matches.append(path)
        }

        return matches.sorted()
    }

    private func objectiveCRuntimeHookMatches() -> [SignalEntry] {
        Self.runtimeProbes.compactMap { probe -> SignalEntry? in
            guard let method = class_getInstanceMethod(probe.type, probe.selector),
                  let imagePath = imagePath(for: method_getImplementation(method)),
                  !isAppleSystemImage(imagePath) else { return nil }

            let className = NSStringFromClass(probe.type)
            let methodName = NSStringFromSelector(probe.selector)
            return SignalEntry(
                label: "\(className).\(methodName)",
                value: URL(fileURLWithPath: imagePath).lastPathComponent)
        }
        .sorted { $0.label < $1.label }
    }

    private func imagePath(for implementation: IMP) -> String? {
        var info = Dl_info()
        let address = unsafeBitCast(implementation, to: UnsafeRawPointer.self)
        guard dladdr(address, &info) != 0, let imageName = info.dli_fname else { return nil }
        return String(cString: imageName)
    }

    private func isAppleSystemImage(_ path: String) -> Bool {
        path.hasPrefix("/usr/lib/") || path.contains("/System/Library/")
    }
}
