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
import UIKit

private let loupeDyldImageLock = NSLock()
nonisolated(unsafe) private var loupeDyldImageHeaders: [UInt: Int] = [:]

private func loupeRecordAddedImage(
    _ header: UnsafePointer<mach_header>?,
    _ slide: Int
) {
    guard let header else { return }
    loupeDyldImageLock.lock()
    loupeDyldImageHeaders[UInt(bitPattern: header)] = slide
    loupeDyldImageLock.unlock()
}

struct SecurityDetectionProvider: SignalProvider {
    let category: SignalCategory = .securityDetection

    private enum DebuggerState {
        case attached(Bool)
        case unavailable(Int32)

        var displayValue: String {
            switch self {
            case let .attached(isAttached):
                return isAttached ? "true" : "false"
            case let .unavailable(errorNumber):
                return "errno \(errorNumber)"
            }
        }

        var details: [SignalEntry]? {
            guard case let .unavailable(errorNumber) = self else { return nil }
            return [SignalEntry(label: "errno", value: String(errorNumber))]
        }
    }

    /// A debugger attached through ptrace marks the process with `P_TRACED`.
    /// Reading that flag detects the current state without changing it.
    private static func debuggerState() -> DebuggerState {
        var processInfo = kinfo_proc()
        var processInfoSize = MemoryLayout<kinfo_proc>.stride
        var mib = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]

        errno = 0
        let result = sysctl(&mib, u_int(mib.count), &processInfo, &processInfoSize, nil, 0)
        guard result == 0 else { return .unavailable(errno) }
        return .attached((processInfo.kp_proc.p_flag & P_TRACED) != 0)
    }

    /// Reads the variable directly from the process environment. A present
    /// value means the dynamic linker was asked to load additional libraries
    /// when this process launched.
    private static func insertedLibrariesValue() -> String? {
        getenv("DYLD_INSERT_LIBRARIES").map { String(cString: $0) }
    }

    /// dyld may remove DYLD_* variables before app code starts. Libraries
    /// loaded from outside the app bundle and outside the shared cache provide
    /// a second, indirect signal that DYLD_INSERT_LIBRARIES was used.
    private static func insertedLibraryCandidates() -> [String] {
        let bundlePath = Bundle.main.bundlePath + "/"
        var candidates = Set<String>()

        // Image zero is the main executable, which is never in the shared
        // cache and must not be treated as an injected library.
        for index in 1..<_dyld_image_count() {
            guard let imageName = _dyld_get_image_name(index) else { continue }
            let path = String(cString: imageName)
            guard path.hasSuffix(".dylib"),
                  URL(fileURLWithPath: path).lastPathComponent != "libobjc-trampolines.dylib",
                  !path.hasPrefix(bundlePath) else { continue }

            let isInSharedCache = path.withCString {
                _dyld_shared_cache_contains_path($0)
            }
            if !isInSharedCache {
                candidates.insert(path)
            }
        }

        return candidates.sorted()
    }

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
        "systemhook",
    ]

    private static let fridaImageMarkers = [
        "frida",
        "fridagadget",
    ]

    private static let fridaPaths = [
        "/Library/Frida/FridaGadget.dylib",
        "/Library/Frida/frida-gadget.config",
        "/usr/sbin/frida-server",
        "/usr/local/bin/frida-server",
        "/var/jb/Library/Frida/FridaGadget.dylib",
        "/var/jb/Library/Frida/frida-gadget.config",
        "/var/jb/usr/sbin/frida-server",
    ]

    private struct RuntimeProbe {
        let type: AnyClass
        let selector: Selector
    }

    private struct PathMatch {
        let path: String
        let successfulProbes: [String]
    }

    private struct RuntimeProbeResult {
        let detail: SignalEntry
        let suspiciousEntry: SignalEntry?
    }

    struct CrashReporterAnnotation {
        let imagePath: String
        let version: UInt64
        let field: String
        let message: String
    }

    private struct OSVersionReading {
        let source: String
        let rawValue: String
        let version: OperatingSystemVersion
    }

    private struct OSVersionConsistencyResult {
        let details: [SignalEntry]
        let mismatches: [SignalEntry]
    }

    /// objc4 stores the method representation in the low two bits of a
    /// `Method` pointer. The remaining bits can include pointer-authentication
    /// data, while iOS user-space addresses fit in the low 47 bits.
    private static let objectiveCPointerAddressMask: UInt = 0x0000_7fff_ffff_ffff

    /// CrashReporterClient stores its annotations in a Mach-O section with
    /// this name. The first five fields of versions 4, 5, and 7 share the
    /// same layout: version, message, signature, backtrace, and message2.
    private static let crashInfoSectionName = "__crash_info"
    private static let supportedCrashInfoVersions: Set<UInt64> = [4, 5, 7]
    private static let maximumCrashReporterMessageLength = 4_096

    private static let runtimeProbes = [
        RuntimeProbe(type: ProcessInfo.self, selector: NSSelectorFromString("isOperatingSystemAtLeastVersion:")),
        RuntimeProbe(type: ProcessInfo.self, selector: NSSelectorFromString("operatingSystemVersion")),
        RuntimeProbe(type: ProcessInfo.self, selector: NSSelectorFromString("operatingSystemVersionString")),
        RuntimeProbe(type: ProcessInfo.self, selector: NSSelectorFromString("environment")),
        RuntimeProbe(type: UIDevice.self, selector: NSSelectorFromString("systemVersion")),
    ]

    private static let hookSensitiveAPISymbols = [
        "getenv",
        "_dyld_image_count",
        "_dyld_get_image_name",
        "_dyld_get_image_header",
        "_dyld_get_image_vmaddr_slide",
        "objc_copyImageNames",
        "mach_vm_region",
        "mach_vm_region_recurse",
        "class_getMethodImplementation",
        "method_getImplementation",
        "object_getMethodImplementation",
        "task_threads",
    ]

    private static let hookRuntimeSymbols = [
        "MSHookFunction",
        "MSHookMessageEx",
        "SubstrateHookFunction",
        "LHHookFunctions",
        "LHHookMessage",
        "EKHookFunction",
    ]

    private static let installDyldImageCallback: Void = {
        _dyld_register_func_for_add_image(loupeRecordAddedImage)
    }()

    func collect() async -> [FingerprintSignal] {
        let debuggerState = Self.debuggerState()
        let insertedLibrariesValue = Self.insertedLibrariesValue()
        let insertedLibraryCandidates = Self.insertedLibraryCandidates()
        let crashReporterAnnotations = Self.crashReporterAnnotations()
        let runtimeImageReport = RuntimeImageReport.capture(
            annotationMessages: crashReporterAnnotations.map(\.message))
        let crashReporterDyldConfiguration = crashReporterAnnotations.filter {
            $0.message.contains("DYLD_INSERT_LIBRARIES=")
        }
        let pathMatches = knownPathMatches()
        let hookMatches = loadedHookFrameworkMatches(in: runtimeImageReport.images)
            + hookRuntimeSymbolMatches()
        let tweakPluginMatches = loadedTweakPluginMatches(in: runtimeImageReport.images)
            + hiddenRuntimeMetadataMatches()
        let fridaMatches = fridaIndicatorMatches(in: runtimeImageReport.images)
        let osVersionConsistency = operatingSystemVersionConsistency()
        let runtimeProbeResults = objectiveCRuntimeProbeResults()
        let runtimeHookMatches = runtimeProbeResults.compactMap(\.suspiciousEntry)

        var signals: [FingerprintSignal] = [
            .make(
                "debuggerAttached",
                category: category,
                name: String(localized: "Debugger attached", comment: "Signal card name in the Security Detection category — whether a debugger is currently tracing the app process."),
                value: debuggerState.displayValue,
                rationale: String(localized: "This read-only check shows whether the app process is being traced. The system sets `P_TRACED` when a debugger attaches through `ptrace`.", comment: "Signal card rationale beneath Debugger attached. Explains that the read-only check detects the P_TRACED process flag set by ptrace-based debugging."),
                details: debuggerState.details),
            .make(
                "dyldInsertLibraries",
                category: category,
                name: String(localized: "Launch-time library injection", comment: "Signal card name in the Security Detection category for evidence that libraries were injected when the app launched."),
                value: insertedLibrariesValue == nil
                    && insertedLibraryCandidates.isEmpty
                    && crashReporterDyldConfiguration.isEmpty ? "false" : "true",
                rationale: String(localized: "Any app can quietly check whether `DYLD_INSERT_LIBRARIES` is set for its process. A value can reveal that extra libraries were injected when the app launched.", comment: "Signal card rationale beneath DYLD_INSERT_LIBRARIES. Explains that the environment variable requests library injection at process launch."),
                details: insertedLibraryDetails(
                    environmentValue: insertedLibrariesValue,
                    candidates: insertedLibraryCandidates,
                    crashReporterAnnotations: crashReporterDyldConfiguration)),
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
                "tweakPlugins",
                category: category,
                name: String(localized: "Tweak plug-ins", comment: "Signal card name in the Security Detection category for Tweak plug-ins currently loaded into the app process."),
                value: String(tweakPluginMatches.count),
                rationale: String(localized: "Any app can quietly inspect the libraries loaded into its own process. Names linked to Substrate, Frida, and other hook frameworks can reveal injected code. A hidden framework may not appear here.", comment: "Signal card rationale beneath Loaded hook frameworks. Explains both what a match means and the limits of this check."),
                displayHint: tweakPluginMatches.isEmpty ? .plain : .list,
                entries: tweakPluginMatches.isEmpty ? nil : tweakPluginMatches),
            .make(
                "fridaIndicators",
                category: category,
                name: String(localized: "Frida indicators", comment: "Signal card name in the Security Detection category — evidence that Frida instrumentation may be attached to the app."),
                value: String(fridaMatches.count),
                rationale: String(localized: "Any app can quietly check for Frida-related files and loaded code, modified entry points, and unusual executable memory. These signs can have other causes, and Frida can hide them, so this check is not proof either way.", comment: "Signal card rationale beneath Frida indicators. Explains the local checks, possible false positives, and that they cannot rule out a hidden Frida installation."),
                displayHint: fridaMatches.isEmpty ? .plain : .keyValue,
                entries: fridaMatches.isEmpty ? nil : fridaMatches),
            .make(
                "osVersionConsistency",
                category: category,
                name: String(localized: "OS version consistency", comment: "Signal card name in the Security Detection category — whether independent operating-system version readings agree."),
                value: String(osVersionConsistency.mismatches.count),
                rationale: String(localized: "Any app can quietly read your operating system version in several ways. If those readings disagree, one path may have been replaced or filtered. Each source can still be hooked.", comment: "Signal card rationale beneath OS version consistency. Explains that comparing independent version sources can reveal selective hooks, while all sources remain bypassable."),
                displayHint: osVersionConsistency.mismatches.isEmpty ? .plain : .keyValue,
                entries: osVersionConsistency.mismatches.isEmpty ? nil : osVersionConsistency.mismatches,
                details: osVersionConsistency.details),
            .make(
                "objectiveCRuntimeHooks",
                category: category,
                name: String(localized: "Objective-C IMP redirections", comment: "Signal card name in the Security Detection category — Objective-C methods whose IMP addresses point outside the executable range of their class's host image."),
                value: String(runtimeHookMatches.count),
                rationale: String(localized: "Any app can quietly check where common Objective-C methods are implemented. If an implementation falls outside its class's own image, another component may have replaced or redirected it. Some hooks can hide from this check.", comment: "Signal card rationale beneath Objective-C IMP redirections. Explains how comparing an implementation address with its class's host image can reveal hooks, and notes the limits of the check."),
                displayHint: runtimeHookMatches.isEmpty ? .plain : .keyValue,
                entries: runtimeHookMatches.isEmpty ? nil : runtimeHookMatches,
                details: runtimeProbeResults.map(\.detail)),
        ]

        if !crashReporterAnnotations.isEmpty {
            signals.insert(
                .make(
                    "crashReporterAnnotations",
                    category: category,
                    name: String(localized: "CrashReporter annotations", comment: "Signal card name in the Security Detection category — messages embedded by loaded Mach-O images for inclusion in a future crash report. CrashReporter is a system component name and must not be translated."),
                    value: String(crashReporterAnnotations.count),
                    rationale: String(localized: "Any app can quietly read CrashReporter messages in its own loaded code. The dynamic linker records accepted `DYLD_*` settings here, even if they are later removed from the process environment.", comment: "Signal card rationale beneath CrashReporter annotations. Explains that dyld leaves accepted DYLD environment settings in in-process crash-report annotations."),
                    displayHint: .list,
                    entries: crashReporterAnnotations.map {
                        SignalEntry(
                            label: "\($0.imagePath) · \($0.field) · v\($0.version)",
                            value: $0.message)
                    }),
                at: 2)
        }

        return signals
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

    private func insertedLibraryDetails(
        environmentValue: String?,
        candidates: [String],
        crashReporterAnnotations: [CrashReporterAnnotation]
    ) -> [SignalEntry]? {
        var details = environmentValue.map {
            [SignalEntry(label: "DYLD_INSERT_LIBRARIES", value: $0)]
        } ?? []
        details.append(contentsOf: candidates.map {
            SignalEntry(label: "loaded image outside shared cache", value: $0)
        })
        details.append(contentsOf: crashReporterAnnotations.map {
            SignalEntry(label: "CrashReporter \($0.field)", value: $0.message)
        })
        return details.isEmpty ? nil : details
    }

    /// Reads CrashReporterClient annotations directly from the `__crash_info`
    /// section of every Mach-O image loaded into this process. This is the
    /// same in-process data that ReportCrash later copies into crash_info_N
    /// fields. dyld uses message2 to retain accepted DYLD_* launch settings.
    static func crashReporterAnnotations() -> [CrashReporterAnnotation] {
        var annotations: [CrashReporterAnnotation] = []
        var images: [(header: UnsafePointer<mach_header>, path: String, slide: Int)] = []

        for imageIndex in 0..<_dyld_image_count() {
            guard let header = _dyld_get_image_header(imageIndex),
                  let imageName = _dyld_get_image_name(imageIndex) else { continue }
            images.append((
                header: header,
                path: String(cString: imageName),
                slide: _dyld_get_image_vmaddr_slide(imageIndex)))
        }

        // dyld is the component that records the launch configuration, but
        // it deliberately does not appear in _dyld_image_count(). Resolve a
        // public dyld function back to its host image and scan that header too.
        if let dyldImage = dyldImage(),
           !images.contains(where: { $0.header == dyldImage.header }) {
            images.append(dyldImage)
        }

        for image in images {
            let header = image.header
            guard header.pointee.magic == MH_MAGIC_64 else { continue }
            let imagePath = image.path
            let slide = image.slide
            var commandPointer = UnsafeRawPointer(header)
                .advanced(by: MemoryLayout<mach_header_64>.size)
            let commandsEnd = commandPointer.advanced(by: Int(header.pointee.sizeofcmds))

            for _ in 0..<header.pointee.ncmds {
                guard commandPointer.advanced(by: MemoryLayout<load_command>.size) <= commandsEnd else { break }
                let loadCommand = commandPointer.load(as: load_command.self)
                guard loadCommand.cmdsize >= MemoryLayout<load_command>.size,
                      commandPointer.advanced(by: Int(loadCommand.cmdsize)) <= commandsEnd else { break }
                defer { commandPointer = commandPointer.advanced(by: Int(loadCommand.cmdsize)) }
                guard loadCommand.cmd == LC_SEGMENT_64,
                      loadCommand.cmdsize >= MemoryLayout<segment_command_64>.size else { continue }

                let segment = commandPointer.load(as: segment_command_64.self)
                let sectionsSize = Int(segment.nsects) * MemoryLayout<section_64>.stride
                guard sectionsSize <= Int(loadCommand.cmdsize) - MemoryLayout<segment_command_64>.size else { continue }

                var sectionPointer = commandPointer.advanced(by: MemoryLayout<segment_command_64>.size)
                for _ in 0..<segment.nsects {
                    let section = sectionPointer.load(as: section_64.self)
                    sectionPointer = sectionPointer.advanced(by: MemoryLayout<section_64>.stride)
                    guard fixedMachOName(section.sectname) == crashInfoSectionName,
                          section.size >= 5 * MemoryLayout<UInt64>.size,
                          let sectionAddress = slidAddress(section.addr, slide: slide),
                          readableByteCount(from: sectionAddress) >= 5 * MemoryLayout<UInt64>.size else { continue }

                    let version = sectionAddress.load(as: UInt64.self)
                    guard supportedCrashInfoVersions.contains(version) else { continue }
                    let messageAddress = sectionAddress.load(fromByteOffset: MemoryLayout<UInt64>.size, as: UInt64.self)
                    let message2Address = sectionAddress.load(fromByteOffset: 4 * MemoryLayout<UInt64>.size, as: UInt64.self)

                    if let message = crashReporterString(at: messageAddress) {
                        annotations.append(CrashReporterAnnotation(
                            imagePath: imagePath,
                            version: version,
                            field: "message",
                            message: message))
                    }
                    if let message = crashReporterString(at: message2Address) {
                        annotations.append(CrashReporterAnnotation(
                            imagePath: imagePath,
                            version: version,
                            field: "message2",
                            message: message))
                    }
                }
            }
        }

        return annotations
    }

    private static func dyldImage() -> (
        header: UnsafePointer<mach_header>,
        path: String,
        slide: Int
    )? {
        // `_dyld_image_count` can resolve to the libdyld entry layer on
        // recent iOS releases. The actual dyld image is deliberately absent
        // from that list, so ask the kernel for dyld_all_image_infos and use
        // its dyldImageLoadAddress, the same route used by crash reporters.
        var taskDyldInfo = task_dyld_info_data_t()
        var taskDyldInfoCount = mach_msg_type_number_t(
            MemoryLayout<task_dyld_info_data_t>.size / MemoryLayout<natural_t>.size)
        let taskInfoResult = withUnsafeMutablePointer(to: &taskDyldInfo) { infoPointer in
            infoPointer.withMemoryRebound(to: integer_t.self, capacity: Int(taskDyldInfoCount)) {
                task_info(
                    mach_task_self_,
                    task_flavor_t(TASK_DYLD_INFO),
                    $0,
                    &taskDyldInfoCount)
            }
        }
        if taskInfoResult == KERN_SUCCESS,
           let allImageInfos = UnsafePointer<dyld_all_image_infos>(
               bitPattern: UInt(taskDyldInfo.all_image_info_addr)),
           let header = allImageInfos.pointee.dyldImageLoadAddress,
           let slide = imageSlide(for: header) {
            var info = Dl_info()
            let path: String
            if dladdr(UnsafeRawPointer(header), &info) != 0,
               let imagePath = info.dli_fname {
                path = String(cString: imagePath)
            } else {
                path = "/usr/lib/dyld"
            }
            return (header, path, slide)
        }

        // Compatibility fallback for systems where the public dyld entry
        // point still resolves directly into the dyld image.
        guard let functionAddress = dlsym(
            UnsafeMutableRawPointer(bitPattern: -2),
            "_dyld_image_count"
        ) else { return nil }
        var info = Dl_info()
        guard dladdr(functionAddress, &info) != 0,
              let imageBase = info.dli_fbase,
              let imagePath = info.dli_fname else { return nil }
        let header = UnsafePointer(imageBase.assumingMemoryBound(to: mach_header.self))
        guard let slide = imageSlide(for: header) else { return nil }
        return (header, String(cString: imagePath), slide)
    }

    private static func imageSlide(for header: UnsafePointer<mach_header>) -> Int? {
        guard header.pointee.magic == MH_MAGIC_64 else { return nil }
        var commandPointer = UnsafeRawPointer(header)
            .advanced(by: MemoryLayout<mach_header_64>.size)

        for _ in 0..<header.pointee.ncmds {
            let loadCommand = commandPointer.load(as: load_command.self)
            guard loadCommand.cmdsize >= MemoryLayout<load_command>.size else { return nil }
            defer { commandPointer = commandPointer.advanced(by: Int(loadCommand.cmdsize)) }
            guard loadCommand.cmd == LC_SEGMENT_64 else { continue }
            let segment = commandPointer.load(as: segment_command_64.self)
            guard fixedMachOName(segment.segname) == "__TEXT",
                  let preferredAddress = UInt(exactly: segment.vmaddr) else { continue }
            let runtimeAddress = UInt(bitPattern: header)
            let difference = runtimeAddress.subtractingReportingOverflow(preferredAddress)
            guard !difference.overflow, difference.partialValue <= UInt(Int.max) else { return nil }
            return Int(difference.partialValue)
        }
        return nil
    }

    private static func fixedMachOName<T>(_ value: T) -> String {
        var value = value
        return withUnsafeBytes(of: &value) { bytes in
            let end = bytes.firstIndex(of: 0) ?? bytes.endIndex
            return String(decoding: bytes[..<end], as: UTF8.self)
        }
    }

    private static func slidAddress(_ address: UInt64, slide: Int) -> UnsafeRawPointer? {
        guard let base = UInt(exactly: address) else { return nil }
        let result: (partialValue: UInt, overflow: Bool)
        if slide >= 0 {
            result = base.addingReportingOverflow(UInt(slide))
        } else {
            result = base.subtractingReportingOverflow(UInt(-Int64(slide)))
        }
        guard !result.overflow else { return nil }
        return UnsafeRawPointer(bitPattern: result.partialValue)
    }

    private static func crashReporterString(at rawAddress: UInt64) -> String? {
        guard rawAddress != 0,
              let address = UnsafeRawPointer(bitPattern: UInt(rawAddress) & objectiveCPointerAddressMask) else { return nil }
        let readableCount = min(readableByteCount(from: address), maximumCrashReporterMessageLength)
        guard readableCount > 0 else { return nil }

        let bytes = address.assumingMemoryBound(to: UInt8.self)
        var length = 0
        while length < readableCount, bytes[length] != 0 {
            length += 1
        }
        guard length > 0 else { return nil }
        return String(decoding: UnsafeBufferPointer(start: bytes, count: length), as: UTF8.self)
    }

    private static func readableByteCount(from pointer: UnsafeRawPointer) -> Int {
        let requestedAddress = vm_address_t(UInt(bitPattern: pointer))
        var regionAddress = requestedAddress
        var regionSize: vm_size_t = 0
        var info = vm_region_basic_info_data_64_t()
        var infoCount = mach_msg_type_number_t(
            MemoryLayout<vm_region_basic_info_data_64_t>.size / MemoryLayout<integer_t>.size)
        var objectName = mach_port_t(MACH_PORT_NULL)

        let result = withUnsafeMutablePointer(to: &info) { infoPointer in
            infoPointer.withMemoryRebound(to: integer_t.self, capacity: Int(infoCount)) {
                vm_region_64(
                    mach_task_self_,
                    &regionAddress,
                    &regionSize,
                    VM_REGION_BASIC_INFO_64,
                    $0,
                    &infoCount,
                    &objectName)
            }
        }
        if objectName != MACH_PORT_NULL {
            mach_port_deallocate(mach_task_self_, objectName)
        }
        guard result == KERN_SUCCESS,
              (info.protection & VM_PROT_READ) != 0,
              requestedAddress >= regionAddress,
              requestedAddress - regionAddress < regionSize else { return 0 }
        return Int(regionSize - (requestedAddress - regionAddress))
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

    private func loadedHookFrameworkMatches(
        in images: [RuntimeImageReport.Image]
    ) -> [String] {
        var seen = Set<String>()
        var matches: [String] = []

        for image in images {
            let lowercasePath = image.path.lowercased()
            guard Self.hookFrameworkMarkers.contains(where: lowercasePath.contains),
                  seen.insert(image.path).inserted else { continue }
            matches.append(image.path)
        }

        return matches.sorted()
    }

    private func loadedTweakPluginMatches(
        in images: [RuntimeImageReport.Image]
    ) -> [SignalEntry] {
        let directoryMarkers = [
            "/tweakinject/",
            "/mobilesubstrate/dynamiclibraries/",
        ]
        var seen = Set<String>()
        return images.compactMap { image in
            let lowercasePath = image.path.lowercased()
            guard directoryMarkers.contains(where: lowercasePath.contains),
                  seen.insert(image.path).inserted else { return nil }
            let source = image.source == .hiddenVM ? "VM mapping" : "dyld"
            return SignalEntry(label: image.name, value: "\(image.path)\n\(source) · \(image.uuid)")
        }.sorted { $0.label.localizedStandardCompare($1.label) == .orderedAscending }
    }

    /// Hook frameworks can remain reachable through the dynamic symbol table
    /// even when their Mach-O image is removed from dyld's public image list.
    private func hookRuntimeSymbolMatches() -> [String] {
        var matches = Set<String>()
        for symbol in Self.hookRuntimeSymbols {
            guard let address = dlsym(UnsafeMutableRawPointer(bitPattern: -2), symbol) else {
                continue
            }
            let info = dynamicLinkerInfo(for: UnsafeRawPointer(address))
            let owner = info.imagePath ?? pointerString(UnsafeRawPointer(address))
            matches.insert("\(symbol) → \(owner)")
        }
        return matches.sorted()
    }

    /// Cross-checks three runtime registries that are independent of the
    /// public dyld index APIs: TASK_DYLD_INFO, dyld add-image callbacks, and
    /// Objective-C's registered class table.
    private func hiddenRuntimeMetadataMatches() -> [SignalEntry] {
        var matches = Set<SignalEntry>()
        let publicHeaders = Set((0..<_dyld_image_count()).compactMap { index in
            _dyld_get_image_header(index).map { UInt(bitPattern: $0) }
        })

        for image in rawTaskDyldImages()
        where !publicHeaders.contains(image.header) && isSuspiciousRuntimeImagePath(image.path) {
            matches.insert(SignalEntry(
                label: "TASK_DYLD_INFO",
                value: "\(image.path)\n0x\(String(image.header, radix: 16))"))
        }

        for image in registeredDyldImages()
        where !publicHeaders.contains(image.header) && isSuspiciousRuntimeImagePath(image.path) {
            matches.insert(SignalEntry(
                label: "dyld add-image callback",
                value: "\(image.path)\n0x\(String(image.header, radix: 16))"))
        }

        let requestedClassCount = objc_getClassList(nil, 0)
        if requestedClassCount > 0 {
            let classes = UnsafeMutablePointer<AnyClass?>.allocate(
                capacity: Int(requestedClassCount))
            defer { classes.deallocate() }
            let classCount = objc_getClassList(
                AutoreleasingUnsafeMutablePointer<AnyClass>(classes),
                requestedClassCount)
            let populatedClassCount = min(classCount, requestedClassCount)
            for index in 0..<Int(populatedClassCount) {
                guard let type = classes[index] else { continue }
                guard let imageName = class_getImageName(type) else { continue }
                let path = String(cString: imageName)
                guard isSuspiciousRuntimeImagePath(path) else { continue }
                matches.insert(SignalEntry(
                    label: "Objective-C class · \(NSStringFromClass(type))",
                    value: path))
            }
        }

        return matches.sorted {
            $0.label == $1.label ? $0.value < $1.value : $0.label < $1.label
        }
    }

    private func rawTaskDyldImages() -> [(header: UInt, path: String)] {
        var taskDyldInfo = task_dyld_info_data_t()
        var count = mach_msg_type_number_t(
            MemoryLayout<task_dyld_info_data_t>.size / MemoryLayout<natural_t>.size)
        let result = withUnsafeMutablePointer(to: &taskDyldInfo) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(
                    mach_task_self_,
                    task_flavor_t(TASK_DYLD_INFO),
                    $0,
                    &count)
            }
        }
        guard result == KERN_SUCCESS,
              taskDyldInfo.all_image_info_addr != 0,
              let allInfos = UnsafePointer<dyld_all_image_infos>(
                  bitPattern: UInt(taskDyldInfo.all_image_info_addr)) else { return [] }

        let imageCount = Int(allInfos.pointee.infoArrayCount)
        guard imageCount > 0, imageCount <= 16_384,
              let imageArray = allInfos.pointee.infoArray else { return [] }

        return (0..<imageCount).compactMap { index in
            let image = imageArray[index]
            guard let header = image.imageLoadAddress else { return nil }
            let path = image.imageFilePath.map { String(cString: $0) }
                ?? imagePathForMappedHeader(UnsafeRawPointer(header))
                ?? "mapped-image-\(String(UInt(bitPattern: header), radix: 16))"
            return (UInt(bitPattern: header), path)
        }
    }

    private func registeredDyldImages() -> [(header: UInt, path: String)] {
        _ = Self.installDyldImageCallback
        loupeDyldImageLock.lock()
        let headers = Array(loupeDyldImageHeaders.keys)
        loupeDyldImageLock.unlock()

        return headers.map { header in
            let pointer = UnsafeRawPointer(bitPattern: header)!
            let path = imagePathForMappedHeader(pointer)
                ?? "mapped-image-\(String(header, radix: 16))"
            return (header, path)
        }
    }

    private func isSuspiciousRuntimeImagePath(_ path: String) -> Bool {
        let lowercasePath = path.lowercased()
        return Self.hookFrameworkMarkers.contains(where: lowercasePath.contains)
            || lowercasePath.contains("/tweakinject/")
            || lowercasePath.contains("/mobilesubstrate/dynamiclibraries/")
            || lowercasePath.contains("/.jbroot/")
    }

    private func fridaIndicatorMatches(
        in images: [RuntimeImageReport.Image]
    ) -> [SignalEntry] {
        var matches = Set<SignalEntry>()

        for path in Self.fridaPaths where !successfulPathProbes(path).isEmpty {
            matches.insert(SignalEntry(label: "path", value: path))
        }

        for image in images {
            let lowercasePath = image.path.lowercased()
            if Self.fridaImageMarkers.contains(where: lowercasePath.contains) {
                matches.insert(SignalEntry(label: "image", value: image.path))
            }
        }

        for symbol in Self.hookSensitiveAPISymbols {
            guard let symbolAddress = dlsym(
                UnsafeMutableRawPointer(bitPattern: -2),
                symbol
            ), let pattern = arm64BranchStubPattern(at: UnsafeRawPointer(symbolAddress)) else {
                continue
            }
            matches.insert(SignalEntry(
                label: "API entry branch",
                value: "\(symbol): \(pattern)"))
        }

        for region in suspiciousExecutableRegions() {
            matches.insert(region)
        }

        for probe in Self.runtimeProbes {
            guard let method = class_getInstanceMethod(probe.type, probe.selector) else { continue }
            let implementation = method_getImplementation(method)
            let address = unsafeBitCast(implementation, to: UnsafeRawPointer.self)
            if let pattern = arm64BranchStubPattern(at: address) {
                let name = "\(NSStringFromClass(probe.type)).\(NSStringFromSelector(probe.selector))"
                matches.insert(SignalEntry(label: "entry branch", value: "\(name): \(pattern)"))
            }
        }

        return matches.sorted {
            $0.label == $1.label ? $0.value < $1.value : $0.label < $1.label
        }
    }

    /// Finds writable executable mappings. Frida can use RWX regions for
    /// trampolines, callback bridges, and Stalker code caches. Other runtimes
    /// can create them too, so each result is only an indicator. Anonymous RX
    /// regions are deliberately ignored because they produce frequent false
    /// positives on otherwise Frida-free processes.
    private func suspiciousExecutableRegions() -> [SignalEntry] {
        var address: vm_address_t = 0
        var matches: [SignalEntry] = []

        while matches.count < 32 {
            var regionAddress = address
            var size: vm_size_t = 0
            var info = vm_region_basic_info_data_64_t()
            var infoCount = mach_msg_type_number_t(
                MemoryLayout<vm_region_basic_info_data_64_t>.size / MemoryLayout<integer_t>.size)
            var objectName = mach_port_t(MACH_PORT_NULL)

            let result = withUnsafeMutablePointer(to: &info) { infoPointer in
                infoPointer.withMemoryRebound(to: integer_t.self, capacity: Int(infoCount)) {
                    vm_region_64(
                        mach_task_self_,
                        &regionAddress,
                        &size,
                        VM_REGION_BASIC_INFO_64,
                        $0,
                        &infoCount,
                        &objectName)
                }
            }
            if objectName != MACH_PORT_NULL {
                mach_port_deallocate(mach_task_self_, objectName)
            }
            guard result == KERN_SUCCESS, size > 0 else { break }

            let isExecutable = (info.protection & VM_PROT_EXECUTE) != 0
            let isWritable = (info.protection & VM_PROT_WRITE) != 0
            if isExecutable && isWritable {
                let endAddress = UInt64(regionAddress) + UInt64(size)
                let range = String(format: "0x%llx–0x%llx (%llu bytes)", UInt64(regionAddress), endAddress, UInt64(size))
                matches.append(SignalEntry(label: "RWX", value: range))
            }

            let nextAddress = regionAddress.addingReportingOverflow(size)
            guard !nextAddress.overflow, nextAddress.partialValue > address else { break }
            address = nextAddress.partialValue
        }
        return matches
    }

    private func arm64BranchStubPattern(at address: UnsafeRawPointer) -> String? {
#if arch(arm64)
        let instructions = address.assumingMemoryBound(to: UInt32.self)
        let first = instructions[0]
        if first & 0x7C00_0000 == 0x1400_0000 {
            return "b"
        }

        let isLoadLiteral = first & 0xFF00_0000 == 0x5800_0000
        let isPageAddress = first & 0x9F00_0000 == 0x9000_0000
        let isAddress = first & 0x9F00_0000 == 0x1000_0000

        // Common absolute trampolines. Frida 16.2.1 uses `adrp x16; br
        // x16` when the target is page-aligned. Other versions may load a
        // literal address or use ADR before branching through a register.
        if isLoadLiteral || isPageAddress || isAddress {
            for index in 1...3 where instructions[index] & 0xFFFF_FC1F == 0xD61F_0000 {
                if isLoadLiteral { return "ldr + br" }
                if isPageAddress { return "adrp + br" }
                return "adr + br"
            }
        }
#endif
        return nil
    }

    private func operatingSystemVersionConsistency() -> OSVersionConsistencyResult {
        let processInfo = ProcessInfo.processInfo
        var readings: [OSVersionReading] = []
        var details: [SignalEntry] = []
        var buildReadings: [SignalEntry] = []

        appendVersionReading(
            source: "UIDevice.systemVersion",
            rawValue: UIDevice.current.systemVersion,
            to: &readings,
            details: &details)

        let processVersion = processInfo.operatingSystemVersion
        let processVersionValue = formattedVersion(processVersion)
        readings.append(OSVersionReading(
            source: "NSProcessInfo.operatingSystemVersion",
            rawValue: processVersionValue,
            version: processVersion))
        details.append(SignalEntry(
            label: "NSProcessInfo.operatingSystemVersion",
            value: processVersionValue))

        let processVersionString = processInfo.operatingSystemVersionString
        appendVersionReading(
            source: "NSProcessInfo.operatingSystemVersionString",
            rawValue: processVersionString,
            to: &readings,
            details: &details)
        if let build = buildVersion(in: processVersionString) {
            buildReadings.append(SignalEntry(
                label: "NSProcessInfo.operatingSystemVersionString build",
                value: build))
        }

        if let productVersion = SysctlHelper.string("kern.osproductversion") {
            appendVersionReading(
                source: "sysctl kern.osproductversion",
                rawValue: productVersion,
                to: &readings,
                details: &details)
        }
        if let buildVersion = SysctlHelper.string("kern.osversion") {
            let entry = SignalEntry(label: "sysctl kern.osversion", value: buildVersion)
            details.append(entry)
            buildReadings.append(entry)
        }
        if let kernelRelease = SysctlHelper.string("kern.osrelease") {
            details.append(SignalEntry(label: "sysctl kern.osrelease", value: kernelRelease))
        }

        let uname = SysctlHelper.uname()
        if let release = uname["release"] {
            details.append(SignalEntry(label: "uname release", value: release))
        }
        if let systemVersion = foundationSystemVersionPropertyList() {
            if let productVersion = systemVersion["ProductVersion"] as? String {
                appendVersionReading(
                    source: "SystemVersion.plist Data ProductVersion",
                    rawValue: productVersion,
                    to: &readings,
                    details: &details)
            }
            if let productBuildVersion = systemVersion["ProductBuildVersion"] as? String {
                let entry = SignalEntry(
                    label: "SystemVersion.plist Data ProductBuildVersion",
                    value: productBuildVersion)
                details.append(entry)
                buildReadings.append(entry)
            }
        }
        if let systemVersion = posixSystemVersionPropertyList() {
            if let productVersion = systemVersion["ProductVersion"] as? String {
                appendVersionReading(
                    source: "SystemVersion.plist POSIX ProductVersion",
                    rawValue: productVersion,
                    to: &readings,
                    details: &details)
            }
            if let productBuildVersion = systemVersion["ProductBuildVersion"] as? String {
                let entry = SignalEntry(
                    label: "SystemVersion.plist POSIX ProductBuildVersion",
                    value: productBuildVersion)
                details.append(entry)
                buildReadings.append(entry)
            }
        }

        var mismatches: [SignalEntry] = []
        let versionGroups = Dictionary(grouping: readings) { formattedVersion($0.version) }
        if versionGroups.count > 1 {
            mismatches.append(contentsOf: readings.map {
                SignalEntry(label: $0.source, value: "\($0.rawValue) [\(formattedVersion($0.version))]")
            })
        }

        let buildGroups = Dictionary(grouping: buildReadings) { $0.value.lowercased() }
        if buildGroups.count > 1 {
            mismatches.append(contentsOf: buildReadings)
        }

        let distinctVersions = versionGroups.values.compactMap(\.first).map(\.version).sorted {
            if $0.majorVersion != $1.majorVersion { return $0.majorVersion < $1.majorVersion }
            if $0.minorVersion != $1.minorVersion { return $0.minorVersion < $1.minorVersion }
            return $0.patchVersion < $1.patchVersion
        }
        for version in distinctVersions {
            let nextPatch = OperatingSystemVersion(
                majorVersion: version.majorVersion,
                minorVersion: version.minorVersion,
                patchVersion: version.patchVersion + 1)
            let atLeastVersion = processInfo.isOperatingSystemAtLeast(version)
            let atLeastNextPatch = processInfo.isOperatingSystemAtLeast(nextPatch)
            let label = "NSProcessInfo.isOperatingSystemAtLeastVersion: \(formattedVersion(version))"
            let value = "current=\(atLeastVersion), next_patch=\(atLeastNextPatch)"
            details.append(SignalEntry(label: label, value: value))
            if !atLeastVersion || atLeastNextPatch {
                mismatches.append(SignalEntry(label: label, value: value))
            }
        }

        return OSVersionConsistencyResult(
            details: details,
            mismatches: Array(Set(mismatches)).sorted {
                $0.label == $1.label ? $0.value < $1.value : $0.label < $1.label
            })
    }

    private func appendVersionReading(
        source: String,
        rawValue: String,
        to readings: inout [OSVersionReading],
        details: inout [SignalEntry]
    ) {
        details.append(SignalEntry(label: source, value: rawValue))
        guard let version = parsedVersion(rawValue) else { return }
        readings.append(OSVersionReading(source: source, rawValue: rawValue, version: version))
    }

    private func parsedVersion(_ value: String) -> OperatingSystemVersion? {
        for token in value.split(whereSeparator: { !$0.isNumber && $0 != "." }) {
            let components = token.split(separator: ".", omittingEmptySubsequences: false)
            guard (2...3).contains(components.count),
                  let major = Int(components[0]),
                  let minor = Int(components[1]),
                  let patch = components.count == 3 ? Int(components[2]) : 0 else { continue }
            return OperatingSystemVersion(
                majorVersion: major,
                minorVersion: minor,
                patchVersion: patch)
        }
        return nil
    }

    private func formattedVersion(_ version: OperatingSystemVersion) -> String {
        "\(version.majorVersion).\(version.minorVersion).\(version.patchVersion)"
    }

    private func buildVersion(in versionString: String) -> String? {
        guard let buildRange = versionString.range(of: "Build ") else { return nil }
        let suffix = versionString[buildRange.upperBound...]
        let build = suffix.prefix { $0 != ")" && !$0.isWhitespace }
        return build.isEmpty ? nil : String(build)
    }

    private func foundationSystemVersionPropertyList() -> [String: Any]? {
        let url = URL(fileURLWithPath: "/System/Library/CoreServices/SystemVersion.plist")
        guard let data = try? Data(contentsOf: url) else { return nil }
        return propertyListDictionary(from: data)
    }

    private func posixSystemVersionPropertyList() -> [String: Any]? {
        let path = "/System/Library/CoreServices/SystemVersion.plist"
        let descriptor = path.withCString { Darwin.open($0, O_RDONLY | O_CLOEXEC) }
        guard descriptor >= 0 else { return nil }
        defer { Darwin.close(descriptor) }

        var metadata = stat()
        guard Darwin.fstat(descriptor, &metadata) == 0,
              metadata.st_size > 0,
              metadata.st_size <= 1_048_576 else { return nil }

        var data = Data(count: Int(metadata.st_size))
        let readSucceeded = data.withUnsafeMutableBytes { buffer -> Bool in
            guard let baseAddress = buffer.baseAddress else { return false }
            var offset = 0
            while offset < buffer.count {
                let count = Darwin.pread(
                    descriptor,
                    baseAddress.advanced(by: offset),
                    buffer.count - offset,
                    off_t(offset))
                guard count > 0 else { return false }
                offset += count
            }
            return true
        }
        guard readSucceeded else { return nil }
        return propertyListDictionary(from: data)
    }

    private func propertyListDictionary(from data: Data) -> [String: Any]? {
        guard let propertyList = try? PropertyListSerialization.propertyList(from: data, format: nil),
              let dictionary = propertyList as? [String: Any] else { return nil }
        return dictionary
    }

    private func objectiveCRuntimeProbeResults() -> [RuntimeProbeResult] {
        Self.runtimeProbes.compactMap { probe -> RuntimeProbeResult? in
            guard let method = class_getInstanceMethod(probe.type, probe.selector) else { return nil }

            let implementation = method_getImplementation(method)
            let implementationAddress = unsafeBitCast(implementation, to: UnsafeRawPointer.self)
            let methodListImplementationAddress = directMethodListImplementationAddress(for: probe)
            let implementationAddressesMatch = methodListImplementationAddress.map {
                comparableAddress(implementationAddress) == comparableAddress($0)
            }
            let className = NSStringFromClass(probe.type)
            let methodName = NSStringFromSelector(probe.selector)
            let label = "\(className).\(methodName)"
            let dladdrInfo = dynamicLinkerInfo(for: implementationAddress)
            let methodListDladdrInfo = methodListImplementationAddress.map {
                dynamicLinkerInfo(for: $0)
            }
            let methodListMappedImage = methodListImplementationAddress.flatMap {
                methodListDladdrInfo?.imagePath == nil
                    ? mappedMachOImageContaining($0)
                    : nil
            }
            let methodListImagePath = methodListDladdrInfo?.imagePath
                ?? methodListMappedImage?.path
            let classImagePath = imagePath(for: probe.type)
            let isInClassImage = classImagePath.flatMap {
                imageContainsExecutableAddress(implementationAddress, imagePath: $0)
            }
            var methodListIsInClassImage: Bool?
            if let methodListImplementationAddress, let classImagePath {
                methodListIsInClassImage = imageContainsExecutableAddress(
                    methodListImplementationAddress,
                    imagePath: classImagePath)
            }
            let isAnonymousExecutable = dladdrInfo.imagePath == nil
                && isExecutableMemory(at: implementationAddress)
            let methodListIsAnonymousExecutable = methodListImplementationAddress.map {
                methodListImagePath == nil && isExecutableMemory(at: $0)
            } ?? false
            let possibleFridaHook = String(
                localized: "Possible Frida hook",
                comment: "Assessment shown when an Objective-C IMP points to executable memory that dladdr cannot associate with an image.")
            let suspiciousValue: String?

            if implementationAddressesMatch == false, let methodListImplementationAddress {
                let methodListOwner = methodListImagePath.map {
                    URL(fileURLWithPath: $0).lastPathComponent
                } ?? (methodListIsAnonymousExecutable ? possibleFridaHook : "unknown image")
                suspiciousValue = "method_getImplementation \(pointerString(implementationAddress)) ≠ method_list \(pointerString(methodListImplementationAddress)) · \(methodListOwner)"
            } else if methodListIsInClassImage == false,
                      let methodListImplementationAddress,
                      let classImagePath {
                let actualName = methodListImagePath.map {
                    URL(fileURLWithPath: $0).lastPathComponent
                } ?? (methodListIsAnonymousExecutable ? possibleFridaHook : "unknown image")
                let expectedName = URL(fileURLWithPath: classImagePath).lastPathComponent
                suspiciousValue = "method_list \(pointerString(methodListImplementationAddress)): \(actualName) ≠ \(expectedName)"
            } else if let methodListImagePath,
                      !isAppleSystemImage(methodListImagePath) {
                suspiciousValue = URL(fileURLWithPath: methodListImagePath).lastPathComponent
            } else if let imagePath = dladdrInfo.imagePath {
                let actualImageName = URL(fileURLWithPath: imagePath).lastPathComponent
                if isInClassImage == false, let classImagePath {
                    let expectedImageName = URL(fileURLWithPath: classImagePath).lastPathComponent
                    suspiciousValue = "\(actualImageName) ≠ \(expectedImageName)"
                } else {
                    suspiciousValue = isAppleSystemImage(imagePath) ? nil : actualImageName
                }
            } else {
                // Frida's ObjC.implement commonly redirects the IMP to an
                // anonymous executable region. It has no Mach-O image, so
                // dladdr cannot name it even though the address is callable.
                suspiciousValue = isAnonymousExecutable
                    ? "\(possibleFridaHook): \(pointerString(implementationAddress))"
                    : nil
            }

            let missingValue = String(localized: "(none)", comment: "Placeholder shown when a technical value is absent.")
            let detailValue = [
                "IMP: \(pointerString(implementationAddress))",
                "method_list_imp: \(pointerString(methodListImplementationAddress))",
                "imp_matches_method_list: \(implementationAddressesMatch.map(String.init) ?? missingValue)",
                "class_image: \(classImagePath ?? missingValue)",
                "in_class_image: \(isInClassImage.map(String.init) ?? missingValue)",
                "method_list_in_class_image: \(methodListIsInClassImage.map(String.init) ?? missingValue)",
                "dli_fname: \(dladdrInfo.imagePath ?? (isAnonymousExecutable ? possibleFridaHook : missingValue))",
                "dli_fbase: \(pointerString(dladdrInfo.imageBase))",
                "dli_sname: \(dladdrInfo.symbolName ?? missingValue)",
                "dli_saddr: \(pointerString(dladdrInfo.symbolAddress))",
                "method_list_dli_fname: \(methodListDladdrInfo?.imagePath ?? missingValue)",
                "method_list_dli_fbase: \(pointerString(methodListDladdrInfo?.imageBase))",
                "method_list_dli_sname: \(methodListDladdrInfo?.symbolName ?? missingValue)",
                "method_list_dli_saddr: \(pointerString(methodListDladdrInfo?.symbolAddress))",
                "method_list_vm_image: \(methodListMappedImage?.path ?? missingValue)",
                "method_list_vm_base: \(pointerString(methodListMappedImage?.base))",
            ].joined(separator: "\n")

            return RuntimeProbeResult(
                detail: SignalEntry(label: label, value: detailValue),
                suspiciousEntry: suspiciousValue.map { SignalEntry(label: label, value: $0) })
        }
        .sorted { $0.detail.label < $1.detail.label }
    }

    /// Reads the IMP field from objc4's method-list storage instead of asking
    /// `method_getImplementation`. This provides an independent value when the
    /// runtime API itself has been hooked or a small method has been remapped.
    private func directMethodListImplementationAddress(
        for probe: RuntimeProbe
    ) -> UnsafeRawPointer? {
        var methodCount: UInt32 = 0
        guard let methods = class_copyMethodList(probe.type, &methodCount) else { return nil }
        defer { free(methods) }

        for index in 0..<Int(methodCount) {
            let method = methods[index]
            guard method_getName(method) == probe.selector else { continue }
            return storedImplementationAddress(in: method)
        }
        return nil
    }

    private func storedImplementationAddress(in method: Method) -> UnsafeRawPointer? {
        let taggedAddress = UInt(bitPattern: method)
        let methodKind = taggedAddress & 0x3
        let storageAddress = taggedAddress & Self.objectiveCPointerAddressMask & ~UInt(0x3)
        guard let storage = UnsafeRawPointer(bitPattern: storageAddress) else { return nil }

        switch methodKind {
        case 0, 2:
            // Big and big-signed methods store SEL, types, and IMP pointers.
            let impField = storage.advanced(by: 2 * MemoryLayout<UnsafeRawPointer>.size)
            let signedIMP = impField.load(as: UInt.self)
            return UnsafeRawPointer(bitPattern: signedIMP & Self.objectiveCPointerAddressMask)
        case 1:
            // Small methods store name, types, and IMP as Int32 offsets from
            // the address of their respective fields.
            let impField = storage.advanced(by: 2 * MemoryLayout<Int32>.size)
            let relativeOffset = impField.load(as: Int32.self)
            let fieldAddress = UInt(bitPattern: impField)
            let result: (partialValue: UInt, overflow: Bool)
            if relativeOffset >= 0 {
                result = fieldAddress.addingReportingOverflow(UInt(relativeOffset))
            } else {
                result = fieldAddress.subtractingReportingOverflow(UInt(-Int64(relativeOffset)))
            }
            guard !result.overflow else { return nil }
            return UnsafeRawPointer(bitPattern: result.partialValue)
        default:
            return nil
        }
    }

    private func comparableAddress(_ address: UnsafeRawPointer) -> UInt {
        UInt(bitPattern: address) & Self.objectiveCPointerAddressMask
    }

    private func dynamicLinkerInfo(for address: UnsafeRawPointer) -> (
        imagePath: String?,
        imageBase: UnsafeRawPointer?,
        symbolName: String?,
        symbolAddress: UnsafeRawPointer?
    ) {
        var info = Dl_info()
        guard dladdr(address, &info) != 0 else { return (nil, nil, nil, nil) }
        return (
            info.dli_fname.map { String(cString: $0) },
            info.dli_fbase.map(UnsafeRawPointer.init),
            info.dli_sname.map { String(cString: $0) },
            info.dli_saddr.map(UnsafeRawPointer.init))
    }

    private func imagePathForMappedHeader(_ header: UnsafeRawPointer) -> String? {
        let linkedInfo = dynamicLinkerInfo(for: header)
        if let path = linkedInfo.imagePath { return path }

        let machHeader = header.load(as: mach_header_64.self)
        guard machHeader.magic == MH_MAGIC_64 else { return nil }
        var commandPointer = header.advanced(by: MemoryLayout<mach_header_64>.size)
        let commandsEnd = commandPointer.advanced(by: Int(machHeader.sizeofcmds))

        for _ in 0..<machHeader.ncmds {
            guard commandPointer.advanced(by: MemoryLayout<load_command>.size) <= commandsEnd else {
                break
            }
            let command = commandPointer.load(as: load_command.self)
            guard command.cmdsize >= MemoryLayout<load_command>.size,
                  commandPointer.advanced(by: Int(command.cmdsize)) <= commandsEnd else { break }
            defer { commandPointer = commandPointer.advanced(by: Int(command.cmdsize)) }
            guard command.cmd == LC_ID_DYLIB,
                  command.cmdsize >= MemoryLayout<dylib_command>.size else { continue }

            let dylibCommand = commandPointer.load(as: dylib_command.self)
            let offset = Int(dylibCommand.dylib.name.offset)
            guard offset >= MemoryLayout<dylib_command>.size,
                  offset < Int(command.cmdsize) else { continue }
            let start = commandPointer.advanced(by: offset)
            let capacity = Int(command.cmdsize) - offset
            let bytes = UnsafeRawBufferPointer(start: start, count: capacity)
            let end = bytes.firstIndex(of: 0) ?? bytes.endIndex
            return String(decoding: bytes[..<end], as: UTF8.self)
        }
        return nil
    }

    /// Starts from a raw IMP address and walks the nearby VM map through the
    /// legacy vm_region_64 entry point. This does not depend on dyld's image
    /// arrays or the mach_vm_region hooks used by common hidden-image scans.
    private func mappedMachOImageContaining(
        _ pointer: UnsafeRawPointer
    ) -> (base: UnsafeRawPointer, path: String?)? {
        let target = UInt(bitPattern: pointer)
        let searchDistance = min(target, 64 * 1_024 * 1_024)
        var nextAddress = vm_address_t(target - searchDistance)

        while UInt(nextAddress) <= target {
            var regionAddress = nextAddress
            var regionSize: vm_size_t = 0
            var info = vm_region_basic_info_data_64_t()
            var infoCount = mach_msg_type_number_t(
                MemoryLayout<vm_region_basic_info_data_64_t>.size / MemoryLayout<integer_t>.size)
            var objectName = mach_port_t(MACH_PORT_NULL)
            let result = withUnsafeMutablePointer(to: &info) { infoPointer in
                infoPointer.withMemoryRebound(to: integer_t.self, capacity: Int(infoCount)) {
                    vm_region_64(
                        mach_task_self_,
                        &regionAddress,
                        &regionSize,
                        VM_REGION_BASIC_INFO_64,
                        $0,
                        &infoCount,
                        &objectName)
                }
            }
            if objectName != MACH_PORT_NULL {
                mach_port_deallocate(mach_task_self_, objectName)
            }
            guard result == KERN_SUCCESS, regionSize > 0,
                  UInt(regionAddress) <= target else { break }

            if info.protection & VM_PROT_READ != 0,
               regionSize >= vm_size_t(MemoryLayout<mach_header_64>.size),
               let image = mappedMachOImage(
                   at: UInt(regionAddress),
                   regionSize: UInt(regionSize),
                   containing: target) {
                return image
            }

            let next = regionAddress.addingReportingOverflow(regionSize)
            guard !next.overflow, next.partialValue > nextAddress else { break }
            nextAddress = next.partialValue
        }
        return nil
    }

    private func mappedMachOImage(
        at baseAddress: UInt,
        regionSize: UInt,
        containing targetAddress: UInt
    ) -> (base: UnsafeRawPointer, path: String?)? {
        guard let base = UnsafeRawPointer(bitPattern: baseAddress),
              regionSize >= UInt(MemoryLayout<mach_header_64>.size) else { return nil }
        let header = base.load(as: mach_header_64.self)
        guard header.magic == MH_MAGIC_64,
              UInt(MemoryLayout<mach_header_64>.size) + UInt(header.sizeofcmds) <= regionSize else {
            return nil
        }

        var preferredTextAddress: UInt64?
        var executableSegments: [(address: UInt64, size: UInt64)] = []
        var commandPointer = base.advanced(by: MemoryLayout<mach_header_64>.size)
        let commandsEnd = commandPointer.advanced(by: Int(header.sizeofcmds))
        for _ in 0..<header.ncmds {
            guard commandPointer.advanced(by: MemoryLayout<load_command>.size) <= commandsEnd else {
                break
            }
            let command = commandPointer.load(as: load_command.self)
            guard command.cmdsize >= MemoryLayout<load_command>.size,
                  commandPointer.advanced(by: Int(command.cmdsize)) <= commandsEnd else { break }
            defer { commandPointer = commandPointer.advanced(by: Int(command.cmdsize)) }
            guard command.cmd == LC_SEGMENT_64 else { continue }
            let segment = commandPointer.load(as: segment_command_64.self)
            if Self.fixedMachOName(segment.segname) == "__TEXT" {
                preferredTextAddress = segment.vmaddr
            }
            if segment.initprot & VM_PROT_EXECUTE != 0, segment.vmsize > 0 {
                executableSegments.append((segment.vmaddr, segment.vmsize))
            }
        }

        guard let preferredTextAddress else { return nil }
        let target = UInt64(targetAddress)
        let base64 = UInt64(baseAddress)
        let containsTarget = executableSegments.contains { segment in
            guard segment.address >= preferredTextAddress else { return false }
            let offset = segment.address - preferredTextAddress
            let start = base64.addingReportingOverflow(offset)
            guard !start.overflow, target >= start.partialValue else { return false }
            return target - start.partialValue < segment.size
        }
        guard containsTarget else { return nil }
        return (base, imagePathForMappedHeader(base))
    }

    private func imagePath(for type: AnyClass) -> String? {
        class_getImageName(type).map { String(cString: $0) }
    }

    /// Checks the address against the executable segments in the class's
    /// loaded Mach-O image. Comparing paths alone is not enough because a
    /// redirected IMP may still resolve to another Apple system image.
    private func imageContainsExecutableAddress(
        _ address: UnsafeRawPointer,
        imagePath: String
    ) -> Bool? {
        let targetAddress = UInt64(UInt(bitPattern: address))

        for index in 0..<_dyld_image_count() {
            guard let imageName = _dyld_get_image_name(index),
                  String(cString: imageName) == imagePath,
                  let header = _dyld_get_image_header(index) else { continue }

            let slide = Int64(_dyld_get_image_vmaddr_slide(index))
            var commandPointer = UnsafeRawPointer(header)
                .advanced(by: MemoryLayout<mach_header_64>.size)

            for _ in 0..<header.pointee.ncmds {
                let command = commandPointer.load(as: load_command.self)
                defer { commandPointer = commandPointer.advanced(by: Int(command.cmdsize)) }

                guard command.cmd == LC_SEGMENT_64 else { continue }
                let segment = commandPointer.load(as: segment_command_64.self)
                guard segment.vmsize > 0,
                      (segment.initprot & VM_PROT_EXECUTE) != 0 else { continue }

                let start = UInt64(bitPattern: Int64(bitPattern: segment.vmaddr) + slide)
                if targetAddress >= start, targetAddress - start < segment.vmsize {
                    return true
                }
            }

            return false
        }

        return nil
    }

    private func pointerString(_ pointer: UnsafeRawPointer?) -> String {
        guard let pointer else { return String(localized: "(none)", comment: "Placeholder shown when a technical value is absent.") }
        return String(format: "0x%llx", UInt64(UInt(bitPattern: pointer)))
    }

    private func isExecutableMemory(at pointer: UnsafeRawPointer) -> Bool {
        let requestedAddress = vm_address_t(UInt(bitPattern: pointer))
        var address = requestedAddress
        var size: vm_size_t = 0
        var info = vm_region_basic_info_data_64_t()
        var infoCount = mach_msg_type_number_t(
            MemoryLayout<vm_region_basic_info_data_64_t>.size / MemoryLayout<integer_t>.size)
        var objectName = mach_port_t(MACH_PORT_NULL)

        let result = withUnsafeMutablePointer(to: &info) { infoPointer in
            infoPointer.withMemoryRebound(
                to: integer_t.self,
                capacity: Int(infoCount)
            ) { reboundInfo in
                vm_region_64(
                    mach_task_self_,
                    &address,
                    &size,
                    VM_REGION_BASIC_INFO_64,
                    reboundInfo,
                    &infoCount,
                    &objectName)
            }
        }

        if objectName != MACH_PORT_NULL {
            mach_port_deallocate(mach_task_self_, objectName)
        }

        let containsRequestedAddress = requestedAddress >= address
            && requestedAddress - address < size
        return result == KERN_SUCCESS
            && containsRequestedAddress
            && (info.protection & VM_PROT_EXECUTE) != 0
    }

    private func isAppleSystemImage(_ path: String) -> Bool {
        path.hasPrefix("/usr/lib/") || path.contains("/System/Library/")
    }
}
