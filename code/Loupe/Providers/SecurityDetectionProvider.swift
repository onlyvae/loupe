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

    private static let runtimeProbes = [
        RuntimeProbe(type: ProcessInfo.self, selector: NSSelectorFromString("operatingSystemVersionString")),
    ]

    func collect() async -> [FingerprintSignal] {
        let pathMatches = knownPathMatches()
        let hookMatches = loadedHookFrameworkMatches()
        let fridaMatches = fridaIndicatorMatches()
        let runtimeProbeResults = objectiveCRuntimeProbeResults()
        let runtimeHookMatches = runtimeProbeResults.compactMap(\.suspiciousEntry)

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
                "fridaIndicators",
                category: category,
                name: String(localized: "Frida indicators", comment: "Signal card name in the Security Detection category — evidence that Frida instrumentation may be attached to the app."),
                value: String(fridaMatches.count),
                rationale: String(localized: "Any app can quietly check for Frida-related files and loaded code, modified entry points, and unusual executable memory. These signs can have other causes, and Frida can hide them, so this check is not proof either way.", comment: "Signal card rationale beneath Frida indicators. Explains the local checks, possible false positives, and that they cannot rule out a hidden Frida installation."),
                displayHint: fridaMatches.isEmpty ? .plain : .keyValue,
                entries: fridaMatches.isEmpty ? nil : fridaMatches),
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

    private func fridaIndicatorMatches() -> [SignalEntry] {
        var matches = Set<SignalEntry>()

        for path in Self.fridaPaths where !successfulPathProbes(path).isEmpty {
            matches.insert(SignalEntry(label: "path", value: path))
        }

        for index in 0..<_dyld_image_count() {
            guard let imageName = _dyld_get_image_name(index) else { continue }
            let path = String(cString: imageName)
            let lowercasePath = path.lowercased()
            if Self.fridaImageMarkers.contains(where: lowercasePath.contains) {
                matches.insert(SignalEntry(label: "image", value: path))
            }
        }

        if let taskThreadsAddress = dlsym(
            UnsafeMutableRawPointer(bitPattern: -2),
            "task_threads"
        ), let pattern = arm64BranchStubPattern(at: UnsafeRawPointer(taskThreadsAddress)) {
            matches.insert(SignalEntry(
                label: "API entry branch",
                value: "task_threads: \(pattern)"))
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

    private func objectiveCRuntimeProbeResults() -> [RuntimeProbeResult] {
        Self.runtimeProbes.compactMap { probe -> RuntimeProbeResult? in
            guard let method = class_getInstanceMethod(probe.type, probe.selector) else { return nil }

            let implementation = method_getImplementation(method)
            let implementationAddress = unsafeBitCast(implementation, to: UnsafeRawPointer.self)
            let className = NSStringFromClass(probe.type)
            let methodName = NSStringFromSelector(probe.selector)
            let label = "\(className).\(methodName)"
            let dladdrInfo = dynamicLinkerInfo(for: implementationAddress)
            let classImagePath = imagePath(for: probe.type)
            let isInClassImage = classImagePath.flatMap {
                imageContainsExecutableAddress(implementationAddress, imagePath: $0)
            }
            let isAnonymousExecutable = dladdrInfo.imagePath == nil
                && isExecutableMemory(at: implementationAddress)
            let possibleFridaHook = String(
                localized: "Possible Frida hook",
                comment: "Assessment shown when an Objective-C IMP points to executable memory that dladdr cannot associate with an image.")
            let suspiciousValue: String?

            if let imagePath = dladdrInfo.imagePath {
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
                "class_image: \(classImagePath ?? missingValue)",
                "in_class_image: \(isInClassImage.map(String.init) ?? missingValue)",
                "dli_fname: \(dladdrInfo.imagePath ?? (isAnonymousExecutable ? possibleFridaHook : missingValue))",
                "dli_fbase: \(pointerString(dladdrInfo.imageBase))",
                "dli_sname: \(dladdrInfo.symbolName ?? missingValue)",
                "dli_saddr: \(pointerString(dladdrInfo.symbolAddress))",
            ].joined(separator: "\n")

            return RuntimeProbeResult(
                detail: SignalEntry(label: label, value: detailValue),
                suspiciousEntry: suspiciousValue.map { SignalEntry(label: label, value: $0) })
        }
        .sorted { $0.detail.label < $1.detail.label }
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
