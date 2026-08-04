//
//  RuntimeImageReport.swift
//  Loupe
//
//  Builds a live snapshot of CrashReporter annotations and Mach-O images.
//  This does not trigger a crash or read the system CrashReporter directory.
//

import Darwin
import Foundation
import MachO

// The kernel entry point is present on iOS but the SDK marks the generated
// declaration unavailable to Swift. Crash reporters use it against their own
// task to enumerate mappings that dyld no longer publishes.
@_silgen_name("mach_vm_region")
private func loupeMachVMRegion(
    _ targetTask: vm_map_read_t,
    _ address: UnsafeMutablePointer<mach_vm_address_t>,
    _ size: UnsafeMutablePointer<mach_vm_size_t>,
    _ flavor: vm_region_flavor_t,
    _ info: UnsafeMutablePointer<integer_t>,
    _ infoCount: UnsafeMutablePointer<mach_msg_type_number_t>,
    _ objectName: UnsafeMutablePointer<mach_port_t>
) -> kern_return_t

// A separate MIG entry point that walks the VM map hierarchy. Keeping several
// region APIs in the report makes it resilient when an injected library
// intercepts only one family of VM entry points.
@_silgen_name("mach_vm_region_recurse")
private func loupeMachVMRegionRecurse(
    _ targetTask: vm_map_read_t,
    _ address: UnsafeMutablePointer<mach_vm_address_t>,
    _ size: UnsafeMutablePointer<mach_vm_size_t>,
    _ nestingDepth: UnsafeMutablePointer<natural_t>,
    _ info: UnsafeMutablePointer<integer_t>,
    _ infoCount: UnsafeMutablePointer<mach_msg_type_number_t>
) -> kern_return_t

@_silgen_name("vm_region_recurse_64")
private func loupeVMRegionRecurse64(
    _ targetTask: vm_map_read_t,
    _ address: UnsafeMutablePointer<vm_address_t>,
    _ size: UnsafeMutablePointer<vm_size_t>,
    _ nestingDepth: UnsafeMutablePointer<natural_t>,
    _ info: UnsafeMutablePointer<integer_t>,
    _ infoCount: UnsafeMutablePointer<mach_msg_type_number_t>
) -> kern_return_t

enum RuntimeImageReport {
    struct Image: Hashable, Sendable {
        enum Source: String, Sendable {
            case dyld
            case hiddenVM
        }

        let baseAddress: UInt64
        let upperBound: UInt64
        let name: String
        let path: String
        let uuid: String
        let source: Source
    }

    struct Snapshot: Sendable {
        let images: [Image]
    }

    static func capture(annotationMessages: [String]) -> Snapshot {
        Snapshot(images: loadedBinaryImages() + hiddenMappedBinaryImages(
            annotations: annotationMessages))
    }

    private static func insertedLibraryPaths(from annotations: [String]) -> [String] {
        annotations.flatMap { annotation -> [String] in
            guard let marker = annotation.range(of: "DYLD_INSERT_LIBRARIES=") else { return [] }
            let value = annotation[marker.upperBound...].prefix { !$0.isWhitespace }
            return value.split(separator: ":").map(String.init)
        }
    }

    private static func jailbreakRootPaths(annotations: [String]) -> [String] {
        var paths: [String] = []
        for injectedPath in insertedLibraryPaths(from: annotations) {
            let filename = URL(fileURLWithPath: injectedPath).lastPathComponent
            guard filename.hasPrefix("systemhook-"), filename.hasSuffix(".dylib") else { continue }
            let hash = filename
                .dropFirst("systemhook-".count)
                .dropLast(".dylib".count)
            paths.append("/private/var/containers/Bundle/Application/.jbroot-\(hash)")
            paths.append("/var/containers/Bundle/Application/.jbroot-\(hash)")
        }
        return paths
    }

    private static func resolvedMappedImagePath(
        installName: String?,
        imageName: String,
        jailbreakRoots: [String]
    ) -> String {
        guard let installName, !installName.isEmpty else { return imageName }

        // RootHide records its on-disk location relative to a synthetic
        // `.jbroot` loader directory. The systemhook hash identifies the real
        // randomized root used for this launch.
        if let marker = installName.range(of: "/.jbroot/") {
            let suffix = String(installName[marker.upperBound...])
            let resolvedPaths = jailbreakRoots.map { "\($0)/\(suffix)" }
            return resolvedPaths.first(where: FileManager.default.fileExists(atPath:))
                ?? resolvedPaths.first
                ?? installName
        }
        return installName
    }

    private static func loadedBinaryImages() -> [Image] {
        (0..<_dyld_image_count()).compactMap { index in
            guard let header = _dyld_get_image_header(index),
                  let imageName = _dyld_get_image_name(index) else { return nil }
            let path = String(cString: imageName)
            let base = UInt64(UInt(bitPattern: header))
            var preferredTextAddress: UInt64?
            var segments: [(address: UInt64, size: UInt64, name: String)] = []
            var uuid = "????????????????????????????????"
            var commandPointer = UnsafeRawPointer(header)
                .advanced(by: MemoryLayout<mach_header_64>.size)

            for _ in 0..<header.pointee.ncmds {
                let command = commandPointer.load(as: load_command.self)
                guard command.cmdsize >= MemoryLayout<load_command>.size else { break }
                defer { commandPointer = commandPointer.advanced(by: Int(command.cmdsize)) }
                if command.cmd == LC_SEGMENT_64 {
                    let segment = commandPointer.load(as: segment_command_64.self)
                    let name = fixedMachOName(segment.segname)
                    if name == "__TEXT" {
                        preferredTextAddress = segment.vmaddr
                    }
                    segments.append((segment.vmaddr, segment.vmsize, name))
                } else if command.cmd == LC_UUID {
                    let uuidCommand = commandPointer.load(as: uuid_command.self)
                    uuid = uuidString(uuidCommand.uuid)
                }
            }

            let name = URL(fileURLWithPath: path).lastPathComponent
            let upperBound = segments.reduce(base) { result, segment in
                guard segment.name != "__LINKEDIT",
                      let preferredTextAddress,
                      segment.address >= preferredTextAddress else { return result }
                let offset = segment.address - preferredTextAddress
                return max(result, base + offset + segment.size)
            }
            return Image(
                baseAddress: base,
                upperBound: max(base + 1, upperBound) - 1,
                name: name,
                path: path,
                uuid: uuid,
                source: .dyld)
        }
    }

    /// Some injection loaders remove images from dyld's public image array.
    /// Walk executable VM mappings through the mach_vm and legacy vm entry
    /// points, then parse Mach-O headers directly. A hook that filters only
    /// one API family cannot hide the mapping from every pass.
    private static func hiddenMappedBinaryImages(annotations: [String]) -> [Image] {
        let dyldHeaders = Set((0..<_dyld_image_count()).compactMap { index in
            _dyld_get_image_header(index).map { UInt64(UInt(bitPattern: $0)) }
        })
        let jailbreakRoots = jailbreakRootPaths(annotations: annotations)

        let regions = executableRegionsUsingMachVMRegion()
            + executableRegionsUsingVMRegion64()
            + executableRegionsUsingMachVMRegionRecurse()
            + executableRegionsUsingVMRegionRecurse64()
        let regionSizes = regions.reduce(into: [UInt64: UInt64]()) { sizes, region in
            sizes[region.address] = max(sizes[region.address] ?? 0, region.size)
        }
        let images = regionSizes.compactMap { address, size -> Image? in
            guard !dyldHeaders.contains(address) else { return nil }
            return mappedBinaryImage(
                at: address,
                regionSize: size,
                jailbreakRoots: jailbreakRoots)
        }
        return images.sorted { $0.baseAddress < $1.baseAddress }
    }

    private struct ExecutableRegion {
        let address: UInt64
        let size: UInt64
    }

    private static func executableRegionsUsingMachVMRegion() -> [ExecutableRegion] {
        var nextAddress: mach_vm_address_t = 0
        var regions: [ExecutableRegion] = []

        while true {
            var regionAddress = nextAddress
            var regionSize: mach_vm_size_t = 0
            var info = vm_region_basic_info_data_64_t()
            var infoCount = mach_msg_type_number_t(
                MemoryLayout<vm_region_basic_info_data_64_t>.size / MemoryLayout<integer_t>.size)
            var objectName: mach_port_t = 0
            let result = withUnsafeMutablePointer(to: &info) { pointer in
                pointer.withMemoryRebound(to: integer_t.self, capacity: Int(infoCount)) {
                    loupeMachVMRegion(
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
            guard result == KERN_SUCCESS, regionSize > 0 else { break }

            if info.protection & VM_PROT_READ != 0,
               info.protection & VM_PROT_EXECUTE != 0,
               regionSize >= mach_vm_size_t(MemoryLayout<mach_header_64>.size) {
                regions.append(ExecutableRegion(address: regionAddress, size: regionSize))
            }

            let next = regionAddress.addingReportingOverflow(regionSize)
            guard !next.overflow, next.partialValue > nextAddress else { break }
            nextAddress = next.partialValue
        }
        return regions
    }

    private static func executableRegionsUsingVMRegion64() -> [ExecutableRegion] {
        var nextAddress: vm_address_t = 0
        var regions: [ExecutableRegion] = []

        while true {
            var regionAddress = nextAddress
            var regionSize: vm_size_t = 0
            var info = vm_region_basic_info_data_64_t()
            var infoCount = mach_msg_type_number_t(
                MemoryLayout<vm_region_basic_info_data_64_t>.size / MemoryLayout<integer_t>.size)
            var objectName = mach_port_t(MACH_PORT_NULL)
            let result = withUnsafeMutablePointer(to: &info) { pointer in
                pointer.withMemoryRebound(to: integer_t.self, capacity: Int(infoCount)) {
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
            guard result == KERN_SUCCESS, regionSize > 0 else { break }

            if info.protection & VM_PROT_READ != 0,
               info.protection & VM_PROT_EXECUTE != 0,
               regionSize >= vm_size_t(MemoryLayout<mach_header_64>.size) {
                regions.append(ExecutableRegion(
                    address: UInt64(regionAddress),
                    size: UInt64(regionSize)))
            }

            let next = regionAddress.addingReportingOverflow(regionSize)
            guard !next.overflow, next.partialValue > nextAddress else { break }
            nextAddress = next.partialValue
        }
        return regions
    }

    private static func executableRegionsUsingMachVMRegionRecurse() -> [ExecutableRegion] {
        var nextAddress: mach_vm_address_t = 0
        var depth: natural_t = 0
        var regions: [ExecutableRegion] = []

        while true {
            var regionAddress = nextAddress
            var regionSize: mach_vm_size_t = 0
            var info = vm_region_submap_info_data_64_t()
            var infoCount = mach_msg_type_number_t(
                MemoryLayout<vm_region_submap_info_data_64_t>.size / MemoryLayout<natural_t>.size)
            let result = withUnsafeMutablePointer(to: &info) { pointer in
                pointer.withMemoryRebound(to: integer_t.self, capacity: Int(infoCount)) {
                    loupeMachVMRegionRecurse(
                        mach_task_self_,
                        &regionAddress,
                        &regionSize,
                        &depth,
                        $0,
                        &infoCount)
                }
            }
            guard result == KERN_SUCCESS, regionSize > 0 else { break }

            if info.is_submap != 0 {
                depth += 1
                nextAddress = regionAddress
                continue
            }

            if info.protection & VM_PROT_READ != 0,
               info.protection & VM_PROT_EXECUTE != 0,
               regionSize >= mach_vm_size_t(MemoryLayout<mach_header_64>.size) {
                regions.append(ExecutableRegion(address: regionAddress, size: regionSize))
            }

            let next = regionAddress.addingReportingOverflow(regionSize)
            guard !next.overflow, next.partialValue > nextAddress else { break }
            nextAddress = next.partialValue
        }
        return regions
    }

    private static func executableRegionsUsingVMRegionRecurse64() -> [ExecutableRegion] {
        var nextAddress: vm_address_t = 0
        var depth: natural_t = 0
        var regions: [ExecutableRegion] = []

        while true {
            var regionAddress = nextAddress
            var regionSize: vm_size_t = 0
            var info = vm_region_submap_info_data_64_t()
            var infoCount = mach_msg_type_number_t(
                MemoryLayout<vm_region_submap_info_data_64_t>.size / MemoryLayout<natural_t>.size)
            let result = withUnsafeMutablePointer(to: &info) { pointer in
                pointer.withMemoryRebound(to: integer_t.self, capacity: Int(infoCount)) {
                    loupeVMRegionRecurse64(
                        mach_task_self_,
                        &regionAddress,
                        &regionSize,
                        &depth,
                        $0,
                        &infoCount)
                }
            }
            guard result == KERN_SUCCESS, regionSize > 0 else { break }

            if info.is_submap != 0 {
                depth += 1
                nextAddress = regionAddress
                continue
            }

            if info.protection & VM_PROT_READ != 0,
               info.protection & VM_PROT_EXECUTE != 0,
               regionSize >= vm_size_t(MemoryLayout<mach_header_64>.size) {
                regions.append(ExecutableRegion(
                    address: UInt64(regionAddress),
                    size: UInt64(regionSize)))
            }

            let next = regionAddress.addingReportingOverflow(regionSize)
            guard !next.overflow, next.partialValue > nextAddress else { break }
            nextAddress = next.partialValue
        }
        return regions
    }

    private static func mappedBinaryImage(
        at regionAddress: UInt64,
        regionSize: UInt64,
        jailbreakRoots: [String]
    ) -> Image? {
        guard let rawHeader = UnsafeRawPointer(bitPattern: UInt(regionAddress)) else {
            return nil
        }

        let header = rawHeader.load(as: mach_header_64.self)
        guard header.magic == MH_MAGIC_64,
              header.filetype == MH_DYLIB || header.filetype == MH_BUNDLE || header.filetype == MH_EXECUTE,
              UInt64(MemoryLayout<mach_header_64>.size) + UInt64(header.sizeofcmds) <= regionSize else {
            return nil
        }

        var preferredTextAddress: UInt64?
        var upperBound = regionAddress
        var uuid = "????????????????????????????????"
        var installName: String?
        var commandPointer = rawHeader.advanced(by: MemoryLayout<mach_header_64>.size)
        let commandsEnd = commandPointer.advanced(by: Int(header.sizeofcmds))

        for _ in 0..<header.ncmds {
            guard commandPointer.advanced(by: MemoryLayout<load_command>.size) <= commandsEnd else { break }
            let command = commandPointer.load(as: load_command.self)
            guard command.cmdsize >= MemoryLayout<load_command>.size,
                  commandPointer.advanced(by: Int(command.cmdsize)) <= commandsEnd else { break }
            defer { commandPointer = commandPointer.advanced(by: Int(command.cmdsize)) }

            if command.cmd == LC_SEGMENT_64 {
                let segment = commandPointer.load(as: segment_command_64.self)
                let segmentName = fixedMachOName(segment.segname)
                if segmentName == "__TEXT" {
                    preferredTextAddress = segment.vmaddr
                }
                if segmentName != "__LINKEDIT",
                   let preferredTextAddress,
                   segment.vmaddr >= preferredTextAddress {
                    upperBound = max(
                        upperBound,
                        regionAddress + (segment.vmaddr - preferredTextAddress) + segment.vmsize)
                }
            } else if command.cmd == LC_UUID {
                uuid = uuidString(commandPointer.load(as: uuid_command.self).uuid)
            } else if command.cmd == LC_ID_DYLIB {
                let dylibCommand = commandPointer.load(as: dylib_command.self)
                let stringOffset = Int(dylibCommand.dylib.name.offset)
                if stringOffset >= MemoryLayout<dylib_command>.size,
                   stringOffset < Int(command.cmdsize) {
                    let start = commandPointer.advanced(by: stringOffset)
                    let capacity = Int(command.cmdsize) - stringOffset
                    let bytes = UnsafeRawBufferPointer(start: start, count: capacity)
                    let end = bytes.firstIndex(of: 0) ?? bytes.endIndex
                    installName = String(decoding: bytes[..<end], as: UTF8.self)
                }
            }
        }

        let fallbackName = installName.map {
            URL(fileURLWithPath: $0).lastPathComponent
        }.flatMap { $0.isEmpty ? nil : $0 } ?? "mapped-image-\(String(regionAddress, radix: 16))"
        let path = resolvedMappedImagePath(
            installName: installName,
            imageName: fallbackName,
            jailbreakRoots: jailbreakRoots)
        return Image(
            baseAddress: regionAddress,
            upperBound: max(regionAddress + 1, upperBound) - 1,
            name: fallbackName,
            path: path,
            uuid: uuid,
            source: .hiddenVM)
    }

    private static func uuidString<T>(_ value: T) -> String {
        var value = value
        return withUnsafeBytes(of: &value) { bytes in
            bytes.map { String(format: "%02x", $0) }.joined()
        }
    }

    private static func fixedMachOName<T>(_ value: T) -> String {
        var value = value
        return withUnsafeBytes(of: &value) { bytes in
            let end = bytes.firstIndex(of: 0) ?? bytes.endIndex
            return String(decoding: bytes[..<end], as: UTF8.self)
        }
    }
}
