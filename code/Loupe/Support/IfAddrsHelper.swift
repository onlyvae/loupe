//
//  IfAddrsHelper.swift
//  Loupe
//
//  Enumerates every network interface address the device currently holds
//  via getifaddrs(3). This is how passive IP fingerprinting works on iOS:
//  the kernel will happily list en0, en1, awdl0, utun0, pdp_ip0, lo0 etc.
//

import Darwin
import Foundation

struct InterfaceAddress: Identifiable, Hashable, Sendable {
    let id: String
    let interface: String
    let family: String
    let address: String
}

nonisolated enum IfAddrsHelper {
    static func interfaceNames() -> [String] {
        interfaceNames(requiredFlags: 0)
    }

    static func upInterfaceNames() -> [String] {
        interfaceNames(requiredFlags: Int32(IFF_UP))
    }

    private static func interfaceNames(requiredFlags: Int32) -> [String] {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return [] }
        defer { freeifaddrs(head) }

        var names: [String] = []
        var seen: Set<String> = []
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let node = cursor {
            let flags = Int32(node.pointee.ifa_flags)
            if (flags & requiredFlags) == requiredFlags {
                let name = String(cString: node.pointee.ifa_name)
                if seen.insert(name).inserted {
                    names.append(name)
                }
            }
            cursor = node.pointee.ifa_next
        }
        return names
    }

    static func addresses() -> [InterfaceAddress] {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return [] }
        defer { freeifaddrs(head) }

        var results: [InterfaceAddress] = []
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let node = cursor {
            let flags = Int32(node.pointee.ifa_flags)
            if let sockaddr = node.pointee.ifa_addr,
                (flags & IFF_UP) == IFF_UP,
                (flags & IFF_RUNNING) == IFF_RUNNING
            {
                let family = sockaddr.pointee.sa_family
                if family == UInt8(AF_INET) || family == UInt8(AF_INET6) {
                    let name = String(cString: node.pointee.ifa_name)
                    var hostBuffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                    let saLen = socklen_t(sockaddr.pointee.sa_len)
                    let result = getnameinfo(
                        sockaddr,
                        saLen,
                        &hostBuffer,
                        socklen_t(hostBuffer.count),
                        nil,
                        0,
                        NI_NUMERICHOST
                    )
                    if result == 0 {
                        let address = String(cString: hostBuffer)
                        let familyName = (family == UInt8(AF_INET)) ? "IPv4" : "IPv6"
                        let identifier = "\(name).\(familyName).\(address)"
                        results.append(
                            InterfaceAddress(
                                id: identifier,
                                interface: name,
                                family: familyName,
                                address: address
                            )
                        )
                    }
                }
            }
            cursor = node.pointee.ifa_next
        }
        return results
    }

    static func hostname() -> String? {
        var buffer = [CChar](repeating: 0, count: 256)
        if gethostname(&buffer, buffer.count) == 0 {
            return String(cString: buffer)
        }
        return nil
    }
}
