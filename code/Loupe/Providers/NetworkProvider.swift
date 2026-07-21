//
//  NetworkProvider.swift
//  Loupe
//
//  Network properties that require no permission: interface list from
//  getifaddrs, NWPathMonitor for the current network path, local
//  hostname. No outbound request is made, so the device never leaves
//  its own stack to produce these values.
//

import CFNetwork
import Foundation
import Network

final class NetworkProvider: SignalProvider, LiveSignalProvider {
    let category: SignalCategory = .network
    let updateInterval: TimeInterval = 3.0

    func collect() async -> [FingerprintSignal] {
        let path = await Self.firstPath()
        return Self.buildSignals(path: path, category: category)
    }

    func stream() -> AsyncStream<[FingerprintSignal]> {
        AsyncStream { continuation in
            let monitor = NWPathMonitor()
            let queue = DispatchQueue(label: "Loupe.NetworkProvider.Live")
            let category = self.category

            monitor.pathUpdateHandler = { path in
                Task { @MainActor in
                    continuation.yield(NetworkProvider.buildSignals(path: path, category: category))
                }
            }
            monitor.start(queue: queue)

            continuation.onTermination = { @Sendable _ in
                monitor.cancel()
            }
        }
    }

    @MainActor private static func buildSignals(path: NWPath?, category: SignalCategory) -> [FingerprintSignal] {
        let interfaceNames = IfAddrsHelper.interfaceNames()
        let upInterfaceNames = IfAddrsHelper.upInterfaceNames()
        let addresses = IfAddrsHelper.addresses()
        let hostname = IfAddrsHelper.hostname()

        var signals: [FingerprintSignal] = []
        signals.append(
            .make(
                "hostname",
                category: category,
                name: String(localized: "Local hostname", comment: "Signal card name in the Network category — system local hostname."),
                value: hostname ?? "unknown",
                rationale: String(localized: "The system's local hostname. Usually matches your device name.", comment: "Signal card rationale beneath the Local hostname value.")))
        if let path {
            signals.append(
                .make(
                    "isExpensive",
                    category: category,
                    name: String(localized: "isExpensive", comment: "Signal card name in the Network category — NWPath.isExpensive (typically true on cellular)."),
                    value: String(path.isExpensive),
                    rationale: String(localized: "Whether the current connection is considered expensive (typically cellular).", comment: "Signal card rationale beneath the isExpensive value.")))
            signals.append(
                .make(
                    "isConstrained",
                    category: category,
                    name: String(localized: "isConstrained", comment: "Signal card name in the Network category — NWPath.isConstrained (Low Data Mode)."),
                    value: String(path.isConstrained),
                    rationale: String(localized: "Whether Low Data Mode is on.", comment: "Signal card rationale beneath the isConstrained value.")))
            let availableInterfaceNames = path.availableInterfaces.map {
                "\(describeType($0.type)): \($0.name)"
            }
            let availableInterfaces = availableInterfaceNames.joined(separator: ", ")
            signals.append(
                .make(
                    "availableInterfaces",
                    category: category,
                    name: String(localized: "Available interfaces", comment: "Signal card name in the Network category — list of available NWInterface types."),
                    value: availableInterfaces.isEmpty ? "(none)" : availableInterfaces,
                    rationale: String(localized: "Network interface types present (e.g., cellular, Wi-Fi, wired).", comment: "Signal card rationale beneath the Available interfaces value."),
                    displayHint: availableInterfaceNames.isEmpty ? .plain : .tags,
                    entries: availableInterfaceNames.isEmpty ? nil : availableInterfaceNames.map { SignalEntry(label: $0, value: "") }))
            let activeInterfaceTypeNames = path.availableInterfaces
                .filter { path.usesInterfaceType($0.type) }
                .map { describeType($0.type) }
            let activeInterfaceTypes = activeInterfaceTypeNames.joined(separator: ", ")
            signals.append(
                .make(
                    "activeInterfaces",
                    category: category,
                    name: String(localized: "Active interface types", comment: "Signal card name in the Network category — NWInterface types used by the current NWPath."),
                    value: activeInterfaceTypes.isEmpty ? "(none)" : activeInterfaceTypes,
                    rationale: String(localized: "Network interface types used by the current connection.", comment: "Signal card rationale beneath the Active interface types value."),
                    displayHint: activeInterfaceTypeNames.isEmpty ? .plain : .tags,
                    entries: activeInterfaceTypeNames.isEmpty ? nil : activeInterfaceTypeNames.map { SignalEntry(label: $0, value: "") }))
        }
        signals.append(
            .make(
                "getifaddrsInterfaces",
                category: category,
                name: String(localized: "System interfaces", comment: "Signal card name in the Network category — all interface names returned by getifaddrs."),
                value: interfaceNames.isEmpty ? "(none)" : interfaceNames.joined(separator: ", "),
                rationale: String(localized: "Every network interface name returned by getifaddrs.", comment: "Signal card rationale beneath the System interfaces value."),
                displayHint: interfaceNames.isEmpty ? .plain : .tags,
                entries: interfaceNames.isEmpty ? nil : interfaceNames.map { SignalEntry(label: $0, value: "") }))
        signals.append(
            .make(
                "upInterfaces",
                category: category,
                name: String(localized: "Up interfaces", comment: "Signal card name in the Network category — interface names whose IFF_UP flag is set."),
                value: upInterfaceNames.isEmpty ? "(none)" : upInterfaceNames.joined(separator: ", "),
                rationale: String(localized: "Network interfaces marked as up by the system.", comment: "Signal card rationale beneath the Up interfaces value."),
                displayHint: upInterfaceNames.isEmpty ? .plain : .tags,
                entries: upInterfaceNames.isEmpty ? nil : upInterfaceNames.map { SignalEntry(label: $0, value: "") }))
        let vpn = vpnStatus()
        signals.append(
            .make(
                "vpnActive",
                category: category,
                name: String(localized: "VPN active (heuristic)", comment: "Signal card name in the Network category — heuristic detection of an active VPN tunnel."),
                value: vpn.active ? "true" : "false",
                rationale: String(localized: "Checks for VPN-related interface names (tap, tun, ipsec) in system proxy settings.", comment: "Signal card rationale beneath the VPN active (heuristic) value.")))
        if !vpn.interfaces.isEmpty {
            signals.append(
                .make(
                    "vpnInterfaces",
                    category: category,
                    name: String(localized: "VPN scoped proxy keys", comment: "Signal card name in the Network category — scoped proxy keys whose names suggest a VPN tunnel."),
                    value: vpn.interfaces.joined(separator: ", "),
                    rationale: String(localized: "Interface names that may indicate a VPN tunnel.", comment: "Signal card rationale beneath the VPN scoped proxy keys value."),
                    displayHint: .tags,
                    entries: vpn.interfaces.map { SignalEntry(label: $0, value: "") }))
        }
        let httpProxy = httpProxyStatus()
        signals.append(
            .make(
                "httpProxyActive",
                category: category,
                name: String(localized: "HTTP proxy active", comment: "Signal card name in the Network category — whether the system HTTP proxy is turned on."),
                value: httpProxy.active ? "true" : "false",
                rationale: String(localized: "Checks whether a system HTTP proxy is turned on.", comment: "Signal card rationale beneath the HTTP proxy active value.")))
        if let endpoint = httpProxy.endpoint {
            signals.append(
                .make(
                    "httpProxyEndpoint",
                    category: category,
                    name: String(localized: "HTTP proxy server", comment: "Signal card name in the Network category — the configured HTTP proxy host and port."),
                    value: endpoint,
                    rationale: String(localized: "The server and port used by the system HTTP proxy.", comment: "Signal card rationale beneath the HTTP proxy server value.")))
        }
        for (index, iface) in addresses.enumerated() {
            signals.append(
                .make(
                    "addr.\(index).\(iface.interface).\(iface.family)",
                    category: category,
                    name: "\(iface.interface) \(iface.family)",
                    value: iface.address,
                    rationale: String(localized: "Network interface address (local IP or cellular IP).", comment: "Signal card rationale beneath each per-interface address value.")))
        }
        return signals
    }

    private static func firstPath() async -> NWPath? {
        let state = PathSamplerState()
        return await withCheckedContinuation { (continuation: CheckedContinuation<NWPath?, Never>) in
            let monitor = NWPathMonitor()
            let queue = DispatchQueue(label: "Loupe.NetworkProvider")
            monitor.pathUpdateHandler = { path in
                state.lock.lock()
                defer { state.lock.unlock() }
                if !state.done {
                    state.done = true
                    monitor.cancel()
                    continuation.resume(returning: path)
                }
            }
            monitor.start(queue: queue)
            queue.asyncAfter(deadline: .now() + 1.2) {
                state.lock.lock()
                defer { state.lock.unlock() }
                if !state.done {
                    state.done = true
                    monitor.cancel()
                    continuation.resume(returning: nil)
                }
            }
        }
    }

    nonisolated private static func vpnStatus() -> (active: Bool, interfaces: [String]) {
        // Per Apple developer forums (thread/650650) and DTS guidance: scan
        // CFNetworkCopySystemProxySettings's __SCOPED__ dict for keys whose
        // names contain tap/tun/ppp/ipsec. `utun` is deliberately excluded —
        // iOS publishes utun interfaces for iCloud Private Relay, Personal
        // Hotspot relay, Handoff, AirDrop, etc., so its presence does not
        // imply a user VPN.
        let tunnelTokens = ["tap", "tun", "ppp", "ipsec"]
        var interfaces: [String] = []
        guard let raw = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any],
            let scoped = raw["__SCOPED__"] as? [String: Any]
        else {
            return (false, [])
        }
        for key in scoped.keys {
            if tunnelTokens.contains(where: { key.contains($0) }) {
                interfaces.append(key)
            }
        }
        interfaces.sort()
        return (!interfaces.isEmpty, interfaces)
    }

    nonisolated private static func httpProxyStatus() -> (active: Bool, endpoint: String?) {
        guard let settings = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any]
        else {
            return (false, nil)
        }

        let isEnabled = (settings[kCFNetworkProxiesHTTPEnable as String] as? NSNumber)?.boolValue == true
        guard isEnabled else { return (false, nil) }

        guard let host = settings[kCFNetworkProxiesHTTPProxy as String] as? String,
              !host.isEmpty
        else {
            return (true, nil)
        }
        let port = (settings[kCFNetworkProxiesHTTPPort as String] as? NSNumber)?.intValue
        return (true, port.map { "\(host):\($0)" } ?? host)
    }

    nonisolated private static func describeType(_ type: NWInterface.InterfaceType) -> String {
        switch type {
        case .wifi: return "wifi"
        case .cellular: return "cellular"
        case .wiredEthernet: return "wiredEthernet"
        case .loopback: return "loopback"
        case .other: return "other"
        @unknown default: return "unknown"
        }
    }
}

/// Shared by NWPathMonitor's update handler and timeout. The lock protects the
/// single-resume flag used before touching the continuation.
nonisolated private final class PathSamplerState: @unchecked Sendable {
    let lock = NSLock()
    var done = false
}
