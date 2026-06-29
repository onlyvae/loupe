//
//  PermissionCenter.swift
//  Loupe
//
//  One place to ask for every permission we care about, with a uniform
//  async return type. Delegate-based APIs (CLLocationManager, CBCentralManager)
//  are wrapped in one-shot continuations.
//

import AVFoundation
import CoreBluetooth
import CoreLocation
import Contacts
import EventKit
import Foundation
import Network
import Photos

#if os(iOS)
import CoreMotion
import MediaPlayer
#endif

@MainActor
final class PermissionCenter {
    private var locationCoordinator: LocationAuthCoordinator?
    private var bluetoothCoordinator: BluetoothAuthCoordinator?
    private var localNetworkPermissionProbe: LocalNetworkPermissionProbe?

    /// The central's lifetime is kept alive after the first probe so the
    /// authorization is remembered for the session.
    private(set) var bluetoothCentral: CBCentralManager?

    func request(_ kind: PermissionKind) async -> PermissionAuthorization {
        switch kind {
        case .motion: return await requestMotion()
        case .location: return await requestLocation()
        case .camera: return await requestCamera()
        case .bluetooth: return await requestBluetooth()
        case .localNetwork: return await requestLocalNetwork()
        case .contacts: return await requestContacts()
        case .photos: return await requestPhotos()
        case .calendar: return await requestCalendar()
        case .reminders: return await requestReminders()
        case .musicLibrary: return await requestMusicLibrary()
        }
    }

    // MARK: - Motion

    private func requestMotion() async -> PermissionAuthorization {
        #if os(iOS)
        guard CMMotionActivityManager.isActivityAvailable() else {
            return .unavailable(String(localized: "Motion activity unavailable on this device", comment: "Fallback message shown when motion activity is unavailable on this platform."))
        }
        let status = CMMotionActivityManager.authorizationStatus()
        if status != .notDetermined {
            return map(status)
        }
        return await Self.probeMotionAuthorization()
        #else
        return .unavailable(String(localized: "Motion is not available on macOS", comment: "Fallback message shown when motion is unavailable on this platform."))
        #endif
    }

    #if os(iOS)
    /// Triggers a one-shot activity query to prompt the user, then reads
    /// the resolved authorization. Marked `nonisolated` so the manager
    /// doesn't carry `@MainActor` isolation into the callback.
    nonisolated private static func probeMotionAuthorization() async -> PermissionAuthorization {
        await withCheckedContinuation { continuation in
            let manager = CMMotionActivityManager()
            let end = Date()
            let start = end.addingTimeInterval(-1)
            manager.queryActivityStarting(from: start, to: end, to: .main) { _, _ in
                let resolved = CMMotionActivityManager.authorizationStatus()
                manager.stopActivityUpdates()
                continuation.resume(returning: map(resolved))
            }
        }
    }
    #endif

    // MARK: - Location

    private func requestLocation() async -> PermissionAuthorization {
        let coordinator = locationCoordinator ?? LocationAuthCoordinator()
        locationCoordinator = coordinator
        return await coordinator.requestWhenInUse()
    }

    // MARK: - Camera

    private func requestCamera() async -> PermissionAuthorization {
        let status = AVCaptureDevice.authorizationStatus(for: .video)
        if status != .notDetermined { return map(status) }
        let granted = await AVCaptureDevice.requestAccess(for: .video)
        return granted ? .authorized : .denied
    }

    // MARK: - Bluetooth

    private func requestBluetooth() async -> PermissionAuthorization {
        let coordinator = bluetoothCoordinator ?? BluetoothAuthCoordinator()
        bluetoothCoordinator = coordinator
        let auth = await coordinator.request()
        bluetoothCentral = coordinator.central
        return auth
    }

    // MARK: - Local Network

    private func requestLocalNetwork() async -> PermissionAuthorization {
        // Local Network has no status API. Treat only an actually-ready
        // browser as usable; denial commonly surfaces as a waiting state.
        await withCheckedContinuation { continuation in
            let probe = LocalNetworkPermissionProbe()
            localNetworkPermissionProbe = probe
            probe.start(continuation: continuation)
        }
    }

    // MARK: - Contacts

    private func requestContacts() async -> PermissionAuthorization {
        let status = CNContactStore.authorizationStatus(for: .contacts)
        if status != .notDetermined { return map(status) }
        do {
            let granted = try await CNContactStore().requestAccess(for: .contacts)
            return granted ? .authorized : .denied
        } catch {
            return .denied
        }
    }

    // MARK: - Photos

    private func requestPhotos() async -> PermissionAuthorization {
        let current = PHPhotoLibrary.authorizationStatus(for: .readWrite)
        if current != .notDetermined { return map(current) }
        let status = await PHPhotoLibrary.requestAuthorization(for: .readWrite)
        return map(status)
    }

    // MARK: - Calendar

    private func requestCalendar() async -> PermissionAuthorization {
        let status = EKEventStore.authorizationStatus(for: .event)
        if status != .notDetermined { return map(status) }
        let store = EKEventStore()
        do {
            let granted: Bool
            if #available(iOS 17.0, macOS 14.0, *) {
                granted = try await store.requestFullAccessToEvents()
            } else {
                granted = try await store.requestAccess(to: .event)
            }
            return granted ? .authorized : .denied
        } catch {
            return .denied
        }
    }

    // MARK: - Reminders

    private func requestReminders() async -> PermissionAuthorization {
        let status = EKEventStore.authorizationStatus(for: .reminder)
        if status != .notDetermined { return map(status) }
        let store = EKEventStore()
        do {
            let granted: Bool
            if #available(iOS 17.0, macOS 14.0, *) {
                granted = try await store.requestFullAccessToReminders()
            } else {
                granted = try await store.requestAccess(to: .reminder)
            }
            return granted ? .authorized : .denied
        } catch {
            return .denied
        }
    }

    // MARK: - Music Library

    private func requestMusicLibrary() async -> PermissionAuthorization {
        #if os(iOS)
        let status = MPMediaLibrary.authorizationStatus()
        if status != .notDetermined {
            return Self.map(status)
        }
        let resolved = await withCheckedContinuation { (continuation: CheckedContinuation<MPMediaLibraryAuthorizationStatus, Never>) in
            MPMediaLibrary.requestAuthorization { resolved in
                continuation.resume(returning: resolved)
            }
        }
        return Self.map(resolved)
        #else
        return .unavailable(String(localized: "Music library is not available on macOS", comment: "Fallback message shown when music library is unavailable on this platform."))
        #endif
    }

    // MARK: - Mappers

    #if os(iOS)
    nonisolated static func map(_ status: CMAuthorizationStatus) -> PermissionAuthorization {
        switch status {
        case .notDetermined: return .notDetermined
        case .authorized: return .authorized
        case .denied: return .denied
        case .restricted: return .restricted
        @unknown default: return .denied
        }
    }
    #endif
    nonisolated static func map(_ status: AVAuthorizationStatus) -> PermissionAuthorization {
        switch status {
        case .authorized: return .authorized
        case .denied: return .denied
        case .restricted: return .restricted
        case .notDetermined: return .notDetermined
        @unknown default: return .denied
        }
    }
    nonisolated static func map(_ status: CNAuthorizationStatus) -> PermissionAuthorization {
        switch status {
        case .authorized, .limited: return .authorized
        case .denied: return .denied
        case .restricted: return .restricted
        case .notDetermined: return .notDetermined
        @unknown default: return .denied
        }
    }
    nonisolated static func map(_ status: PHAuthorizationStatus) -> PermissionAuthorization {
        switch status {
        case .authorized: return .authorized
        case .limited: return .limited
        case .denied: return .denied
        case .restricted: return .restricted
        case .notDetermined: return .notDetermined
        @unknown default: return .denied
        }
    }
    nonisolated static func map(_ status: EKAuthorizationStatus) -> PermissionAuthorization {
        switch status {
        case .authorized: return .authorized
        case .fullAccess: return .authorized
        case .writeOnly: return .authorized
        case .denied: return .denied
        case .restricted: return .restricted
        case .notDetermined: return .notDetermined
        @unknown default: return .denied
        }
    }
    nonisolated static func map(_ status: CLAuthorizationStatus) -> PermissionAuthorization {
        switch status {
        case .authorizedAlways, .authorizedWhenInUse: return .authorized
        case .denied: return .denied
        case .restricted: return .restricted
        case .notDetermined: return .notDetermined
        @unknown default: return .denied
        }
    }
    nonisolated static func map(_ status: CBManagerAuthorization) -> PermissionAuthorization {
        switch status {
        case .allowedAlways: return .authorized
        case .denied: return .denied
        case .restricted: return .restricted
        case .notDetermined: return .notDetermined
        @unknown default: return .denied
        }
    }
    #if os(iOS)
    nonisolated static func map(_ status: MPMediaLibraryAuthorizationStatus) -> PermissionAuthorization {
        switch status {
        case .authorized: return .authorized
        case .denied: return .denied
        case .restricted: return .restricted
        case .notDetermined: return .notDetermined
        @unknown default: return .denied
        }
    }
    #endif

    #if os(iOS)
    nonisolated func map(_ status: CMAuthorizationStatus) -> PermissionAuthorization { Self.map(status) }
    nonisolated func map(_ status: MPMediaLibraryAuthorizationStatus) -> PermissionAuthorization { Self.map(status) }
    #endif
    nonisolated func map(_ status: AVAuthorizationStatus) -> PermissionAuthorization { Self.map(status) }
    nonisolated func map(_ status: CNAuthorizationStatus) -> PermissionAuthorization { Self.map(status) }
    nonisolated func map(_ status: PHAuthorizationStatus) -> PermissionAuthorization { Self.map(status) }
    nonisolated func map(_ status: EKAuthorizationStatus) -> PermissionAuthorization { Self.map(status) }
    nonisolated func map(_ status: CLAuthorizationStatus) -> PermissionAuthorization { Self.map(status) }
    nonisolated func map(_ status: CBManagerAuthorization) -> PermissionAuthorization { Self.map(status) }
}

/// Shared between NWBrowser's queue and the caller's continuation. All mutable
/// state is protected by `lock`, and `finish` is the only resume path.
nonisolated private final class LocalNetworkPermissionProbe: @unchecked Sendable {
    private let lock = NSLock()
    private var resolved = false
    private var listener: NWListener?
    private var browser: NWBrowser?

    private static let probeType = "_loupe-probe._tcp"

    func start(continuation: CheckedContinuation<PermissionAuthorization, Never>) {
        let queue = DispatchQueue(label: "Loupe.LocalNetworkPermissionProbe")

        // Publish a listener so we have a guaranteed service to discover.
        let listener: NWListener
        do {
            listener = try NWListener(using: NWParameters(tls: .none, tcp: NWProtocolTCP.Options()))
        } catch {
            finish(.unavailable(error.localizedDescription), continuation)
            return
        }
        listener.service = NWListener.Service(name: UUID().uuidString, type: Self.probeType)
        listener.newConnectionHandler = { _ in }
        self.listener = listener

        listener.stateUpdateHandler = { [weak self] state in
            switch state {
            case .failed(let error):
                self?.finish(.unavailable(error.localizedDescription), continuation)
            case .cancelled:
                self?.finish(.unavailable(String(localized: "Listener cancelled", comment: "Fallback message shown when the local-network permission probe's listener was cancelled before resolving.")), continuation)
            default:
                break
            }
        }
        listener.start(queue: queue)

        // Browse for the self-published service.
        let params = NWParameters()
        params.includePeerToPeer = true
        let browser = NWBrowser(for: .bonjour(type: Self.probeType, domain: nil), using: params)
        self.browser = browser

        browser.stateUpdateHandler = { [weak self] state in
            switch state {
            case .waiting(let error):
                if Self.isPolicyDenied(error) {
                    self?.finish(.denied, continuation)
                }
            case .failed(let error):
                if Self.isPolicyDenied(error) {
                    self?.finish(.denied, continuation)
                } else {
                    self?.finish(.unavailable(error.localizedDescription), continuation)
                }
            case .cancelled:
                self?.finish(.unavailable(String(localized: "Browser cancelled", comment: "Fallback message shown when the local-network permission probe's browser was cancelled before resolving.")), continuation)
            default:
                break
            }
        }

        browser.browseResultsChangedHandler = { [weak self] results, _ in
            guard !results.isEmpty else { return }
            self?.finish(.authorized, continuation)
        }

        browser.start(queue: queue)

        queue.asyncAfter(deadline: .now() + 3.0) { [weak self] in
            self?.finish(.unavailable(String(localized: "Local Network permission result unknown", comment: "Fallback message shown when the local-network permission probe timed out without a clear allow/deny result.")), continuation)
        }
    }

    private func finish(_ authorization: PermissionAuthorization,
                        _ continuation: CheckedContinuation<PermissionAuthorization, Never>) {
        lock.lock()
        guard !resolved else { lock.unlock(); return }
        resolved = true
        let listener = self.listener
        let browser = self.browser
        self.listener = nil
        self.browser = nil
        lock.unlock()

        listener?.cancel()
        browser?.cancel()
        continuation.resume(returning: authorization)
    }

    private static func isPolicyDenied(_ error: NWError) -> Bool {
        if case .dns(let dnsError) = error, dnsError == kDNSServiceErr_PolicyDenied {
            return true
        }
        return false
    }
}

// MARK: - Location Coordinator

@MainActor
final class LocationAuthCoordinator: NSObject, CLLocationManagerDelegate {
    private let manager = CLLocationManager()
    private var pending: [CheckedContinuation<PermissionAuthorization, Never>] = []

    override init() {
        super.init()
        manager.delegate = self
    }

    func requestWhenInUse() async -> PermissionAuthorization {
        if manager.authorizationStatus != .notDetermined {
            return PermissionCenter.map(manager.authorizationStatus)
        }
        return await withCheckedContinuation { continuation in
            let shouldStart = pending.isEmpty
            pending.append(continuation)
            if shouldStart {
                manager.requestWhenInUseAuthorization()
            }
        }
    }

    nonisolated func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        let status = manager.authorizationStatus
        Task { @MainActor in
            guard status != .notDetermined else { return }
            self.resolve(PermissionCenter.map(status))
        }
    }

    private func resolve(_ authorization: PermissionAuthorization) {
        guard !pending.isEmpty else { return }
        let continuations = pending
        pending.removeAll()
        for continuation in continuations {
            continuation.resume(returning: authorization)
        }
    }
}

// MARK: - Bluetooth Coordinator

@MainActor
final class BluetoothAuthCoordinator: NSObject, CBCentralManagerDelegate {
    private(set) var central: CBCentralManager?
    private var pending: [CheckedContinuation<PermissionAuthorization, Never>] = []

    func request() async -> PermissionAuthorization {
        let auth = CBCentralManager.authorization
        if central != nil, auth != .notDetermined {
            return PermissionCenter.map(CBCentralManager.authorization)
        }
        return await withCheckedContinuation { continuation in
            pending.append(continuation)
            if central == nil {
                central = CBCentralManager(delegate: self, queue: nil)
            }
        }
    }

    nonisolated func centralManagerDidUpdateState(_ central: CBCentralManager) {
        let auth = CBCentralManager.authorization

        Task { @MainActor [weak self] in
            guard let self else { return }
            guard auth != .notDetermined else { return }
            guard self.central != nil else { return }

            self.resolve(PermissionCenter.map(auth))
        }
    }

    private func resolve(_ authorization: PermissionAuthorization) {
        guard !pending.isEmpty else { return }
        let continuations = pending
        pending.removeAll()
        for continuation in continuations {
            continuation.resume(returning: authorization)
        }
    }
}
