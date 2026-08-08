//
//  CameraProvider.swift
//  Loupe
//
//  AVCaptureDevice.DiscoverySession enumerates every camera the device
//  has. The list of device types, their min/max zoom, apertures and
//  fields of view is basically a serial number for the iPhone model.
//

import AVFoundation

@MainActor
struct CameraProvider: SignalProvider {
    let category: SignalCategory = .camera
    let center: PermissionCenter

    func collect() async -> [FingerprintSignal] {
        var types: [AVCaptureDevice.DeviceType] = [.builtInWideAngleCamera]
        if #available(iOS 17.0, macOS 14.0, *) {
            types.append(contentsOf: [.external, .continuityCamera])
        }
        #if os(iOS)
        types.append(contentsOf: [
            .builtInUltraWideCamera,
            .builtInTelephotoCamera,
            .builtInDualCamera,
            .builtInDualWideCamera,
            .builtInTripleCamera,
            .builtInTrueDepthCamera,
        ])
        if #available(iOS 15.4, *) {
            types.append(.builtInLiDARDepthCamera)
        }
        #endif
        let discovery = AVCaptureDevice.DiscoverySession(
            deviceTypes: types,
            mediaType: .video,
            position: .unspecified)

        var signals: [FingerprintSignal] = []
        let devices = discovery.devices
        signals.append(
            .make(
                "deviceCount",
                category: category,
                name: String(localized: "Camera count", comment: "Signal card name in the Cameras category — total number of cameras the device exposes (physical and virtual)."),
                value: String(devices.count),
                rationale: String(localized: "Number of cameras on your \(PlatformDevice.localizedModel). The count also includes \"virtual\" cameras that simulate various focal lengths.", comment: "Signal card rationale beneath the Camera count value. %@ is the device model name (e.g., iPhone, iPad).")))
        for (index, device) in devices.enumerated() {
            let ident = "cam.\(index).\(device.deviceType.rawValue)"
            let position: String
            switch device.position {
            case .front: position = "front"
            case .back: position = "back"
            case .unspecified: position = "unspecified"
            @unknown default: position = "unknown"
            }
            #if os(iOS)
            let fov = device.formats.first.map { Int($0.videoFieldOfView) }
            let typeValue: String
            if let fov, fov > 0 {
                typeValue = "\(device.localizedName) (\(position)) · FOV \(fov)°"
            } else {
                typeValue = "\(device.localizedName) (\(position))"
            }
            #else
            let typeValue = "\(device.localizedName) (\(position))"
            #endif
            signals.append(
                .make(
                    ident + ".type",
                    category: category,
                    name: String(localized: "Camera \(index)", comment: "Signal card name in the Cameras category — describes a single camera by index. %lld is the zero-based camera index in the enumeration."),
                    value: typeValue,
                    rationale: String(localized: "Lens type, position, and field of view.", comment: "Signal card rationale beneath a per-camera entry.")))
            signals.append(
                .make(
                    ident + ".uniqueID",
                    category: category,
                    name: String(localized: "Camera \(index) uniqueID", comment: "Signal card name in the Cameras category — Apple's uniqueID property for a single camera. %lld is the zero-based camera index in the enumeration."),
                    value: device.uniqueID,
                    rationale: String(localized: "Hardware identifier for this camera. Stable across apps with camera permission.", comment: "Signal card rationale beneath a per-camera uniqueID value.")))
        }
        return signals
    }
}
