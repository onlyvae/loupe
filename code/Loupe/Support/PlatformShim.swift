//
//  PlatformShim.swift
//  Loupe
//
//  Cross-platform abstraction layer so the rest of the codebase can
//  avoid `#if os(…)` conditionals. On iOS each wrapper delegates to
//  UIKit; on macOS it uses AppKit, IOKit, or Foundation equivalents.
//

import CoreText
import Foundation
import SwiftUI

#if os(iOS)
import UIKit
#elseif os(macOS)
import AppKit
import Carbon.HIToolbox
import IOKit.ps
#endif

// MARK: - PlatformDevice
@MainActor
enum PlatformDevice {

    static var name: String {
        #if os(iOS)
        return UIDevice.current.name
        #else
        return Host.current().localizedName ?? ProcessInfo.processInfo.hostName
        #endif
    }

    static var systemName: String {
        #if os(iOS)
        return UIDevice.current.systemName
        #else
        return "macOS"
        #endif
    }

    static var systemVersion: String {
        #if os(iOS)
        return UIDevice.current.systemVersion
        #else
        let v = ProcessInfo.processInfo.operatingSystemVersion
        return "\(v.majorVersion).\(v.minorVersion).\(v.patchVersion)"
        #endif
    }

    static var identifierForVendor: UUID? {
        #if os(iOS)
        return UIDevice.current.identifierForVendor
        #else
        return macSerialBasedUUID()
        #endif
    }

    static var localizedModel: String {
        #if os(iOS)
        return UIDevice.current.localizedModel
        #else
        return "Mac"
        #endif
    }

    static var modelIdentifier: String? {
        SysctlHelper.modelIdentifier()
    }

    static var marketingName: String {
        guard let identifier = modelIdentifier else { return PlatformDevice.name }
        return DeviceModelNames.marketingName(for: identifier) ?? PlatformDevice.name
    }

    // MARK: Battery

    static var isBatteryMonitoringEnabled: Bool {
        get {
            #if os(iOS)
            return UIDevice.current.isBatteryMonitoringEnabled
            #else
            return true
            #endif
        }
        set {
            #if os(iOS)
            UIDevice.current.isBatteryMonitoringEnabled = newValue
            #endif
        }
    }

    static var batteryLevel: Float {
        #if os(iOS)
        return UIDevice.current.batteryLevel
        #else
        return macBatteryLevel()
        #endif
    }

    static var batteryState: String {
        #if os(iOS)
        return describeBatteryState(UIDevice.current.batteryState)
        #else
        return macBatteryState()
        #endif
    }

    // MARK: - Private helpers

    #if os(iOS)
    private static func describeBatteryState(_ state: UIDevice.BatteryState) -> String {
        switch state {
        case .unknown: return "unknown"
        case .unplugged: return "unplugged"
        case .charging: return "charging"
        case .full: return "full"
        @unknown default: return "unknown"
        }
    }
    #endif

    #if os(macOS)
    private static func macBatteryLevel() -> Float {
        guard let snapshot = IOPSCopyPowerSourcesInfo()?.takeRetainedValue(),
              let sources = IOPSCopyPowerSourcesList(snapshot)?.takeRetainedValue() as? [CFTypeRef],
              let first = sources.first,
              let desc = IOPSGetPowerSourceDescription(snapshot, first)?.takeUnretainedValue() as? [String: Any],
              let capacity = desc[kIOPSCurrentCapacityKey] as? Int,
              let max = desc[kIOPSMaxCapacityKey] as? Int, max > 0
        else { return -1 }
        return Float(capacity) / Float(max)
    }

    private static func macBatteryState() -> String {
        guard let snapshot = IOPSCopyPowerSourcesInfo()?.takeRetainedValue(),
              let sources = IOPSCopyPowerSourcesList(snapshot)?.takeRetainedValue() as? [CFTypeRef],
              let first = sources.first,
              let desc = IOPSGetPowerSourceDescription(snapshot, first)?.takeUnretainedValue() as? [String: Any]
        else { return "unknown" }
        if let charging = desc[kIOPSIsChargingKey] as? Bool {
            if charging { return "charging" }
            if let level = desc[kIOPSCurrentCapacityKey] as? Int,
               let max = desc[kIOPSMaxCapacityKey] as? Int,
               level >= max { return "full" }
            return "unplugged"
        }
        if let source = desc[kIOPSPowerSourceStateKey] as? String,
           source == kIOPSACPowerValue { return "AC power" }
        return "unknown"
    }

    private static func macSerialBasedUUID() -> UUID? {
        let matching = IOServiceMatching("IOPlatformExpertDevice")
        let service = IOServiceGetMatchingService(kIOMainPortDefault, matching)
        defer { IOObjectRelease(service) }
        guard service != 0,
              let data = IORegistryEntryCreateCFProperty(
                  service, "IOPlatformUUID" as CFString, kCFAllocatorDefault, 0)?
                  .takeRetainedValue() as? String
        else { return nil }
        return UUID(uuidString: data)
    }
    #endif
}

// MARK: - PlatformPasteboard

enum PlatformPasteboard {

    static var changeCount: Int {
        #if os(iOS)
        return UIPasteboard.general.changeCount
        #else
        return NSPasteboard.general.changeCount
        #endif
    }

    static var hasStrings: Bool {
        #if os(iOS)
        return UIPasteboard.general.hasStrings
        #else
        return NSPasteboard.general.canReadItem(withDataConformingToTypes: [NSPasteboard.PasteboardType.string.rawValue])
        #endif
    }

    static var hasURLs: Bool {
        #if os(iOS)
        return UIPasteboard.general.hasURLs
        #else
        return NSPasteboard.general.canReadItem(withDataConformingToTypes: [NSPasteboard.PasteboardType.URL.rawValue])
        #endif
    }

    static var hasImages: Bool {
        #if os(iOS)
        return UIPasteboard.general.hasImages
        #else
        return NSPasteboard.general.canReadItem(withDataConformingToTypes: [NSPasteboard.PasteboardType.tiff.rawValue, NSPasteboard.PasteboardType.png.rawValue])
        #endif
    }

    static var hasColors: Bool {
        #if os(iOS)
        return UIPasteboard.general.hasColors
        #else
        return NSPasteboard.general.canReadItem(withDataConformingToTypes: [NSPasteboard.PasteboardType.color.rawValue])
        #endif
    }

    static var numberOfItems: Int {
        #if os(iOS)
        return UIPasteboard.general.numberOfItems
        #else
        return NSPasteboard.general.pasteboardItems?.count ?? 0
        #endif
    }

    static func setString(_ string: String) {
        #if os(iOS)
        UIPasteboard.general.string = string
        #else
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(string, forType: .string)
        #endif
    }
}

// MARK: - PlatformFont

/// CoreText is thread-safe, so reading the installed font family list
/// off the main actor is fine and avoids the cold-launch hit that
/// `UIFont.familyNames` / `NSFontManager.shared` would incur.
enum PlatformFont {
    static var familyNames: [String] {
        (CTFontManagerCopyAvailableFontFamilyNames() as? [String]) ?? []
    }
}

// MARK: - PlatformAccessibility
@MainActor
enum PlatformAccessibility {
    static var isVoiceOverRunning: Bool {
        #if os(iOS)
        return UIAccessibility.isVoiceOverRunning
        #else
        return NSWorkspace.shared.isVoiceOverEnabled
        #endif
    }

    static var isSwitchControlRunning: Bool {
        #if os(iOS)
        return UIAccessibility.isSwitchControlRunning
        #else
        return NSWorkspace.shared.isSwitchControlEnabled
        #endif
    }

    static var isReduceMotionEnabled: Bool {
        #if os(iOS)
        return UIAccessibility.isReduceMotionEnabled
        #else
        return NSWorkspace.shared.accessibilityDisplayShouldReduceMotion
        #endif
    }

    static var isBoldTextEnabled: Bool {
        #if os(iOS)
        return UIAccessibility.isBoldTextEnabled
        #else
        return false
        #endif
    }

    static var isDarkerSystemColorsEnabled: Bool {
        #if os(iOS)
        return UIAccessibility.isDarkerSystemColorsEnabled
        #else
        return NSWorkspace.shared.accessibilityDisplayShouldIncreaseContrast
        #endif
    }

    static var isReduceTransparencyEnabled: Bool {
        #if os(iOS)
        return UIAccessibility.isReduceTransparencyEnabled
        #else
        return NSWorkspace.shared.accessibilityDisplayShouldReduceTransparency
        #endif
    }

    static var shouldDifferentiateWithoutColor: Bool {
        #if os(iOS)
        return UIAccessibility.shouldDifferentiateWithoutColor
        #else
        return NSWorkspace.shared.accessibilityDisplayShouldDifferentiateWithoutColor
        #endif
    }

    static var buttonShapesEnabled: Bool {
        #if os(iOS)
        return UIAccessibility.buttonShapesEnabled
        #else
        return false
        #endif
    }

    static var isOnOffSwitchLabelsEnabled: Bool {
        #if os(iOS)
        return UIAccessibility.isOnOffSwitchLabelsEnabled
        #else
        return false
        #endif
    }

    static var isGuidedAccessEnabled: Bool {
        #if os(iOS)
        return UIAccessibility.isGuidedAccessEnabled
        #else
        return false
        #endif
    }

    static var isGrayscaleEnabled: Bool {
        #if os(iOS)
        return UIAccessibility.isGrayscaleEnabled
        #else
        return false
        #endif
    }

    static var isInvertColorsEnabled: Bool {
        #if os(iOS)
        return UIAccessibility.isInvertColorsEnabled
        #else
        return NSWorkspace.shared.accessibilityDisplayShouldInvertColors
        #endif
    }

    static var isAssistiveTouchRunning: Bool {
        #if os(iOS)
        return UIAccessibility.isAssistiveTouchRunning
        #else
        return false
        #endif
    }

    static var isShakeToUndoEnabled: Bool {
        #if os(iOS)
        return UIAccessibility.isShakeToUndoEnabled
        #else
        return false
        #endif
    }

    static var isMonoAudioEnabled: Bool {
        #if os(iOS)
        return UIAccessibility.isMonoAudioEnabled
        #else
        return false
        #endif
    }

    static var isSpeakScreenEnabled: Bool {
        #if os(iOS)
        return UIAccessibility.isSpeakScreenEnabled
        #else
        return false
        #endif
    }

    static var isSpeakSelectionEnabled: Bool {
        #if os(iOS)
        return UIAccessibility.isSpeakSelectionEnabled
        #else
        return false
        #endif
    }

    static var isClosedCaptioningEnabled: Bool {
        #if os(iOS)
        return UIAccessibility.isClosedCaptioningEnabled
        #else
        return false
        #endif
    }

    static var isVideoAutoplayEnabled: Bool {
        #if os(iOS)
        return UIAccessibility.isVideoAutoplayEnabled
        #else
        return true
        #endif
    }
}

// MARK: - PlatformApplication
@MainActor
enum PlatformApplication {

    static func canOpenURL(_ url: URL) -> Bool {
        #if os(iOS)
        return UIApplication.shared.canOpenURL(url)
        #else
        return NSWorkspace.shared.urlForApplication(toOpen: url) != nil
        #endif
    }

    static var openSettingsURL: URL {
        #if os(iOS)
        return URL(string: UIApplication.openSettingsURLString)!
        #else
        return URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy")!
        #endif
    }

    static var preferredContentSizeCategory: String {
        #if os(iOS)
        return UIApplication.shared.preferredContentSizeCategory.rawValue
        #else
        return "UICTContentSizeCategoryL"
        #endif
    }

    static var preferredContentSizeCategoryIsLarge: Bool {
        #if os(iOS)
        return UIApplication.shared.preferredContentSizeCategory > .large
        #else
        return false
        #endif
    }

    static var preferredContentSizeCategoryIsAccessibility: Bool {
        #if os(iOS)
        return UIApplication.shared.preferredContentSizeCategory.isAccessibilityCategory
        #else
        return false
        #endif
    }
}

// MARK: - PlatformScreen

@MainActor
enum PlatformScreen {

    struct DisplayInfo {
        var nativeBounds: CGRect = .zero
        var scale: CGFloat = 1
        var nativeScale: CGFloat = 1
        var maximumFramesPerSecond: Int = 60
        var brightness: CGFloat = -1
        var displayGamut: String = "unspecified"
        var horizontalSizeClass: String = "unspecified"
        var verticalSizeClass: String = "unspecified"
        var preferredContentSizeCategory: String = "UICTContentSizeCategoryL"
        var safeAreaInsets: (top: CGFloat, left: CGFloat, bottom: CGFloat, right: CGFloat) = (0, 0, 0, 0)
        var isCaptured: Bool?
        var userInterfaceStyle: String = "unspecified"
        var accessibilityContrast: String = "normal"
    }

    static func displayInfo() -> DisplayInfo? {
        #if os(iOS)
        guard
            let scene = UIApplication.shared.connectedScenes
                .first(where: { $0.activationState != .unattached }) as? UIWindowScene,
            let window = scene.windows.first
        else { return nil }

        let screen = scene.screen
        let traits = window.traitCollection
        let insets = window.safeAreaInsets

        return DisplayInfo(
            nativeBounds: screen.nativeBounds,
            scale: screen.scale,
            nativeScale: screen.nativeScale,
            maximumFramesPerSecond: screen.maximumFramesPerSecond,
            brightness: screen.brightness,
            displayGamut: describeGamut(traits.displayGamut),
            horizontalSizeClass: describeSizeClass(traits.horizontalSizeClass),
            verticalSizeClass: describeSizeClass(traits.verticalSizeClass),
            preferredContentSizeCategory: traits.preferredContentSizeCategory.rawValue,
            safeAreaInsets: (insets.top, insets.left, insets.bottom, insets.right),
            isCaptured: screen.isCaptured,
            userInterfaceStyle: describeStyle(traits.userInterfaceStyle),
            accessibilityContrast: describeContrast(traits.accessibilityContrast)
        )
        #else
        guard let screen = NSScreen.main else { return nil }
        let frame = screen.frame
        let backing = screen.backingScaleFactor
        let style: String
        if NSApp.effectiveAppearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua {
            style = "dark"
        } else {
            style = "light"
        }
        let contrast = NSWorkspace.shared.accessibilityDisplayShouldIncreaseContrast ? "high" : "normal"
        return DisplayInfo(
            nativeBounds: CGRect(x: 0, y: 0, width: frame.width * backing, height: frame.height * backing),
            scale: backing,
            nativeScale: backing,
            maximumFramesPerSecond: screen.maximumFramesPerSecond,
            brightness: -1,
            displayGamut: screen.colorSpace?.colorSpaceModel == .rgb ? "P3" : "sRGB",
            horizontalSizeClass: "regular",
            verticalSizeClass: "regular",
            preferredContentSizeCategory: "UICTContentSizeCategoryL",
            safeAreaInsets: (screen.safeAreaInsets.top, screen.safeAreaInsets.left, screen.safeAreaInsets.bottom, screen.safeAreaInsets.right),
            userInterfaceStyle: style,
            accessibilityContrast: contrast
        )
        #endif
    }

    #if os(iOS)
    private static func describeGamut(_ gamut: UIDisplayGamut) -> String {
        switch gamut {
        case .P3: return "P3"
        case .SRGB: return "sRGB"
        case .unspecified: return "unspecified"
        @unknown default: return "unknown"
        }
    }

    private static func describeSizeClass(_ sc: UIUserInterfaceSizeClass) -> String {
        switch sc {
        case .compact: return "compact"
        case .regular: return "regular"
        case .unspecified: return "unspecified"
        @unknown default: return "unknown"
        }
    }

    private static func describeStyle(_ style: UIUserInterfaceStyle) -> String {
        switch style {
        case .dark: return "dark"
        case .light: return "light"
        case .unspecified: return "unspecified"
        @unknown default: return "unknown"
        }
    }

    private static func describeContrast(_ contrast: UIAccessibilityContrast) -> String {
        switch contrast {
        case .normal: return "normal"
        case .high: return "high"
        case .unspecified: return "unspecified"
        @unknown default: return "unknown"
        }
    }
    #endif
}

// MARK: - PlatformTextInput
@MainActor
enum PlatformTextInput {
    static func keyboardLanguageCodes() -> [String] {
        #if os(iOS)
        var seen = Set<String>()
        var ordered: [String] = []
        for mode in UITextInputMode.activeInputModes {
            guard let lang = mode.primaryLanguage else { continue }
            let base = String(lang.prefix { $0 != "-" })
            guard base != "emoji", !base.isEmpty else { continue }
            if seen.insert(base).inserted {
                ordered.append(base)
            }
        }
        return ordered
        #else
        let filter: CFDictionary = [
            kTISPropertyInputSourceIsSelectCapable: true,
            kTISPropertyInputSourceIsEnabled: true,
            kTISPropertyInputSourceCategory: kTISCategoryKeyboardInputSource!,
        ] as CFDictionary
        guard let list = TISCreateInputSourceList(filter, false)?.takeRetainedValue() as? [TISInputSource]
        else { return [] }
        var seen = Set<String>()
        var ordered: [String] = []
        for source in list {
            guard let ptr = TISGetInputSourceProperty(source, kTISPropertyInputSourceLanguages),
                  let langs = Unmanaged<CFArray>.fromOpaque(ptr).takeUnretainedValue() as? [String],
                  let primary = langs.first
            else { continue }
            let base = String(primary.prefix { $0 != "-" && $0 != "_" })
            guard !base.isEmpty else { continue }
            if seen.insert(base).inserted {
                ordered.append(base)
            }
        }
        return ordered
        #endif
    }
}

// MARK: - Cross-platform SwiftUI modifiers

extension View {
    @ViewBuilder
    func platformInsetGroupedListStyle() -> some View {
        #if os(iOS)
        listStyle(.insetGrouped)
        #else
        listStyle(.inset)
        #endif
    }

    @ViewBuilder
    func platformInlineNavigationBarTitle() -> some View {
        #if os(iOS)
        navigationBarTitleDisplayMode(.inline)
        #else
        self
        #endif
    }

    /// Presents `content` as a sheet when both size classes are regular
    /// (iPad, Mac) and as a full-screen cover otherwise (iPhone).
    @ViewBuilder
    func adaptiveModalPresentation<Modal: View>(
        isPresented: Binding<Bool>,
        @ViewBuilder content: @escaping () -> Modal
    ) -> some View {
        #if os(iOS)
        modifier(AdaptiveModalPresentation(isPresented: isPresented, modalContent: content))
        #else
        sheet(isPresented: isPresented) {
            content()
                .frame(minWidth: 520, minHeight: 640)
        }
        #endif
    }
}

#if os(iOS)
private struct AdaptiveModalPresentation<Modal: View>: ViewModifier {
    @Binding var isPresented: Bool
    let modalContent: () -> Modal
    @Environment(\.horizontalSizeClass) private var horizontalSizeClass
    @Environment(\.verticalSizeClass) private var verticalSizeClass

    func body(content: Content) -> some View {
        if horizontalSizeClass == .regular, verticalSizeClass == .regular {
            content.sheet(isPresented: $isPresented, content: modalContent)
        } else {
            content.fullScreenCover(isPresented: $isPresented, content: modalContent)
        }
    }
}
#endif

// MARK: - Cross-platform colors

extension Color {
    static var platformBackground: Color {
        #if os(iOS)
        Color(UIColor.systemBackground)
        #else
        Color(NSColor.windowBackgroundColor)
        #endif
    }
}
