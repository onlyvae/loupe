//
//  LoupeApp.swift
//  Loupe
//

import SwiftUI

@main
struct LoupeApp: App {
    @AppStorage("showOnboarding") private var showOnboarding = true

    init() {
        KeychainInstallLog.shared.recordLaunch()
    }

    var body: some Scene {
        WindowGroup {
            HomeView()
                .adaptiveModalPresentation(isPresented: onboardingPresented) {
                    OnboardingView(showOnboarding: onboardingPresented)
                }
        }
    }

    /// In screenshot mode onboarding visibility is fixed by launch arguments so
    /// every screen is reachable deterministically: hidden by default, shown
    /// only when `-LoupeShowOnboarding` is passed. Otherwise it tracks the
    /// persisted `showOnboarding` flag as usual.
    private var onboardingPresented: Binding<Bool> {
        if ScreenshotMode.isActive {
            return .constant(ScreenshotMode.showsOnboarding)
        }
        return $showOnboarding
    }
}
