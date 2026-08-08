//
//  OnboardingView.swift
//  Loupe
//
//  Root onboarding container shown on first launch. Renders the
//  animated gradient behind a native paged TabView so the background
//  stays continuous across page transitions, then flips the
//  @AppStorage flag when the user finishes.
//

import SwiftUI

struct OnboardingView: View {
    @Binding var showOnboarding: Bool
    @State private var currentPage = 0

    private let pages = OnboardingContent.pages

    var body: some View {
        CompatibleNavigationStack {
            ZStack {
                OnboardingGradientBackground()
                VStack(spacing: 0) {
                    pager
                    bottomBar
                }
            }
        }
    }

    // MARK: - Pager

    private var pager: some View {
        TabView(selection: $currentPage) {
            ForEach(Array(pages.enumerated()), id: \.element.id) { index, page in
                OnboardingPageView(page: page)
                    .tag(index)
            }
        }
        #if os(iOS)
        .tabViewStyle(.page(indexDisplayMode: .always))
        #endif
    }

    // MARK: - Bottom bar

    private var bottomBar: some View {
        VStack(spacing: 16) {
            HStack(spacing: 12) {
                if currentPage > 0 {
                    Button {
                        goToPage(currentPage - 1)
                    } label: {
                        Text("Back")
                            .fontWeight(.semibold)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 6)
                    }
                    .compatibleBorderedButtonStyle()
                }

                Button {
                    advance()
                } label: {
                    Text(isLastPage ? "Let's Go" : "Next")
                        .fontWeight(.semibold)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 6)
                        .foregroundStyle(.black)
                }
                .compatibleProminentButtonStyle()
                .accessibilityIdentifier("onboardingAdvanceButton")
            }
            .controlSize(.large)
            .frame(maxWidth: 560)
        }
        .animation(.default, value: currentPage)
        .padding(.horizontal, 24)
        .padding(.bottom, 24)
        .padding(.top, 8)
    }

    // MARK: - Actions

    private var isLastPage: Bool {
        currentPage == pages.count - 1
    }

    private func advance() {
        if isLastPage {
            showOnboarding = false
        } else {
            goToPage(currentPage + 1)
        }
    }

    private func goToPage(_ page: Int) {
        let clampedPage = min(max(page, 0), pages.count - 1)
        guard clampedPage != currentPage else { return }
        withAnimation {
            currentPage = clampedPage
        }
    }
}

#Preview {
    OnboardingView(showOnboarding: .constant(true))
}
