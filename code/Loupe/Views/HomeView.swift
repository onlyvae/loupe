//
//  HomeView.swift
//  Loupe
//
//  The top-level navigation surface. Driven entirely by CategoryStore
//  and SignalCategory.allCases; no strings are baked into this view.
//

import SwiftUI

struct HomeView: View {
    @StateObject private var store = ScreenshotMode.isActive
        ? CategoryStore(mockSignals: MockData.signals)
        : CategoryStore()
    @State private var collectingPassive = false
    @State private var showingSummary = false
    @Namespace private var transitionNamespace

    @ViewBuilder
    var body: some View {
        Group {
            if #available(iOS 16.0, macOS 13.0, *) {
                modernNavigation
            } else {
                legacyNavigation
            }
        }
        .platformInlineNavigationBarTitle()
        .sheet(isPresented: $showingSummary) {
            FingerprintSummaryView()
                .compatibleZoomNavigationTransition(sourceID: TransitionID.highlights, in: transitionNamespace)
        }
        .task {
            if !collectingPassive && store.totalSignalCount == 0 {
                await refreshPassive()
            }
        }
    }

    @available(iOS 16.0, macOS 13.0, *)
    private var modernNavigation: some View {
        NavigationSplitView {
            categoryList
            .navigationDestination(for: SignalCategory.self) { category in
                CategoryDetailView(category: category, store: store)
            }
            #if os(macOS)
            .navigationSplitViewColumnWidth(min: 320, ideal: 380, max: 500)
            #endif
        } detail: {
            detailPlaceholder
        }
    }

    private var legacyNavigation: some View {
        NavigationView {
            categoryList
            detailPlaceholder
        }
        #if os(iOS)
        .navigationViewStyle(.stack)
        #endif
    }

    private var categoryList: some View {
        List {
            Section {
                IntroCardView(
                    onShowSummary: { showingSummary = true },
                    transitionNamespace: transitionNamespace
                )
                    .listRowInsets(EdgeInsets(top: 8, leading: 16, bottom: 8, trailing: 16))
                    .listRowBackground(Color.clear)
                    .listRowSeparator(.hidden)
            }
            section(title: .passive, caption: Sensitivity.passive.blurb)
            section(title: .permissioned, caption: Sensitivity.permissioned.blurb)
            section(title: .advanced, caption: Sensitivity.advanced.blurb)
            Section {
                PsyloPromotionView()
                    .listRowInsets(EdgeInsets(top: 8, leading: 16, bottom: 8, trailing: 16))
                    .listRowBackground(Color.clear)
                    .listRowSeparator(.hidden)
            }
        }
        .navigationTitle("Loupe")
        .platformInsetGroupedListStyle()
        .toolbar { toolbarContent }
        .refreshable { await refreshPassive() }
    }

    private var detailPlaceholder: some View {
        VStack(spacing: 12) {
            Image(systemName: "doc.text.image.fill")
                .font(.largeTitle)
                .foregroundStyle(.secondary)
            Text("Select a category from the sidebar")
                .foregroundStyle(.secondary)
        }
    }

    // MARK: - Sections

    @ViewBuilder
    private func section(title tier: Sensitivity, caption: String) -> some View {
        let categories = store.categories(for: tier)
        Section {
            ForEach(categories) { category in
                if #available(iOS 16.0, macOS 13.0, *) {
                    NavigationLink(value: category) {
                        categoryRow(category)
                    }
                } else {
                    NavigationLink {
                        CategoryDetailView(category: category, store: store)
                    } label: {
                        categoryRow(category)
                    }
                }
            }
        } header: {
            sectionHeader(for: tier)
        } footer: {
            Text(caption)
                .font(.caption)
        }
    }

    private func categoryRow(_ category: SignalCategory) -> some View {
        CategoryRowView(
            category: category,
            state: store.loadState(for: category),
            count: store.count(for: category)
        )
    }

    private func sectionHeader(for tier: Sensitivity) -> some View {
        HStack(spacing: 8) {
            Image(systemName: tier.symbolName)
            Text(tier.title)
        }
        .font(.subheadline.weight(.semibold))
        .foregroundStyle(tier.tint)
        .textCase(nil)
    }

    // MARK: - Toolbar

    @ToolbarContentBuilder
    private var toolbarContent: some ToolbarContent {
        #if os(iOS)
        ToolbarItem(placement: .topBarTrailing) {
            ExportButton(store: store)
        }
        #else
        ToolbarItem(placement: .primaryAction) {
            ExportButton(store: store)
        }
        #endif
    }

    // MARK: - Actions

    private func refreshPassive() async {
        collectingPassive = true
        defer { collectingPassive = false }
        await store.refreshPassive()
    }

    // MARK: - Chrome

    private var backgroundGradient: some View {
        LinearGradient(
            colors: [
                Color(white: 0.95),
                Color.accentColor.opacity(0.08),
                Color(white: 0.95),
            ],
            startPoint: .top,
            endPoint: .bottom
        )
        .ignoresSafeArea()
    }
}

private enum TransitionID: Hashable {
    case highlights
}

private struct IntroCardView: View {
    let onShowSummary: () -> Void
    let transitionNamespace: Namespace.ID

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                Image(systemName: "eye.trianglebadge.exclamationmark")
                    .font(.title3.weight(.semibold))
                    .foregroundStyle(.tint)
                Text("What your apps can see")
                    .font(.headline)
                Spacer()
            }
            Text(
                "Each section below reads a public \(PlatformDevice.systemName) API that any app can quietly call. Tap a category to see what your \(PlatformDevice.localizedModel) gives away, and how those values add up to a fingerprint."
            )
            .font(.subheadline)
            .foregroundStyle(.secondary)
            Button(action: onShowSummary) {
                Text("See the Highlights")
                    .fontWeight(.semibold)
            }
            .compatibleProminentButtonStyle()
            .compatibleZoomTransitionSource(id: TransitionID.highlights, in: transitionNamespace)
            .frame(maxWidth: .infinity)
            .controlSize(.large)
            .accessibilityIdentifier("highlightsButton")
        }
        .padding()
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 20, style: .continuous)
                .fill(.regularMaterial)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 20, style: .continuous)
                .strokeBorder(.white.opacity(0.25), lineWidth: 1)
        )
    }
}
