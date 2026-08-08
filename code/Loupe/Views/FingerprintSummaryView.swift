//
//  FingerprintSummaryView.swift
//  Loupe
//
//  A non-technical "here's what your phone gives away" sheet. Translates
//  passive readings into one-line claims with a small "Based on …"
//  caption, then closes by showing how the union of those innocuous
//  facts forms a stable fingerprint.
//

import SwiftUI

struct FingerprintSummaryView: View {
    @Environment(\.dismiss) private var dismiss

    private let items: [NarrativeItem] = FingerprintNarrative.items()
    private let bootDate: Date? = FingerprintNarrative.bootDate()
    private let chip: String = FingerprintNarrative.fingerprintChip()
    private let appInferences: [NarrativeItem] = AppInferenceEngine.detectedInferences()

    var body: some View {
        CompatibleNavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 24) {
                    header
                    explainer
                    cards
                    if !appInferences.isEmpty {
                        appInferencesSection
                    }
                    closingBlock
                }
                .padding(.horizontal, 20)
                .padding(.vertical, 24)
            }
            .navigationTitle("Fingerprinting Highlights")
            .platformInlineNavigationBarTitle()
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done", systemImage: "checkmark") {
                        dismiss()
                    }
                    .accessibilityIdentifier("summaryDoneButton")
                }
            }
        }
    }

    // MARK: - Sections

    private var header: some View {
        VStack(alignment: .leading, spacing: 12) {
            Image(systemName: "person.crop.square.filled.and.at.rectangle")
                .font(.largeTitle.weight(.thin))
                .foregroundStyle(.tint)
                .accessibilityHidden(true)
            Text("What your \(PlatformDevice.marketingName) reveals")
                .font(.title2.bold())
            Text(
                "Any app on your \(PlatformDevice.localizedModel) can quietly read these values without asking. Each one seems harmless on its own, but together they can be enough to single your \(PlatformDevice.localizedModel) out."
            )
            .font(.subheadline)
            .foregroundStyle(.secondary)
        }
    }

    private var explainer: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("What is fingerprinting?", systemImage: "questionmark.circle")
                .font(.headline)
            Text(
                "Fingerprinting recognizes a \(PlatformDevice.localizedModel) by combining ordinary settings instead of relying on a tracker ID. Region, languages, model, storage size, even uptime each narrow the pool of possible devices. Enough of them together can single yours out with reasonable confidence."
            )
            .font(.subheadline)
            .foregroundStyle(.secondary)
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .fill(.ultraThinMaterial)
        )
    }

    private var cards: some View {
        VStack(spacing: 12) {
            ForEach(items) { item in
                NarrativeCardView(item: item)
            }
            if bootDate != nil {
                uptimeCard
            }
        }
    }

    private var appInferencesSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("What your apps say about you", systemImage: "app.badge.checkmark")
                .font(.headline)
            Text(
                "The mix of apps on your \(PlatformDevice.localizedModel) can hint at your interests and habits. Any app can quietly run these same checks."
            )
            .font(.subheadline)
            .foregroundStyle(.secondary)
            ForEach(appInferences) { item in
                NarrativeCardView(item: item)
            }
        }
    }

    @ViewBuilder
    private var uptimeCard: some View {
        if bootDate != nil {
            TimelineView(.animation) { context in
                if let item = FingerprintNarrative.uptimeItem(at: context.date) {
                    NarrativeCardView(item: item)
                }
            }
        }
    }

    private var closingBlock: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Put it together", systemImage: "link")
                .font(.headline)
            Text(
                "None of these readings are a name or an account. But together, they can be distinctive enough to recognize your \(PlatformDevice.localizedModel) again. When a tracker sees the same combination show up twice, it can link those sessions across apps or days."
            )
            .font(.subheadline)
            .foregroundStyle(.secondary)
            if !chip.isEmpty {
                Text(chip)
                    .font(.system(.footnote, design: .monospaced))
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(
                        RoundedRectangle(cornerRadius: 10, style: .continuous)
                            .fill(.tint.opacity(0.12))
                    )
                    .overlay(
                        RoundedRectangle(cornerRadius: 10, style: .continuous)
                            .strokeBorder(.tint.opacity(0.35), lineWidth: 1)
                    )
                    .textSelection(.enabled)
            }
            Text("Loupe reads all of this on your \(PlatformDevice.localizedModel) and keeps it here. Nothing is uploaded, synced, or shared unless you choose to export.")
                .font(.caption)
                .foregroundStyle(.tertiary)
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .fill(.ultraThinMaterial)
        )
    }

}

private struct NarrativeCardView: View {
    let item: NarrativeItem

    var body: some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: item.symbol)
                .font(.title3)
                .foregroundStyle(.tint)
                .frame(width: 28, height: 28)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 4) {
                Text(item.headline)
                    .font(.body.weight(.semibold))
                    .fixedSize(horizontal: false, vertical: true)
                Text(item.basis)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .fill(.regularMaterial)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .strokeBorder(.white.opacity(0.18), lineWidth: 1)
        )
        .accessibilityElement(children: .combine)
    }
}

#Preview {
    FingerprintSummaryView()
}
