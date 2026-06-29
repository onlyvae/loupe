//
//  ExportView.swift
//  Loupe
//
//  Serialises every currently-loaded signal to JSON and offers it via
//  ShareLink. Nothing is written off-device.
//

import SwiftUI
import UniformTypeIdentifiers

struct ExportButton: View {
    @ObservedObject var store: CategoryStore

    var body: some View {
        ShareLink(item: ExportPayload(snapshot: store.allSignalsSnapshot()), preview: SharePreview("Loupe report")) {
            Label("Export report", systemImage: "square.and.arrow.up")
        }
        .disabled(store.totalSignalCount == 0)
        .accessibilityLabel("Export report")
        .accessibilityValue(String(localized: "\(store.totalSignalCount) loaded signals", comment: "Accessibility value on the Export Report share button. %lld is the number of signals currently loaded across all categories."))
        .accessibilityHint(String(localized: "Shares a JSON file containing currently loaded raw values", comment: "Accessibility hint on the Export Report share button."))
    }

}

struct ExportPayload: Transferable, Sendable {
    struct Category: Codable, Sendable {
        let id: String
        let title: String
        let sensitivity: String
        let signals: [FingerprintSignal]
    }

    private struct Report: Codable, Sendable {
        let generatedAt: String
        let categories: [Category]
    }

    let snapshot: [SignalCategory: [FingerprintSignal]]

    static var transferRepresentation: some TransferRepresentation {
        DataRepresentation(exportedContentType: .json) { payload in
            let categories = payload.snapshot
                .sorted { $0.key.rawValue < $1.key.rawValue }
                .map { entry in
                    Category(
                        id: entry.key.rawValue,
                        title: entry.key.title,
                        sensitivity: entry.key.sensitivity.rawValue,
                        signals: entry.value
                    )
                }
            let report = Report(
                generatedAt: ISO8601DateFormatter().string(from: Date()),
                categories: categories
            )
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            return try encoder.encode(report)
        }
        .suggestedFileName("loupe-report.json")
    }
}
