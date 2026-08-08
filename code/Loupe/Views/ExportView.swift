//
//  ExportView.swift
//  Loupe
//
//  Serialises every currently-loaded signal to JSON and offers it through
//  the platform share sheet. Nothing is written off-device.
//

import SwiftUI
import UniformTypeIdentifiers

#if os(iOS)
import UIKit
#endif

struct ExportButton: View {
    @ObservedObject var store: CategoryStore

    #if os(iOS)
    @State private var exportURL: URL?
    @State private var showingShareSheet = false
    #endif

    var body: some View {
        exportControl
            .disabled(store.totalSignalCount == 0)
            .accessibilityLabel("Export report")
            .accessibilityValue(String(localized: "\(store.totalSignalCount) loaded signals", comment: "Accessibility value on the Export Report share button. %lld is the number of signals currently loaded across all categories."))
            .accessibilityHint(String(localized: "Shares a JSON file containing currently loaded raw values", comment: "Accessibility hint on the Export Report share button."))
            #if os(iOS)
            .sheet(isPresented: $showingShareSheet, onDismiss: removeTemporaryReport) {
                if let exportURL {
                    ActivityView(activityItems: [exportURL])
                }
            }
            #endif
    }

    @ViewBuilder
    private var exportControl: some View {
        #if os(iOS)
        if #available(iOS 16.0, *) {
            ShareLink(
                item: ExportPayload(snapshot: store.allSignalsSnapshot()),
                preview: SharePreview("Loupe report")
            ) {
                exportLabel
            }
        } else {
            Button(action: prepareReportForSharing) {
                exportLabel
            }
        }
        #else
        ShareLink(
            item: ExportPayload(snapshot: store.allSignalsSnapshot()),
            preview: SharePreview("Loupe report")
        ) {
            exportLabel
        }
        #endif
    }

    private var exportLabel: some View {
        Label("Export report", systemImage: "square.and.arrow.up")
    }

    #if os(iOS)
    private func prepareReportForSharing() {
        removeTemporaryReport()
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let url = directory.appendingPathComponent("loupe-report.json")

        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            try ExportReport.data(from: store.allSignalsSnapshot()).write(to: url, options: .atomic)
            exportURL = url
            showingShareSheet = true
        } catch {
            try? FileManager.default.removeItem(at: directory)
        }
    }

    private func removeTemporaryReport() {
        guard let exportURL else { return }
        try? FileManager.default.removeItem(at: exportURL.deletingLastPathComponent())
        self.exportURL = nil
    }
    #endif
}

private enum ExportReport {
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

    static func data(from snapshot: [SignalCategory: [FingerprintSignal]]) throws -> Data {
        let categories = snapshot
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
}

#if os(iOS)
@available(iOS 16.0, *)
private struct ExportPayload: Transferable, Sendable {
    let snapshot: [SignalCategory: [FingerprintSignal]]

    static var transferRepresentation: some TransferRepresentation {
        DataRepresentation(exportedContentType: .json) { payload in
            try ExportReport.data(from: payload.snapshot)
        }
        .suggestedFileName("loupe-report.json")
    }
}

private struct ActivityView: UIViewControllerRepresentable {
    let activityItems: [Any]

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: activityItems, applicationActivities: nil)
    }

    func updateUIViewController(_ controller: UIActivityViewController, context: Context) {}
}
#else
private struct ExportPayload: Transferable, Sendable {
    let snapshot: [SignalCategory: [FingerprintSignal]]

    static var transferRepresentation: some TransferRepresentation {
        DataRepresentation(exportedContentType: .json) { payload in
            try ExportReport.data(from: payload.snapshot)
        }
        .suggestedFileName("loupe-report.json")
    }
}
#endif
