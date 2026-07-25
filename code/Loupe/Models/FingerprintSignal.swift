//
//  FingerprintSignal.swift
//  Loupe
//
//  One row in a category detail view: a named reading, its displayable
//  value, and a short rationale that teaches the user why it leaks identity.
//

import Foundation

// MARK: - Display Hint

enum DisplayHint: String, Hashable, Sendable, Codable {
    /// Default monospaced text.
    case plain
    /// VStack of LabeledContent rows (label → value).
    case keyValue
    /// Compact horizontal layout for 3-axis / vector data.
    case axis
    /// Horizontally-wrapping capsule chips.
    case tags
    /// Full-width rows for long values such as filesystem paths.
    case list
    /// Side-by-side labeled parts for composite values.
    case compound
}

// MARK: - Signal Entry

struct SignalEntry: Hashable, Sendable, Codable {
    let label: String
    let value: String
}

// MARK: - Fingerprint Signal

struct FingerprintSignal: Identifiable, Hashable, Sendable, Codable {
    let id: String
    let name: String
    let value: String
    let rationale: String
    let sensitivity: Sensitivity
    var displayHint: DisplayHint
    var entries: [SignalEntry]?

    init(
        id: String,
        name: String,
        value: String,
        rationale: String,
        sensitivity: Sensitivity = .passive,
        displayHint: DisplayHint = .plain,
        entries: [SignalEntry]? = nil
    ) {
        self.id = id
        self.name = name
        self.value = value
        self.rationale = rationale
        self.sensitivity = sensitivity
        self.displayHint = displayHint
        self.entries = entries
    }
}

extension FingerprintSignal {
    /// Convenience builder used inside provider bodies: uses the provided
    /// key as the stable identifier and prepends the category id, so the
    /// `id` is deterministic across launches and therefore safe to hash.
    static func make(
        _ key: String,
        category: SignalCategory,
        name: String,
        value: String,
        rationale: String,
        displayHint: DisplayHint = .plain,
        entries: [SignalEntry]? = nil
    ) -> FingerprintSignal {
        FingerprintSignal(
            id: "\(category.rawValue).\(key)",
            name: name,
            value: value,
            rationale: rationale,
            sensitivity: category.sensitivity,
            displayHint: displayHint,
            entries: entries
        )
    }
}
