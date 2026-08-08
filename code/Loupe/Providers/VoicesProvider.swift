//
//  VoicesProvider.swift
//  Loupe
//
//  Enumerates installed text-to-speech voices. Vanilla devices have an
//  identical baseline set, but every Enhanced or Premium voice the user
//  has downloaded in Settings → Accessibility → Spoken Content adds
//  hundreds of megabytes of disk and a very identifying entry to this
//  list. Browser fingerprinters lean on the equivalent web API
//  (`speechSynthesis.getVoices()`) for the same reason.
//

import AVFoundation
import Foundation

struct VoicesProvider: SignalProvider {
    let category: SignalCategory = .voices

    func collect() async -> [FingerprintSignal] {
        let voices = AVSpeechSynthesisVoice.speechVoices()
            .sorted { lhs, rhs in
                if lhs.language != rhs.language { return lhs.language < rhs.language }
                return lhs.name.localizedCaseInsensitiveCompare(rhs.name) == .orderedAscending
            }

        var signals: [FingerprintSignal] = []

        signals.append(
            .make(
                "count",
                category: category,
                name: String(localized: "Installed voices", comment: "Signal card name in the Installed Voices category — number of AVSpeechSynthesisVoice entries available."),
                value: String(voices.count),
                rationale: String(localized: "Number of available text-to-speech voices. Higher counts usually mean you've downloaded Enhanced or Premium voices.", comment: "Signal card rationale beneath the Installed voices value.")))

        let languages = Set(voices.map(\.language)).sorted()
        let languageEntries = languages.map { code -> SignalEntry in
            let name = Locale.current.localizedString(forIdentifier: code) ?? code
            return SignalEntry(label: name, value: code)
        }
        signals.append(
            .make(
                "languages",
                category: category,
                name: String(localized: "Voice languages", comment: "Signal card name in the Installed Voices category — distinct language tags covered by the installed voices."),
                value: languages.isEmpty ? "(none)" : languages.joined(separator: ", "),
                rationale: String(localized: "Language tags covered by the installed voices.", comment: "Signal card rationale beneath the Voice languages value."),
                displayHint: languageEntries.isEmpty ? .plain : .keyValue,
                entries: languageEntries.isEmpty ? nil : languageEntries))

        let downloaded = voices.filter { $0.quality == .enhanced || isPremium($0.quality) }
        let downloadedEntries = downloaded.map { voice in
            SignalEntry(label: "\(voice.name) (\(voice.language))", value: qualityName(voice.quality))
        }
        signals.append(
            .make(
                "downloaded",
                category: category,
                name: String(localized: "Enhanced / Premium voices", comment: "Signal card name in the Installed Voices category — voices the user has explicitly downloaded (Enhanced or Premium quality)."),
                value: downloaded.isEmpty
                    ? "0"
                    : "\(downloaded.count): \(downloaded.map(\.name).joined(separator: ", "))",
                rationale: String(localized: "Voices you've explicitly downloaded. Most devices have none of these.", comment: "Signal card rationale beneath the Enhanced / Premium voices value."),
                displayHint: downloadedEntries.isEmpty ? .plain : .keyValue,
                entries: downloadedEntries.isEmpty ? nil : downloadedEntries))

        let allEntries = voices.map { voice -> SignalEntry in
            let qualitySuffix = voice.quality == .default ? "" : " · \(qualityName(voice.quality))"
            return SignalEntry(label: "\(voice.name) (\(voice.language))", value: "\(genderName(voice.gender))\(qualitySuffix)")
        }
        signals.append(
            .make(
                "all",
                category: category,
                name: String(localized: "All voices", comment: "Signal card name in the Installed Voices category — full per-voice list with language, gender, and quality."),
                value: voices.isEmpty
                    ? "(none)"
                    : voices.map { "\($0.name) (\($0.language))" }.joined(separator: ", "),
                rationale: String(localized: "Full per-voice list with language, gender, and quality.", comment: "Signal card rationale beneath the All voices value."),
                displayHint: allEntries.isEmpty ? .plain : .keyValue,
                entries: allEntries.isEmpty ? nil : allEntries))

        return signals
    }

    private func qualityName(_ quality: AVSpeechSynthesisVoiceQuality) -> String {
        if #available(iOS 16.0, macOS 13.0, *), quality == .premium {
            return String(localized: "Premium", comment: "Voice quality")
        }
        if quality == .default {
            return String(localized: "Default", comment: "Voice quality")
        }
        if quality == .enhanced {
            return String(localized: "Enhanced", comment: "Voice quality")
        }
        return String(describing: quality)
    }

    private func isPremium(_ quality: AVSpeechSynthesisVoiceQuality) -> Bool {
        if #available(iOS 16.0, macOS 13.0, *) {
            return quality == .premium
        }
        return false
    }

    private func genderName(_ gender: AVSpeechSynthesisVoiceGender) -> String {
        switch gender {
        case .male: return String(localized: "Male", comment: "Voice gender")
        case .female: return String(localized: "Female", comment: "Voice gender")
        case .unspecified: return String(localized: "Unspecified", comment: "Voice gender")
        @unknown default: return String(describing: gender)
        }
    }
}
