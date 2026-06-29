//
//  PreviousInstallsProvider.swift
//  Loupe
//
//  Demonstrates that a native app can track how many times it has been
//  installed on a device by persisting timestamps in the Keychain, which
//  survives app deletion and reinstallation.
//

import Foundation

struct PreviousInstallsProvider: SignalProvider {
    let category: SignalCategory = .previousInstalls

    func collect() async -> [FingerprintSignal] {
        let log = KeychainInstallLog.shared
        log.recordInstallIfNeeded()

        let dates = log.installDates()
        var signals: [FingerprintSignal] = []

        if let stats = log.launchStats() {
            let formatter = ISO8601DateFormatter()
            signals.append(
                .make(
                    "launchCount",
                    category: category,
                    name: String(localized: "Open count", comment: "Signal card name in the Previous Installs Log category. Number of times Loupe has been launched."),
                    value: String(stats.count),
                    rationale:
                        String(localized: "Number of times you've opened Loupe. This count is kept in the Keychain.", comment: "Signal card rationale beneath the Open count value.")))
            signals.append(
                .make(
                    "latestLaunchDate",
                    category: category,
                    name: String(localized: "Latest open time", comment: "Signal card name in the Previous Installs Log category. Most recent time Loupe was launched."),
                    value: formatter.string(from: stats.latestLaunchDate),
                    rationale:
                        String(localized: "The latest time you opened Loupe. This date is kept in the Keychain.", comment: "Signal card rationale beneath the Latest open time value.")))
        }

        signals.append(
            .make(
                "installCount",
                category: category,
                name: String(localized: "Install count", comment: "Signal card name in the Previous Installs Log category — number of times this app has been installed on this device."),
                value: String(dates.count),
                rationale:
                    String(localized: "Number of times this app has been installed. Keychain entries persist across uninstalls.", comment: "Signal card rationale beneath the Install count value.")))

        let formatter = ISO8601DateFormatter()

        if let first = dates.first {
            signals.append(
                .make(
                    "firstInstall",
                    category: category,
                    name: String(localized: "First install date", comment: "Signal card name in the Previous Installs Log category — earliest recorded install date."),
                    value: formatter.string(from: first),
                    rationale:
                        String(localized: "Earliest recorded install date. Persists in the Keychain across uninstalls.", comment: "Signal card rationale beneath the First install date value.")))
        }

        if let current = dates.last, dates.count > 1 {
            signals.append(
                .make(
                    "currentInstall",
                    category: category,
                    name: String(localized: "Current install date", comment: "Signal card name in the Previous Installs Log category — first launch date of the current installation."),
                    value: formatter.string(from: current),
                    rationale:
                        String(localized: "First launch date of the current installation.", comment: "Signal card rationale beneath the Current install date value.")))
        }

        if dates.count > 1 {
            let logString = dates.map { formatter.string(from: $0) }.joined(separator: ", ")
            signals.append(
                .make(
                    "installLog",
                    category: category,
                    name: String(localized: "Install history", comment: "Signal card name in the Previous Installs Log category — timestamps of each recorded installation."),
                    value: logString,
                    rationale:
                        String(localized: "Timestamps of each recorded installation.", comment: "Signal card rationale beneath the Install history value.")))
        }

        return signals
    }
}
