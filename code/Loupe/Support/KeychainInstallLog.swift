//
//  KeychainInstallLog.swift
//  Loupe
//
//  Uses the iOS Keychain to persist a log of install timestamps across
//  app deletions. UserDefaults are wiped on uninstall; Keychain entries
//  survive. By comparing the two we detect fresh installs.
//

import Foundation
import Security

struct KeychainInstallLog: Sendable {
    static let shared = KeychainInstallLog()

    struct LaunchStats: Codable, Sendable {
        let count: Int
        let latestLaunchDate: Date
    }

    private let service = "co.mysk.loupe.installLog"
    private let account = "installDates"
    private let launchStatsAccount = "launchStats"
    private let sharedAccessGroup = "P54HCX53YR.com.onlyvae.shared-keychain"
    private let legacyAccessGroup = "P54HCX53YR.com.onlyvae.loupe"
    private let defaultsKey = "KeychainInstallLog.hasRecorded"

    func recordLaunch() {
        let current = readLaunchStats()
        let updated = LaunchStats(
            count: (current?.count ?? 0) + 1,
            latestLaunchDate: Date()
        )
        writeLaunchStats(updated)
    }

    func launchStats() -> LaunchStats? {
        readLaunchStats()
    }

    func recordInstallIfNeeded() {
        let alreadyRecorded = UserDefaults.standard.bool(forKey: defaultsKey)
        if alreadyRecorded {
            migrateLegacyDatesIfNeeded()
            return
        }

        var dates = readDates()
        dates.append(Date())
        writeDates(dates)
        UserDefaults.standard.set(true, forKey: defaultsKey)
    }

    func installDates() -> [Date] {
        readDates()
    }

    // MARK: - Keychain helpers

    private func readDates() -> [Date] {
        readDates(accessGroup: sharedAccessGroup)
    }

    private func readDates(accessGroup: String) -> [Date] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: accessGroup,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else {
            return []
        }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return (try? decoder.decode([Date].self, from: data)) ?? []
    }

    private func writeDates(_ dates: [Date]) {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        guard let data = try? encoder.encode(dates) else { return }

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: sharedAccessGroup,
        ]

        let existing = SecItemCopyMatching(query as CFDictionary, nil)
        if existing == errSecSuccess {
            let update: [String: Any] = [kSecValueData as String: data]
            SecItemUpdate(query as CFDictionary, update as CFDictionary)
        } else {
            var add = query
            add[kSecValueData as String] = data
            add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            SecItemAdd(add as CFDictionary, nil)
        }
    }

    private func migrateLegacyDatesIfNeeded() {
        guard readDates().isEmpty else { return }
        let legacyDates = readDates(accessGroup: legacyAccessGroup)
        guard !legacyDates.isEmpty else { return }
        writeDates(legacyDates)
    }

    private func readLaunchStats() -> LaunchStats? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: launchStatsAccount,
            kSecAttrAccessGroup as String: sharedAccessGroup,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else {
            return nil
        }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try? decoder.decode(LaunchStats.self, from: data)
    }

    private func writeLaunchStats(_ stats: LaunchStats) {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        guard let data = try? encoder.encode(stats) else { return }

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: launchStatsAccount,
            kSecAttrAccessGroup as String: sharedAccessGroup,
        ]

        if SecItemCopyMatching(query as CFDictionary, nil) == errSecSuccess {
            let update: [String: Any] = [kSecValueData as String: data]
            SecItemUpdate(query as CFDictionary, update as CFDictionary)
        } else {
            var add = query
            add[kSecValueData as String] = data
            add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            SecItemAdd(add as CFDictionary, nil)
        }
    }
}
