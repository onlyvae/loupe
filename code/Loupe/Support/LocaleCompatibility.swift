//
//  LocaleCompatibility.swift
//  Loupe
//
//  Locale gained strongly typed region, weekday, hour-cycle, and
//  measurement APIs in iOS 16. These helpers expose the same readings
//  using Foundation APIs that are available on iOS 15.
//

import Foundation

enum LocaleCompatibility {
    enum MeasurementSystem: Equatable {
        case metric
        case us
        case uk
    }

    static func regionIdentifier(for locale: Locale) -> String? {
        locale.regionCode
    }

    static func currencyIdentifier(for locale: Locale) -> String? {
        locale.currencyCode
    }

    static func languageIdentifier(for locale: Locale) -> String {
        locale.languageCode ?? "en"
    }

    static func firstWeekday(for locale: Locale) -> Int {
        locale.calendar.firstWeekday
    }

    static func weekdayIdentifier(_ weekday: Int) -> String {
        switch weekday {
        case 1: return "sunday"
        case 2: return "monday"
        case 3: return "tuesday"
        case 4: return "wednesday"
        case 5: return "thursday"
        case 6: return "friday"
        case 7: return "saturday"
        default: return "unknown"
        }
    }

    static func uses24HourClock(_ locale: Locale) -> Bool {
        let format = DateFormatter.dateFormat(fromTemplate: "j", options: 0, locale: locale) ?? ""
        return !format.contains("a")
    }

    static func hourCycleIdentifier(for locale: Locale) -> String {
        uses24HourClock(locale) ? "h23" : "h12"
    }

    static func measurementSystem(for locale: Locale) -> MeasurementSystem {
        if regionIdentifier(for: locale) == "GB" {
            return .uk
        }
        return locale.usesMetricSystem ? .metric : .us
    }
}
