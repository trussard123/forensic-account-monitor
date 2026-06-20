import Foundation
import CoreLocation

// ============================================================
// GeoLocator.swift
// FORENSIC MONITOR v4.0.0
// Copyright (c) 2026 Thomas D. Kraemer / Kraemer Inc.
// All Rights Reserved.
// ============================================================
// Reverse geocodes coordinates via Nominatim.
// Called by DirectLinkDetector and SwarmDetector
// when a qualifying event fires.
// ============================================================

final class GeoLocator: NSObject, CLLocationManagerDelegate {

    // ── Singleton ────────────────────────────────────────────
    static let shared = GeoLocator()

    private let locationManager = CLLocationManager()
    private var locationContinuation: CheckedContinuation<CLLocation?, Never>?

    private override init() {
        super.init()
        locationManager.delegate = self
        locationManager.desiredAccuracy = kCLLocationAccuracyBest
    }

    // ── Request current location ─────────────────────────────
    func currentLocation() async -> CLLocation? {
        return await withCheckedContinuation { continuation in
            locationContinuation = continuation
            locationManager.requestLocation()
        }
    }

    // ── Reverse geocode via Nominatim ────────────────────────
    func resolveLocation() async -> String {
        guard let location = await currentLocation() else {
            return "unavailable"
        }
        let lat = location.coordinate.latitude
        let lon = location.coordinate.longitude
        let urlString = "https://nominatim.openstreetmap.org/reverse?lat=\(lat)&lon=\(lon)&format=json"
        guard let url = URL(string: urlString) else { return "unavailable" }

        var request = URLRequest(url: url)
        request.setValue("ForensicMonitor/4.0", forHTTPHeaderField: "User-Agent")

        do {
            let (data, _) = try await URLSession.shared.data(for: request)
            if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let displayName = json["display_name"] as? String {
                let components = displayName.components(separatedBy: ", ")
                let short = components.prefix(4).joined(separator: ", ")
                return "\(short) (\(lat), \(lon))"
            }
        } catch {
            return "\(lat), \(lon)"
        }
        return "\(lat), \(lon)"
    }

    // ── CLLocationManagerDelegate ────────────────────────────
    func locationManager(_ manager: CLLocationManager,
                         didUpdateLocations locations: [CLLocation]) {
        locationContinuation?.resume(returning: locations.first)
        locationContinuation = nil
    }

    func locationManager(_ manager: CLLocationManager,
                         didFailWithError error: Error) {
        locationContinuation?.resume(returning: nil)
        locationContinuation = nil
    }
}
