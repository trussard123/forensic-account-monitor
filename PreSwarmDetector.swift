import Foundation

// ============================================================
// PreSwarmDetector.swift
// FORENSIC MONITOR v4.0.0
// Copyright (c) 2026 Thomas D. Kraemer / Kraemer Inc.
// All Rights Reserved.
// ============================================================
// Detects FILE SHARING, SCREEN SHARING, KEYBOARD/MOUSE,
// CAMERA and IMAGE CAPTURE service staging events
// from sharingd output — the pre-swarm indicators.
// ============================================================

final class PreSwarmDetector {

    static let shared = PreSwarmDetector()

    // ── Service keywords to watch ─────────────────────────────
    private let serviceKeywords: [String: String] = [
        "FILE SHARING":   "FILE SHARING",
        "SCREEN":         "SCREEN SHARING",
        "KEYBOARD":       "KEYBOARD/MOUSE",
        "CAMERA":         "CAMERA",
        "IMAGE CAPTURE":  "IMAGE CAPTURE",
        "AirDrop":        "AIRDROP",
        "Handoff":        "HANDOFF"
    ]

    // ── Cooldown — avoid alert flooding ──────────────────────
    private var lastAlertTime: [String: Date] = [:]
    private let cooldown: TimeInterval = 30.0
    private let queue = DispatchQueue(label: "com.kraemerinc.preswarmdetector", qos: .utility)

    private init() {}

    func process(line: String) {
        guard line.contains("sharingd") ||
              line.contains("SDNearbyAgent") else { return }

        queue.async {
            for (keyword, label) in self.serviceKeywords {
                guard line.contains(keyword) else { continue }

                let now = Date()
                if let last = self.lastAlertTime[label],
                   now.timeIntervalSince(last) < self.cooldown { continue }
                self.lastAlertTime[label] = now

                let timestamp = self.currentTimestamp()
                let event = ForensicEvent(
                    timestamp: timestamp,
                    type: .preSwarm,
                    mac: nil,
                    transport: nil,
                    ids: nil,
                    deviceName: nil,
                    geo: nil,
                    rawLog: "PRE-SWARM | \(label) | \(label) service activated | \(timestamp)"
                )
                LiveStreamWriter.shared.write(event)

                AlertManager.shared.pushover(
                    title: "PRE-SWARM: \(label) STAGED",
                    message: "\(label) service activated | \(timestamp)",
                    priority: 1
                )
            }
        }
    }

    private func currentTimestamp() -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return formatter.string(from: Date())
    }
}
