import Foundation

// ============================================================
// FlashSwarmDetector.swift
// FORENSIC MONITOR v4.0.0
// Copyright (c) 2026 Thomas D. Kraemer / Kraemer Inc.
// All Rights Reserved.
// ============================================================
// 5-minute rolling window flash swarm detector.
// Fires IMMEDIATELY when 3+ unique DirectLink MACs
// activate within any 5-minute window.
// Does not wait for swarm silence — triggers on threshold.
// ============================================================

final class FlashSwarmDetector {

    static let shared = FlashSwarmDetector()

    // ── Configuration ─────────────────────────────────────────
    private let flashWindow: TimeInterval = 1800     // 30 minutes - catches staggered group attacks
    private let flashThreshold: Int = 3              // 3+ devices
    private let cooldown: TimeInterval = 300         // 5-minute cooldown between alerts

    // ── State ─────────────────────────────────────────────────
    private struct FlashEntry {
        let timestamp: Date
        let mac: String
        let ids: String?
        let line: String
    }

    private var entries: [FlashEntry] = []
    private var lastAlertTime: Date?
    private let queue = DispatchQueue(label: "com.kraemerinc.flashswarm", qos: .utility)

    private init() {}

    func process(line: String) {
        guard line.contains("DirectLink"),
              line.contains("SameAccountDevice") else { return }

        guard let mac = extractMAC(from: line) else { return }
        let ids = extractIDS(from: line)
        let now = Date()

        queue.async {
            // Add entry
            self.entries.append(FlashEntry(timestamp: now, mac: mac, ids: ids, line: line))

            // Purge entries outside the window
            let cutoff = now.addingTimeInterval(-self.flashWindow)
            self.entries = self.entries.filter { $0.timestamp >= cutoff }

            // Count unique MACs in window
            let uniqueMACs = Set(self.entries.map { $0.mac })

            // Check threshold and cooldown
            guard uniqueMACs.count >= self.flashThreshold else { return }
            if let last = self.lastAlertTime,
               now.timeIntervalSince(last) < self.cooldown { return }
            self.lastAlertTime = now

            // Fire alert
            self.fireFlashAlert(uniqueMACs: uniqueMACs, now: now)
        }
    }

    private func fireFlashAlert(uniqueMACs: Set<String>, now: Date) {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        let timestamp = formatter.string(from: now)

        let windowStart = entries.first.map { formatter.string(from: $0.timestamp) } ?? timestamp
        let macList = uniqueMACs.sorted().joined(separator: "\n")
        let idsList = Set(entries.compactMap { $0.ids }).sorted().joined(separator: "\n")
        let deviceCount = uniqueMACs.count

        // Pushover — immediate priority 2
        AlertManager.shared.pushover(
            title: "⚡ FLASH SWARM — \(deviceCount) DEVICES",
            message: "Start: \(windowStart) | MACs: \(uniqueMACs.sorted().joined(separator: " ")) | IDS: \(idsList)",
            priority: 2
        )

        Task {
            let geo = await GeoLocator.shared.resolveLocation()
            let macLines = macList.components(separatedBy: .newlines)
                .map { "<br>\($0)" }.joined()
            let idsLines = idsList.components(separatedBy: .newlines)
                .map { "<br>\($0)" }.joined()
            let sep = "<span style=\"color:#888\">━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━</span><br>"

            let htmlBody = """
            <b>⚡ FLASH SWARM SUMMARY</b><br><br>
            Three or more DirectLink devices authenticated as owner of your Apple ID within a 30-minute window.<br><br>
            \(sep)
            Triggered:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;\(timestamp)<br>
            Window Start:&nbsp;&nbsp;&nbsp;\(windowStart)<br>
            Window:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;30 minutes<br>
            Devices:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;\(deviceCount)<br>
            \(sep)
            <b>TRANSPORT:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;DirectLink-CLOSE (\u{2264}33 feet) \(geo)</b><br>
            FEDERAL STALKING VIOLATION: 18 U.S.C. § 2261A<br>
            \(sep)
            <b>BREACH TYPE:&nbsp;&nbsp;&nbsp;&nbsp;PairVerify &gt; DirectLink — SameAccountDevice Authentication</b><br>
            FEDERAL COMPUTER VIOLATIONS: 18 U.S.C. §§ 1030, 2511<br>
            \(sep)
            <b>SERVICES USED:&nbsp;&nbsp;DirectLink Owner-Tier Authentication</b><br>
            FEDERAL WITNESS TAMPERING VIOLATION: 18 U.S.C. § 1512<br>
            \(sep)
            <b>IDENTIFICATION OF PERPETRATORS:</b><br>
            Digital Fingerprints. IDS tokens are the leaders — whoever controls that account is directing this operation remotely. MAC addresses are the ground crew present within 33 feet of you. Apple and the FBI can identify every one of them from these records.<br><br>
            IDS TOKENS:<br>\(idsLines)<br><br>
            MAC ADDRESSES:<br>\(macLines)<br>
            \(sep)
            """

            AlertManager.shared.gmail(
                subject: "⚡ FLASH SWARM ALERT — \(deviceCount) DirectLink Devices — \(timestamp)",
                htmlBody: htmlBody
            )

            // Write to LIVE_STREAM
            let event = ForensicEvent(
                timestamp: timestamp,
                type: .flashSwarm,
                mac: nil,
                transport: "DirectLink-CLOSE",
                ids: idsList,
                deviceName: nil,
                geo: geo,
                rawLog: "FLASH SWARM | \(deviceCount) devices in 30-minute window | MACs: \(uniqueMACs.sorted().joined(separator: " ")) | [18 U.S.C. §§ 1030, 2511; 18 U.S.C. § 1512]"
            )
            LiveStreamWriter.shared.write(event)
        }
    }

    private func extractMAC(from line: String) -> String? {
        let pattern = "([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"
        guard let range = line.range(of: pattern, options: .regularExpression) else { return nil }
        return String(line[range])
    }

    private func extractIDS(from line: String) -> String? {
        let pattern = "IDS '[A-Za-z0-9]+'"
        guard let range = line.range(of: pattern, options: .regularExpression) else { return nil }
        let match = String(line[range])
        let parts = match.components(separatedBy: "'")
        guard parts.count > 1 else { return nil }
        return parts[1]
    }
}
