import Foundation

// ============================================================
// DirectLinkDetector.swift
// FORENSIC MONITOR v4.0.0
// Copyright (c) 2026 Thomas D. Kraemer / Kraemer Inc.
// All Rights Reserved.
// ============================================================

final class DirectLinkDetector {

    static let shared = DirectLinkDetector()

    private var seenMACs: [String: Int] = [:]
    private let queue = DispatchQueue(label: "com.kraemerinc.directlinkdetector", qos: .utility)
    private var lastMAC: String = ""
    private var lastIDS: String = ""
    private var lastTimestamp: String = ""

    private init() {}

    func process(line: String) {
        guard line.contains("SameAccountDevice"),
              line.contains("DeviceAuthTag") else { return }

        let mac = extractMAC(from: line)
        guard mac != nil else { return }
        let safeMac = mac!
        let ids = extractIDS(from: line)
        let deviceName = extractDeviceName(from: line)
        let transport = classifyTransport(from: line)
        let timestamp = currentTimestamp()
        let isDirectLink = transport == "DirectLink-CLOSE" || transport == "USB+DirectLink"

        queue.async {
            let count = self.seenMACs[safeMac] ?? 0
            self.seenMACs[safeMac] = count + 1
            let capturedLastMAC = self.lastMAC
            let capturedLastIDS = self.lastIDS
            let capturedLastTimestamp = self.lastTimestamp
            self.lastMAC = safeMac
            self.lastIDS = ids ?? ""
            self.lastTimestamp = timestamp

            if isDirectLink {
                Task {
                    let geo = await GeoLocator.shared.resolveLocation()
                    let eventType: ForensicEvent.EventType = transport == "USB+DirectLink" ? .usbDirectLink : .directLink
                    let event = ForensicEvent(
                        timestamp: timestamp,
                        type: eventType,
                        mac: safeMac,
                        transport: transport,
                        ids: ids,
                        deviceName: deviceName,
                        geo: geo,
                        rawLog: line
                    )
                    LiveStreamWriter.shared.write(event)
                    let alertTitle = count == 0 ? "NEW MAC — DirectLink" : "REPEAT OFFENDER — DirectLink"
                    let alertMsg = "MAC: \(safeMac) | Seen: \(count + 1)x | \(transport) | IDS: \(ids ?? "unknown") | GEO: \(geo)"
                    AlertManager.shared.pushover(title: alertTitle, message: alertMsg, priority: 0)
                    if let ids = ids, ids == capturedLastIDS, timestamp == capturedLastTimestamp {
                        let batchMsg = "SIMULTANEOUS DirectLink | IDS '\(ids)' | \(capturedLastMAC) + \(safeMac) | \(timestamp)"
                        AlertManager.shared.pushover(title: "BATCH PROXIMITY DEPLOYMENT QNTY=2", message: batchMsg, priority: 2)
                    }
                }
            } else {
                let event = ForensicEvent(
                    timestamp: timestamp,
                    type: .awdl,
                    mac: safeMac,
                    transport: transport,
                    ids: ids,
                    deviceName: deviceName,
                    geo: nil,
                    rawLog: line
                )
                LiveStreamWriter.shared.write(event)
            }
        }
    }

    private func classifyTransport(from line: String) -> String {
        if line.contains("0x18") || (line.contains("USB") && line.contains("DirectLink")) {
            return "USB+DirectLink"
        } else if line.contains("0x10") || line.contains("DirectLink") {
            return "DirectLink-CLOSE"
        } else if line.contains("0x4") || line.contains("AWDL") {
            return "AWDL"
        }
        return "Unknown"
    }

    private func extractMAC(from line: String) -> String? {
        let pattern = "([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"
        guard let range = line.range(of: pattern, options: .regularExpression) else {
            return nil
        }
        return String(line[range])
    }

    private func extractIDS(from line: String) -> String? {
            let pattern = "IDS '[A-Za-z0-9]+'"
            guard let range = line.range(of: pattern, options: .regularExpression) else {
                return nil
            }
            let match = String(line[range])
            let parts = match.components(separatedBy: "'")
            guard parts.count > 1 else { return nil }
            return parts[1]
        }

    private func extractDeviceName(from line: String) -> String? {
        let pattern = "\"[^\"]+\""
        guard let range = line.range(of: pattern, options: .regularExpression) else {
            return nil
        }
        return String(line[range]).replacingOccurrences(of: "\"", with: "")
    }

    private func currentTimestamp() -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return formatter.string(from: Date())
    }

    func seenCount(for mac: String) -> Int {
        return queue.sync { seenMACs[mac] ?? 0 }
    }
}
