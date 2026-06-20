import Foundation

final class BLEWatcher {

    static let shared = BLEWatcher()

    private let rssiClose: Int = -50
    private let rssiApproach: Int = -70
    private var lastAlertTime: [String: Date] = [:]
    private var lastGlobalPushover: Date = Date.distantPast
    private let cooldown: TimeInterval = 60.0
    private let globalPushoverCooldown: TimeInterval = 300.0 // 5 minutes between ANY BLE pushover
    private let queue = DispatchQueue(label: "com.kraemerinc.blewatcher", qos: .utility)

    private init() {}

    func process(line: String) {
        guard (line.contains("bluetoothd") || line.contains("sharingd")),
              line.contains("RSSI") else { return }

        queue.async {
            guard let rssi = self.extractRSSI(from: line) else { return }
            guard rssi >= self.rssiApproach else { return }

            let mac = self.extractMAC(from: line) ?? "unknown"
            let timestamp = self.currentTimestamp()
            let now = Date()

            // Per-device cooldown for logging
            if let last = self.lastAlertTime[mac],
               now.timeIntervalSince(last) < self.cooldown { return }
            self.lastAlertTime[mac] = now

            let distance = rssi >= self.rssiClose ? "<=50 feet" : "50-100 feet"
            let event = ForensicEvent(
                timestamp: timestamp,
                type: .bleWarning,
                mac: mac,
                transport: "BLE",
                ids: nil,
                deviceName: nil,
                geo: nil,
                rawLog: "BLE APPROACH | RSSI \(rssi) | \(distance) | \(line)"
            )
            LiveStreamWriter.shared.write(event)

            // Global pushover cooldown — prevents flooding when multiple devices approach
            let timeSinceLastPushover = now.timeIntervalSince(self.lastGlobalPushover)
            if timeSinceLastPushover >= self.globalPushoverCooldown {
                self.lastGlobalPushover = now
                AlertManager.shared.pushover(
                    title: "BLE APPROACH - HEADS UP WARNING",
                    message: "MAC: \(mac) | RSSI \(rssi) | \(distance) | \(timestamp)",
                    priority: 1
                )
            }
        }
    }

    private func extractRSSI(from line: String) -> Int? {
        let pattern = "RSSI[: ]+(-?[0-9]+)"
        guard let range = line.range(of: pattern, options: .regularExpression) else {
            return nil
        }
        let match = String(line[range])
        let digits = match.filter { $0.isNumber }
        if let value = Int(digits) {
            return line.contains("-") ? -value : value
        }
        return nil
    }

    private func extractMAC(from line: String) -> String? {
        // Try standard MAC format: XX:XX:XX:XX:XX:XX
        let pattern1 = "([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"
        if let range = line.range(of: pattern1, options: .regularExpression) {
            return String(line[range]).uppercased()
        }
        
        // Try hyphen format: XX-XX-XX-XX-XX-XX
        let pattern2 = "([0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}"
        if let range = line.range(of: pattern2, options: .regularExpression) {
            return String(line[range]).replacingOccurrences(of: "-", with: ":").uppercased()
        }
        
        // Try compact format: XXXXXXXXXXXX
        let pattern3 = "[0-9A-Fa-f]{12}"
        if let range = line.range(of: pattern3, options: .regularExpression) {
            let compact = String(line[range])
            let formatted = stride(from: 0, to: compact.count, by: 2).map {
                let start = compact.index(compact.startIndex, offsetBy: $0)
                let end = compact.index(start, offsetBy: 2)
                return String(compact[start..<end])
            }.joined(separator: ":")
            return formatted.uppercased()
        }
        
        return nil
    }

    private func currentTimestamp() -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return formatter.string(from: Date())
    }
}
