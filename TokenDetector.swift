import Foundation

// ============================================================
// TokenDetector.swift
// FORENSIC MONITOR v4.0.0
// Copyright (c) 2026 Thomas D. Kraemer / Kraemer Inc.
// All Rights Reserved.
// ============================================================
// Detects SameAccountDevice batch token deposits,
// new IDS/AID/AccountAltDSID tokens, and batch
// proximity deployments from rapportd output.
// ============================================================

final class TokenDetector {

    static let shared = TokenDetector()

    private var knownTokens: Set<String> = []
    private var batchBuffer: [String] = []
    private var batchTimer: Timer?
    private let batchWindow: TimeInterval = 2.0
    private let queue = DispatchQueue(label: "com.kraemerinc.tokendetector", qos: .utility)

    private init() {}

    func process(line: String) {
        guard line.contains("SameAccountDevice") ||
              line.contains("RPIdentityDaemon") else { return }

        queue.async {
            self.detectNewTokens(in: line)
            self.detectBatchDeployment(line: line)
        }
    }

    // ── New token detection ───────────────────────────────────
    private func detectNewTokens(in line: String) {
        let tokenPatterns = [
            ("IDS", "IDS '[A-Za-z0-9]+'"),
            ("AID", "AID '[A-Za-z0-9]+'"),
            ("AccountAltDSID", "AccountAltDSID '[A-Za-z0-9]+'")
        ]
        for (label, pattern) in tokenPatterns {
            guard let range = line.range(of: pattern, options: .regularExpression) else { continue }
            let token = String(line[range])
            if !self.knownTokens.contains(token) {
                self.knownTokens.insert(token)
                let timestamp = self.currentTimestamp()
                let event = ForensicEvent(
                    timestamp: timestamp,
                    type: .tokenDeposit,
                    mac: nil,
                    transport: nil,
                    ids: token,
                    deviceName: nil,
                    geo: nil,
                    rawLog: "NEW TOKEN: \(label) \(token)"
                )
                LiveStreamWriter.shared.write(event)
                AlertManager.shared.pushover(
                    title: "NEW TOKEN: \(label)",
                    message: "\(token) | \(timestamp)",
                    priority: 0
                )
            }
        }
    }

    // ── Batch deployment detection ────────────────────────────
    private func detectBatchDeployment(line: String) {
        guard line.contains("Added same account identity") else { return }
        batchBuffer.append(line)

        batchTimer?.invalidate()
        batchTimer = Timer.scheduledTimer(withTimeInterval: batchWindow,
                                          repeats: false) { _ in
            self.queue.async {
                self.evaluateBatch()
            }
        }
    }

    private func evaluateBatch() {
        guard batchBuffer.count >= 3 else {
            batchBuffer.removeAll()
            return
        }
        let count = batchBuffer.count
        let timestamp = currentTimestamp()

        // Extract unique IDS tokens from batch
        var ids = Set<String>()
        for line in batchBuffer {
            if let range = line.range(of: "IDS '[A-Za-z0-9]+'",
                                       options: .regularExpression) {
                ids.insert(String(line[range]))
            }
        }

        let event = ForensicEvent(
            timestamp: timestamp,
            type: .batchDeploy,
            mac: nil,
            transport: nil,
            ids: ids.joined(separator: ", "),
            deviceName: nil,
            geo: nil,
            rawLog: "BATCH DEPOSIT: \(count) SameAccountDevice identities"
        )
        LiveStreamWriter.shared.write(event)

        AlertManager.shared.pushover(
            title: "BATCH PROXIMITY DEPLOYMENT QNTY=\(count)",
            message: "0x10 DirectLink | \(count) identities | \(timestamp)",
            priority: 2
        )

        batchBuffer.removeAll()
    }

    private func currentTimestamp() -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return formatter.string(from: Date())
    }
}
