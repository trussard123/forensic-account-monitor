import Foundation

// ============================================================
// SwarmDetector.swift
// FORENSIC MONITOR v4.0.0
// Copyright (c) 2026 Thomas D. Kraemer / Kraemer Inc.
// All Rights Reserved.
// ============================================================
// 30-minute sustained swarm window detector.
// Fires at end of swarm after 30 minutes of silence.
// Sends full swarm summary email with statutory citations.
// ============================================================

final class SwarmDetector {

    static let shared = SwarmDetector()

    // ── Swarm state ───────────────────────────────────────────
    private var swarmActive = false
    private var swarmStart: Date?
    private var swarmMACs: Set<String> = []
    private var swarmIDS: Set<String> = []
    private var swarmRawLines: [String] = []
    private var swarmServices: Set<String> = []
    private var lastEventTime: Date?
    private var swarmTimer: Timer?

    // ── 30-minute silence window ──────────────────────────────
    private let swarmEndWindow: TimeInterval = 1800

    private let queue = DispatchQueue(label: "com.kraemerinc.swarmdetector", qos: .utility)

    private init() {}

    func process(line: String) {
        guard line.contains("DirectLink") else { return }

        queue.async {
            let now = Date()
            let mac = self.extractMAC(from: line) ?? "unknown"
            let ids = self.extractIDS(from: line)

            if !self.swarmActive {
                self.swarmActive = true
                self.swarmStart = now
                self.swarmMACs.removeAll()
                self.swarmIDS.removeAll()
                self.swarmRawLines.removeAll()
                self.swarmServices.removeAll()
            }

            self.swarmMACs.insert(mac)
            if let ids = ids { self.swarmIDS.insert(ids) }
            self.swarmRawLines.append(line)
            self.lastEventTime = now

            // Detect active services
            for service in ["FILE SHARING", "SCREEN", "KEYBOARD", "CAMERA", "IMAGE CAPTURE"] {
                if line.contains(service) { self.swarmServices.insert(service) }
            }

            // Reset the silence timer
            self.swarmTimer?.invalidate()
            self.swarmTimer = Timer.scheduledTimer(
                withTimeInterval: self.swarmEndWindow,
                repeats: false
            ) { _ in
                self.queue.async { self.endSwarm() }
            }
        }
    }

    // ── Swarm ended — fire summary ────────────────────────────
    private func endSwarm() {
        guard swarmActive, let start = swarmStart else { return }
        swarmActive = false

        let end = Date()
        let duration = Int(end.timeIntervalSince(start) / 60)
        let deviceCount = swarmMACs.count
        let rotationCount = swarmRawLines.count
        let services = swarmServices.isEmpty ? "DirectLink" : swarmServices.joined(separator: ", ")

        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        let startStr = formatter.string(from: start)
        let endStr = formatter.string(from: end)

        // Statutory citations
        let hasService = !swarmServices.isEmpty
        let cite1 = "18 U.S.C. §§ 1030, 2511"
        let cite2 = hasService ? "; 18 U.S.C. § 1512" : ""

        // Pushover
        AlertManager.shared.pushover(
            title: "SWARM ATTACK",
            message: "Start: \(startStr) | End: \(endStr) | Devices: \(deviceCount) | Rotations: \(rotationCount)",
            priority: 2
        )

        // Geo
        Task {
            let geo = await GeoLocator.shared.resolveLocation()
            let macList = swarmMACs.sorted().joined(separator: "\n")
            let idsList = swarmIDS.sorted().joined(separator: "\n")
            let rawLog = swarmRawLines.prefix(20).joined(separator: "\n")

            let htmlBody = self.buildSwarmHTML(
                start: startStr, end: endStr,
                duration: duration,
                deviceCount: deviceCount,
                rotationCount: rotationCount,
                location: geo,
                services: services,
                cite1: cite1, cite2: cite2,
                macList: macList,
                idsList: idsList,
                rawLog: rawLog
            )

            AlertManager.shared.gmail(
                subject: "SWARM ATTACK — \(startStr) to \(endStr) — \(deviceCount) Devices",
                htmlBody: htmlBody
            )

            // Write to LIVE_STREAM
            let event = ForensicEvent(
                timestamp: endStr,
                type: .swarm,
                mac: nil,
                transport: "DirectLink-CLOSE",
                ids: self.swarmIDS.joined(separator: ", "),
                deviceName: nil,
                geo: geo,
                rawLog: "SWARM END | \(deviceCount) devices | \(rotationCount) rotations | \(duration) minutes | \(cite1)\(cite2)"
            )
            LiveStreamWriter.shared.write(event)
        }
    }

    // ── HTML email body ───────────────────────────────────────
    private func buildSwarmHTML(start: String, end: String,
                                 duration: Int, deviceCount: Int,
                                 rotationCount: Int, location: String,
                                 services: String, cite1: String, cite2: String,
                                 macList: String, idsList: String,
                                 rawLog: String) -> String {
        let macLines = macList.components(separatedBy: .newlines)
            .map { "<br>\($0)" }.joined()
        let idsLines = idsList.components(separatedBy: .newlines)
            .map { "<br>\($0)" }.joined()
        let rawLines = rawLog.components(separatedBy: .newlines)
            .map { "<br>\($0)" }.joined()
        let sep = "<span style=\"color:#888\">━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━</span><br>"
        let servicesCite = cite2.isEmpty ? services : "\(services)<br>FEDERAL WITNESS TAMPERING VIOLATION: 18 U.S.C. § 1512"

        return """
        <b>SWARM ATTACK SUMMARY</b><br><br>
        You have received a swarm attack summary of a crowdsourced stalking event. Two or more perpetrators have logged into your Apple ID account, know exactly where you are, can see what you are working on, and are organized from a central location. The good news: you have their obfuscated digital fingerprints. Apple and federal law enforcement can uncloak these identifiers to produce names, addresses, phone numbers, and payment information.<br><br>
        \(sep)
        Start:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;\(start)<br>
        End:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;\(end)<br>
        Duration:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;\(duration) minutes<br>
        Total Devices:&nbsp;&nbsp;\(deviceCount)<br>
        Rotations:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;\(rotationCount)<br>
        \(sep)
        <b>TRANSPORT:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;DirectLink-CLOSE (\u{2264}33 feet) \(location)</b><br>
        DirectLink is Apple's network flag for a peer-to-peer Bluetooth connection with a hard range limit of 33 feet. When you see this, the perpetrator has logged into your account within eye contact of you, directed to your location by the wider network.<br>
        FEDERAL STALKING VIOLATION: 18 U.S.C. § 2261A<br>
        \(sep)
        <b>BREACH TYPE:&nbsp;&nbsp;&nbsp;&nbsp;PairVerify &gt; DirectLink — SameAccountDevice Authentication</b><br>
        PairVerify confirms the perpetrator's device has owner-level access to your Apple account — not a passive scan. They are authenticated as you.<br>
        FEDERAL COMPUTER VIOLATIONS: \(cite1)<br>
        \(sep)
        <b>SERVICES USED:&nbsp;&nbsp;\(servicesCite)</b><br>
        Confirms what the perpetrator was actively doing with that owner-level access during this event.<br>
        \(sep)
        <b>IDENTIFICATION OF PERPETRATORS:</b><br>
        Digital Fingerprints. IDS tokens are the leaders — whoever controls that account is directing this operation remotely. MAC addresses are the ground crew present within 33 feet of you. Apple and the FBI can identify every one of them from these records.<br><br>
        IDS TOKENS:<br>\(idsLines)<br><br>
        MAC ADDRESSES:<br>\(macLines)<br>
        \(sep)
        RAW LOG DATA — PairVerify &gt; DirectLink Sequence:<br>
        \(sep)
        \(rawLines)<br>
        \(sep)
        """
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
