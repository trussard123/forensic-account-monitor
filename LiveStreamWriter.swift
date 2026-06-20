import Foundation

// ============================================================
// LiveStreamWriter.swift
// FORENSIC MONITOR v4.0.0
// Copyright (c) 2026 Thomas D. Kraemer / Kraemer Inc.
// All Rights Reserved.
// ============================================================
// Single write point for all forensic events.
// Every module calls LiveStreamWriter — nothing writes
// to LIVE_STREAM.log directly.
// ============================================================

final class LiveStreamWriter {

    // ── Singleton ────────────────────────────────────────────
    static let shared = LiveStreamWriter()

    // ── Log directory and file path ──────────────────────────
    private let logDir: URL
    private let logFile: URL
    private let queue = DispatchQueue(label: "com.kraemerinc.livestreamwriter", qos: .utility)

    private init() {
        let home = FileManager.default.homeDirectoryForCurrentUser
        logDir = home.appendingPathComponent("Documents/forensic_monitor")
        logFile = logDir.appendingPathComponent("LIVE_STREAM.log")
        createLogDirectoryIfNeeded()
    }

    // ── Directory setup ──────────────────────────────────────
    private func createLogDirectoryIfNeeded() {
        if !FileManager.default.fileExists(atPath: logDir.path) {
            try? FileManager.default.createDirectory(at: logDir,
                withIntermediateDirectories: true)
        }
        if !FileManager.default.fileExists(atPath: logFile.path) {
            FileManager.default.createFile(atPath: logFile.path, contents: nil)
        }
    }

    // ── Primary write method ─────────────────────────────────
    // All modules call this. Thread-safe via serial queue.
    func write(_ event: ForensicEvent) {
        queue.async {
            let line = event.formatted() + "\n"
            guard let data = line.data(using: .utf8) else { return }
            if let handle = try? FileHandle(forWritingTo: self.logFile) {
                handle.seekToEndOfFile()
                handle.write(data)
                handle.closeFile()
            }
        }
    }

    // ── Annotation write — manual forensic notes ─────────────
    func annotate(_ note: String) {
        let timestamp = ISO8601DateFormatter().string(from: Date())
        let event = ForensicEvent(
            timestamp: timestamp,
            type: .annotation,
            mac: nil,
            transport: nil,
            ids: nil,
            deviceName: nil,
            geo: nil,
            rawLog: note
        )
        write(event)
    }
}

// ============================================================
// ForensicEvent — unified event model
// Every detection type produces a ForensicEvent
// ============================================================

struct ForensicEvent {

    enum EventType: String {
        case directLink     = "DirectLink-CLOSE"
        case awdl           = "AWDL"
        case usbDirectLink  = "USB+DirectLink"
        case preSwarm       = "PRE-SWARM"
        case swarm          = "SWARM ATTACK"
        case flashSwarm     = "FLASH SWARM"
        case batchDeploy    = "BATCH PROXIMITY DEPLOYMENT"
        case tokenDeposit   = "TOKEN DEPOSIT"
        case bleWarning     = "BLE WARNING"
        case annotation     = "FORENSIC-ANNOTATION"
        case stats          = "STATS"
    }

    let timestamp: String
    let type: EventType
    let mac: String?
    let transport: String?
    let ids: String?
    let deviceName: String?
    let geo: String?
    let rawLog: String?

    func formatted() -> String {
        var parts: [String] = [timestamp]
        parts.append(type.rawValue)
        if let mac = mac { parts.append("MAC: \(mac)") }
        if let transport = transport { parts.append(transport) }
        if let ids = ids { parts.append("IDS '\(ids)'") }
        if let deviceName = deviceName { parts.append("\"\(deviceName)\"") }
        if let geo = geo { parts.append("GEO: \(geo)") }
        if let rawLog = rawLog { parts.append(rawLog) }
        return parts.joined(separator: " | ")
    }
}
