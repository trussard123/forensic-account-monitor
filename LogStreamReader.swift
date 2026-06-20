import Foundation

// ============================================================
// LogStreamReader.swift
// FORENSIC MONITOR v4.0.0
// Copyright (c) 2026 Thomas D. Kraemer / Kraemer Inc.
// All Rights Reserved.
// ============================================================

final class LogStreamReader {

    static let shared = LogStreamReader()

    var onLine: ((String) -> Void)?

    // Support multiple concurrent streams
    private var streams: [String: StreamInstance] = [:]

    private init() {}
    
    // Individual stream instance
    private class StreamInstance {
        var process: Process?
        var pipe: Pipe?
        var watchdogTimer: Timer?
        var lastLineTime: Date = Date()
        var predicate: String = ""
        weak var reader: LogStreamReader?
        
        init(reader: LogStreamReader) {
            self.reader = reader
        }
    }

    func start(predicate: String, name: String = "default") {
        stop(name: name)
        
        let instance = StreamInstance(reader: self)
        instance.predicate = predicate
        streams[name] = instance

        let process = Process()
        let pipe = Pipe()

        process.executableURL = URL(fileURLWithPath: "/usr/bin/log")
        process.arguments = ["stream", "--predicate", predicate, "--style", "syslog"]
        process.standardOutput = pipe
        process.standardError = Pipe()

        pipe.fileHandleForReading.readabilityHandler = { [weak self, weak instance] handle in
            let data = handle.availableData
            guard !data.isEmpty,
                  let line = String(data: data, encoding: .utf8) else { return }
            instance?.lastLineTime = Date()
            for rawLine in line.components(separatedBy: .newlines) {
                let trimmed = rawLine.trimmingCharacters(in: .whitespaces)
                guard !trimmed.isEmpty else { continue }
                self?.onLine?(trimmed)
            }
        }

        instance.process = process
        instance.pipe = pipe

        do {
            try process.run()
            startWatchdog(for: name)
            let timestamp = ISO8601DateFormatter().string(from: Date())
            print("[\(timestamp)] LogStreamReader [\(name)] started — predicate: \(predicate)")
        } catch {
            print("[LogStreamReader] [\(name)] Failed to start: \(error.localizedDescription)")
        }
    }

    func stop(name: String = "default") {
        guard let instance = streams[name] else { return }
        instance.watchdogTimer?.invalidate()
        instance.watchdogTimer = nil
        instance.pipe?.fileHandleForReading.readabilityHandler = nil
        instance.process?.terminate()
        streams.removeValue(forKey: name)
    }
    
    func stopAll() {
        for name in streams.keys {
            stop(name: name)
        }
    }

    private func startWatchdog(for name: String) {
        guard let instance = streams[name] else { return }
        
        instance.watchdogTimer?.invalidate()
        instance.watchdogTimer = Timer.scheduledTimer(withTimeInterval: 60.0,
                                              repeats: true) { [weak self, weak instance] _ in
            guard let self = self, let instance = instance else { return }
            let elapsed = Date().timeIntervalSince(instance.lastLineTime)
            if elapsed > 60.0 {
                let predicate = instance.predicate
                print("[\(Date())] Watchdog: [\(name)] stream stalled — restarting")
                self.stop(name: name)
                self.start(predicate: predicate, name: name)
            }
        }
    }

    func startForensicStream() {
        let predicate = "(process == \"rapportd\" OR process == \"sharingd\") AND (eventMessage CONTAINS \"SameAccountDevice\" OR eventMessage CONTAINS \"DirectLink\" OR eventMessage CONTAINS \"FILE SHARING\" OR eventMessage CONTAINS \"SDNearbyAgent\")"
        start(predicate: predicate, name: "forensic")
    }

    func startRSSIStream() {
        let predicate = "(process == \"rapportd\" OR process == \"bluetoothd\" OR process == \"sharingd\") AND (eventMessage CONTAINS \"RSSI\" OR eventMessage CONTAINS \"proximity\")"
        start(predicate: predicate, name: "rssi")
    }

    func startBLEStream() {
        let predicate = "(process == \"bluetoothd\" OR process == \"sharingd\") AND (eventMessage CONTAINS \"RSSI\" OR eventMessage CONTAINS \"proximity\")"
        start(predicate: predicate, name: "ble")
    }
}

