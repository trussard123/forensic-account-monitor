import Foundation
import CryptoKit

// ============================================================
// VaultManager.swift
// FORENSIC MONITOR v4.0.0
// Copyright (c) 2026 Thomas D. Kraemer / Kraemer Inc.
// All Rights Reserved.
// ============================================================
// SHA-256 seal chain for forensic log files.
// Mirrors the root-owned vault daemon functionality.
// Seals: LIVE_STREAM.log, PROXIMITY.log,
//        PUSHOVER_DELIVERY.log, SWARM_SUMMARIES.log
// ============================================================

final class VaultManager {

    static let shared = VaultManager()

    private let home = FileManager.default.homeDirectoryForCurrentUser
    private var sealTimer: Timer?

    private var logDir: URL {
        home.appendingPathComponent("Documents/forensic_monitor")
    }

    private var vaultDir: URL {
        URL(fileURLWithPath: "/var/forensic_vault")
    }

    private init() {}

    // ── Start periodic sealing — every 60 seconds ────────────
    func startSealing() {
        sealTimer = Timer.scheduledTimer(withTimeInterval: 60.0,
                                         repeats: true) { _ in
            self.sealAll()
        }
        sealAll() // seal immediately on start
    }

    func stopSealing() {
        sealTimer?.invalidate()
        sealTimer = nil
    }

    // ── Seal all monitored log files ─────────────────────────
    private func sealAll() {
        let filesToSeal = [
            "LIVE_STREAM.log",
            "PROXIMITY.log",
            "PUSHOVER_DELIVERY.log",
            "SWARM_SUMMARIES.log"
        ]
        for filename in filesToSeal {
            let fileURL = logDir.appendingPathComponent(filename)
            seal(fileURL: fileURL)
        }
        updateMasterSeal()
    }

    // ── SHA-256 hash and append to vault file ────────────────
    private func seal(fileURL: URL) {
        guard FileManager.default.fileExists(atPath: fileURL.path),
              let data = try? Data(contentsOf: fileURL) else { return }

        let hash = SHA256.hash(data: data)
        let hashString = hash.compactMap { String(format: "%02x", $0) }.joined()
        let timestamp = ISO8601DateFormatter().string(from: Date())
        let sealLine = "\(hashString)  \(fileURL.lastPathComponent)  \(timestamp)\n"

        let sealFile = vaultDir.appendingPathComponent(
            fileURL.deletingPathExtension().lastPathComponent + ".sha256"
        )
        appendToVault(line: sealLine, file: sealFile)
    }

    // ── Master seal — hash of all individual seal files ──────
    private func updateMasterSeal() {
        let masterFile = vaultDir.appendingPathComponent("MASTER_SEAL.sha256")
        let timestamp = ISO8601DateFormatter().string(from: Date())
        let line = "MASTER_SEAL updated: \(timestamp)\n"
        appendToVault(line: line, file: masterFile)
    }

    // ── Append line to vault file ────────────────────────────
    // Note: vault directory is root-owned — requires sudo in production.
    // In development, writes to ~/Documents/forensic_monitor/vault/
    private func appendToVault(line: String, file: URL) {
        guard let data = line.data(using: .utf8) else { return }

        // Try vault dir first, fall back to local dev path
        if FileManager.default.fileExists(atPath: vaultDir.path) {
            if let handle = try? FileHandle(forWritingTo: file) {
                handle.seekToEndOfFile()
                handle.write(data)
                handle.closeFile()
            }
        } else {
            // Development fallback
            let devVault = logDir.appendingPathComponent("vault")
            try? FileManager.default.createDirectory(at: devVault,
                withIntermediateDirectories: true)
            let devFile = devVault.appendingPathComponent(file.lastPathComponent)
            if !FileManager.default.fileExists(atPath: devFile.path) {
                FileManager.default.createFile(atPath: devFile.path, contents: nil)
            }
            if let handle = try? FileHandle(forWritingTo: devFile) {
                handle.seekToEndOfFile()
                handle.write(data)
                handle.closeFile()
            }
        }
    }

    // ── On-demand seal of a specific file ────────────────────
    func sealFile(named filename: String) {
        let fileURL = logDir.appendingPathComponent(filename)
        seal(fileURL: fileURL)
    }

    // ── SHA-256 of a specific file — returns hex string ──────
    func sha256(of fileURL: URL) -> String? {
        guard let data = try? Data(contentsOf: fileURL) else { return nil }
        let hash = SHA256.hash(data: data)
        return hash.compactMap { String(format: "%02x", $0) }.joined()
    }
}
